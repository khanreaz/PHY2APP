#include <iostream>
#include <cstring>
#include <mutex>
#include <memory>
#include <vector>
#include <wolfssl/ssl.h>
#include <limits>

class SecureString {
    std::vector<char> data;
public:
    SecureString(const std::string& s) : data(s.begin(), s.end()) {}
    ~SecureString() { std::fill(data.begin(), data.end(), 0); }
    const char* c_str() const { return data.data(); }
    size_t length() const { return data.size(); }
};

std::mutex psk_mutex;
SecureString g_psk_key("0123456789abcdef0123456789abcdef");
SecureString g_psk_identity("Client_identity");

void update_psk(const std::string& new_key, const std::string& new_identity) {
    if (new_key.empty() || new_identity.empty()) {
        throw std::invalid_argument("PSK key and identity cannot be empty");
    }
    if (new_key.length() % 2 != 0) {
        throw std::invalid_argument("PSK key length must be even");
    }
    std::lock_guard<std::mutex> lock(psk_mutex);
    g_psk_key = SecureString(new_key);
    g_psk_identity = SecureString(new_identity);
}

unsigned int psk_server_cb(WOLFSSL* ssl, const char* identity, unsigned char* key,
                           unsigned int key_max_len) {
    std::lock_guard<std::mutex> lock(psk_mutex);
    
    if (strcmp(identity, g_psk_identity.c_str()) != 0) {
        std::cerr << "PSK identity not recognized" << std::endl;
        return 0;
    }

    size_t key_len = g_psk_key.length() / 2;
    if (key_len > key_max_len) {
        std::cerr << "PSK buffer too small" << std::endl;
        return 0;
    }

    for (size_t i = 0; i < key_len; i++) {
        sscanf(g_psk_key.c_str() + 2*i, "%2hhx", &key[i]);
    }

    return key_len;
}

class WolfSSLContext {
    WOLFSSL_CTX* ctx;
public:
    WolfSSLContext(WOLFSSL_METHOD* method) : ctx(wolfSSL_CTX_new(method)) {
        if (!ctx) throw std::runtime_error("Failed to create WOLFSSL_CTX");
    }
    ~WolfSSLContext() { if (ctx) wolfSSL_CTX_free(ctx); }
    WOLFSSL_CTX* get() { return ctx; }
};

class WolfSSL {
    WOLFSSL* ssl;
public:
    WolfSSL(WOLFSSL_CTX* ctx) : ssl(wolfSSL_new(ctx)) {
        if (!ssl) throw std::runtime_error("Failed to create WOLFSSL");
    }
    ~WolfSSL() { if (ssl) wolfSSL_free(ssl); }
    WOLFSSL* get() { return ssl; }
};

int main() {
    try {
        if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
            throw std::runtime_error("Failed to initialize wolfSSL");
        }

        WolfSSLContext ctx(wolfTLSv1_3_server_method());

        wolfSSL_CTX_set_psk_server_callback(ctx.get(), psk_server_cb);
        
        const char* ciphers = "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384";
        if (wolfSSL_CTX_set_cipher_list(ctx.get(), ciphers) != WOLFSSL_SUCCESS) {
            throw std::runtime_error("Failed to set cipher list");
        }

        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            throw std::runtime_error("Error creating socket");
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(4433);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            throw std::runtime_error("Error binding to port");
        }

        if (listen(server_fd, SOMAXCONN) < 0) {
            throw std::runtime_error("Error listening for connections");
        }

        std::cout << "Server listening on port 4433..." << std::endl;

        while (true) {
            int client_fd = accept(server_fd, NULL, NULL);
            if (client_fd < 0) {
                std::cerr << "Error accepting client connection" << std::endl;
                continue;
            }

            WolfSSL ssl(ctx.get());
            wolfSSL_set_fd(ssl.get(), client_fd);

            if (wolfSSL_accept(ssl.get()) != SSL_SUCCESS) {
                int err = wolfSSL_get_error(ssl.get(), 0);
                char buffer[80];
                wolfSSL_ERR_error_string(err, buffer);
                std::cerr << "SSL handshake failed: " << buffer << std::endl;
            } else {
                std::cout << "SSL connection established" << std::endl;

                // Perform secure communication here
                char buff[256];
                int len = wolfSSL_read(ssl.get(), buff, sizeof(buff)-1);
                if (len > 0) {
                    buff[len] = '\0';
                    std::cout << "Received: " << buff << std::endl;
                    
                    const char* response = "Hello, client!";
                    wolfSSL_write(ssl.get(), response, strlen(response));
                }
            }

            wolfSSL_shutdown(ssl.get());
            close(client_fd);
        }

        close(server_fd);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    wolfSSL_Cleanup();
    return 0;
}
