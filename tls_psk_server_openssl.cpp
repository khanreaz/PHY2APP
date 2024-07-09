#include <iostream>
#include <cstring>
#include <mutex>
#include <memory>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>

class SecureString {
    std::vector<unsigned char> data;
public:
    SecureString(const std::string& s) : data(s.begin(), s.end()) {}
    ~SecureString() { std::fill(data.begin(), data.end(), 0); }
    const char* c_str() const { return reinterpret_cast<const char*>(data.data()); }
    size_t length() const { return data.size(); }
    bool empty() const { return data.empty(); }  
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

unsigned int psk_server_cb(SSL *ssl, const char *identity,
                           unsigned char *psk, unsigned int max_psk_len) {
    std::lock_guard<std::mutex> lock(psk_mutex);
    
    if (g_psk_key.empty() || g_psk_identity.empty() || 
        strcmp(identity, g_psk_identity.c_str()) != 0) {
        std::cerr << "PSK identity not recognized or invalid PSK data" << std::endl;
        return 0;
    }

    size_t psk_len = g_psk_key.length() / 2;
    if (psk_len > max_psk_len) {
        std::cerr << "PSK buffer too small" << std::endl;
        return 0;
    }

    for (size_t i = 0; i < psk_len; i++) {
        sscanf(g_psk_key.c_str() + 2*i, "%2hhx", &psk[i]);
    }

    return psk_len;
}
class OpenSSLContext {
    SSL_CTX* ctx;
public:
    OpenSSLContext(const SSL_METHOD* method) : ctx(SSL_CTX_new(method)) {
        if (!ctx) throw std::runtime_error("Failed to create SSL_CTX");
    }
    ~OpenSSLContext() { if (ctx) SSL_CTX_free(ctx); }
    SSL_CTX* get() { return ctx; }
};

class OpenSSLConnection {
    SSL* ssl;
public:
    OpenSSLConnection(SSL_CTX* ctx) : ssl(SSL_new(ctx)) {
        if (!ssl) throw std::runtime_error("Failed to create SSL");
    }
    ~OpenSSLConnection() { if (ssl) SSL_free(ssl); }
    SSL* get() { return ssl; }
};


int main() {
    try {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        OpenSSLContext ctx(TLS_server_method());

        // Force TLS 1.3
        SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION); 
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);

        SSL_CTX_set_psk_server_callback(ctx.get(), psk_server_cb);

        // Cipher suite specific to TLS 1.3
        //const char* ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
        //if (SSL_CTX_set_cipher_list(ctx.get(), ciphers) != 1) {
        //    throw std::runtime_error("Error setting cipher list");
        //}

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

            OpenSSLConnection ssl(ctx.get());
            SSL_set_fd(ssl.get(), client_fd);
            
            // Verify selected cipher suite after SSL_accept
            int ret = SSL_accept(ssl.get());
            if (ret <= 0) {
                int err = SSL_get_error(ssl.get(), ret);
                char buf[256];
                ERR_error_string_n(err, buf, sizeof(buf));
                std::cerr << "SSL handshake failed: " << buf << std::endl;
                SSL_free(ssl.get());
                close(client_fd);  // Close the socket in case of error
                continue; 
            } else {
                const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl.get());
                if (cipher) {
                    std::cout << "Negotiated Cipher: " << SSL_CIPHER_get_name(cipher) << std::endl;
                }

                std::cout << "SSL connection established" << std::endl;

                // ... (Handle secure communication) ...

                SSL_shutdown(ssl.get());
                close(client_fd); 
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    EVP_cleanup();
    return 0;
}
