#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <stdexcept>
#include <wolfssl/ssl.h>
#include <arpa/inet.h>
#include <unistd.h>

class SecureString {
    std::vector<char> data;
public:
    SecureString(const std::string& s) : data(s.begin(), s.end()) {}
    ~SecureString() { std::fill(data.begin(), data.end(), 0); }
    const char* c_str() const { return data.data(); }
    size_t length() const { return data.size(); }
};

SecureString g_psk_key("");
SecureString g_psk_identity("");

void read_psk_from_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open PSK file: " + filename);
    }

    std::string key, identity;
    if (!(std::getline(file, key) && std::getline(file, identity))) {
        throw std::runtime_error("Error reading PSK file: " + filename);
    }

    // Remove any trailing whitespace
    key.erase(key.find_last_not_of(" \n\r\t") + 1);
    identity.erase(identity.find_last_not_of(" \n\r\t") + 1);

    if (key.empty() || identity.empty()) {
        throw std::runtime_error("PSK or identity is empty in file: " + filename);
    }

    g_psk_key = SecureString(key);
    g_psk_identity = SecureString(identity);
}

unsigned int psk_client_cb(WOLFSSL* ssl, const char* hint, char* identity,
                           unsigned int id_max_len, unsigned char* key,
                           unsigned int key_max_len) {
    size_t id_len = g_psk_identity.length();
    size_t key_len = g_psk_key.length() / 2;

    if (id_len > id_max_len) {
        std::cerr << "PSK identity too long" << std::endl;
        return 0;
    }

    if (key_len > key_max_len) {
        std::cerr << "PSK key too long" << std::endl;
        return 0;
    }

    memcpy(identity, g_psk_identity.c_str(), id_len);
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

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <psk_file>" << std::endl;
        return 1;
    }

    try {
        read_psk_from_file(argv[1]);

        if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
            throw std::runtime_error("Failed to initialize wolfSSL");
        }

        WolfSSLContext ctx(wolfTLSv1_3_client_method());

        wolfSSL_CTX_set_psk_client_callback(ctx.get(), psk_client_cb);

        const char* ciphers = "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384";
        if (wolfSSL_CTX_set_cipher_list(ctx.get(), ciphers) != WOLFSSL_SUCCESS) {
            throw std::runtime_error("Failed to set cipher list");
        }

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            throw std::runtime_error("Error creating socket");
        }

        struct sockaddr_in servAddr;
        memset(&servAddr, 0, sizeof(servAddr));
        servAddr.sin_family = AF_INET;
        servAddr.sin_port = htons(4433);

        if (inet_pton(AF_INET, "127.0.0.1", &servAddr.sin_addr) != 1) {
            throw std::runtime_error("Error setting IP address");
        }

        if (connect(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
            throw std::runtime_error("Error connecting to server");
        }

        WolfSSL ssl(ctx.get());
        wolfSSL_set_fd(ssl.get(), sockfd);

        if (wolfSSL_connect(ssl.get()) != SSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl.get(), 0);
            char buffer[80];
            wolfSSL_ERR_error_string(err, buffer);
            throw std::runtime_error(std::string("SSL connection failed: ") + buffer);
        }

        std::cout << "SSL connection established" << std::endl;

        const char* message = "Hello, server!";
        if (wolfSSL_write(ssl.get(), message, strlen(message)) != strlen(message)) {
            throw std::runtime_error("Failed to send message");
        }

        char buffer[256];
        int bytes = wolfSSL_read(ssl.get(), buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::cout << "Received: " << buffer << std::endl;
        } else if (bytes < 0) {
            throw std::runtime_error("Failed to receive message");
        }

        wolfSSL_shutdown(ssl.get());
        close(sockfd);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    wolfSSL_Cleanup();
    return 0;
}
