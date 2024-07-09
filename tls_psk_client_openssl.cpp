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
};

// Global PSK data 
std::mutex psk_mutex;
SecureString g_psk_key("0123456789abcdef0123456789abcdef");
SecureString g_psk_identity("Client_identity");

unsigned int psk_client_cb(SSL* ssl, const char* hint, char* identity, 
                           unsigned int max_identity_len, unsigned char* psk, unsigned int max_psk_len) {
    std::lock_guard<std::mutex> lock(psk_mutex);
    
    if (g_psk_identity.length() > max_identity_len || 
        g_psk_key.length() / 2 > max_psk_len) {
        std::cerr << "Insufficient buffer size for PSK data" << std::endl;
        return 0;
    }

    strcpy(identity, g_psk_identity.c_str()); 
    for (size_t i = 0; i < g_psk_key.length() / 2; i++) {
        sscanf(g_psk_key.c_str() + 2 * i, "%2hhx", &psk[i]);
    }
    
    return g_psk_key.length() / 2;
}

// OpenSSLContext 
class OpenSSLContext {
    SSL_CTX* ctx;
public:
    OpenSSLContext(const SSL_METHOD* method) : ctx(SSL_CTX_new(method)) {
        if (!ctx) throw std::runtime_error("Failed to create SSL_CTX");
    }
    ~OpenSSLContext() { if (ctx) SSL_CTX_free(ctx); }
    SSL_CTX* get() { return ctx; }
};

// OpenSSLConnection
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

        OpenSSLContext ctx(TLS_client_method());
        SSL_CTX_set_psk_client_callback(ctx.get(), psk_client_cb);
        SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);

        // Cipher list (optional, but good practice for compatibility)
        const char* ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
        if (SSL_CTX_set_cipher_list(ctx.get(), ciphers) != 1) {
            throw std::runtime_error("Error setting cipher list");
        }

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) throw std::runtime_error("Error creating socket");

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(4433); // Same port as server
        if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) { // Connect to localhost
            throw std::runtime_error("Invalid address/ Address not supported");
        }

        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            throw std::runtime_error("Connection failed");
        }

        OpenSSLConnection ssl(ctx.get());
        SSL_set_fd(ssl.get(), sockfd);

        if (SSL_connect(ssl.get()) != 1) {
            throw std::runtime_error("SSL connect failed");
        }

        std::cout << "SSL connection established" << std::endl;

        // Send and receive data securely
        const char* message = "Hello from client!";
        SSL_write(ssl.get(), message, strlen(message));

        char buffer[1024];
        int bytes = SSL_read(ssl.get(), buffer, sizeof(buffer) - 1);
        buffer[bytes] = '\0';

        std::cout << "Received from server: " << buffer << std::endl;

        close(sockfd); // Close socket after SSL shutdown

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    EVP_cleanup();
    return 0;
}
