#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define PORT 8080
#define BUF_SIZE 1024
#define PASSWORD_FILE "client_password.txt"

const unsigned char AES_KEY[] = "0123456789012345";
const unsigned char AES_IV[] = "0123456789012345";

int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void hash_password(const char *password, unsigned char *hash) {
    SHA256((unsigned char *)password, strlen(password), hash);
}

void prompt_for_password(char *password, int is_new) {
    if (is_new)
        printf("Set a new client password: ");
    else
        printf("Enter client password: ");

    fgets(password, BUF_SIZE, stdin);
    password[strcspn(password, "\n")] = 0; // Remove newline
}

int verify_password() {
    char entered_password[BUF_SIZE];
    unsigned char entered_hash[SHA256_DIGEST_LENGTH];
    unsigned char stored_hash[SHA256_DIGEST_LENGTH];
    FILE *file = fopen(PASSWORD_FILE, "rb");

    if (!file) {
        char new_password[BUF_SIZE];
        prompt_for_password(new_password, 1);

        file = fopen(PASSWORD_FILE, "wb");
        if (!file) {
            perror("Failed to create password file");
            exit(EXIT_FAILURE);
        }

        hash_password(new_password, stored_hash);
        fwrite(stored_hash, 1, SHA256_DIGEST_LENGTH, file);
        fclose(file);

        printf("Password set successfully.\n");
        return 1;
    }

    fread(stored_hash, 1, SHA256_DIGEST_LENGTH, file);
    fclose(file);

    prompt_for_password(entered_password, 0);
    hash_password(entered_password, entered_hash);

    if (memcmp(stored_hash, entered_hash, SHA256_DIGEST_LENGTH) == 0) {
        printf("Authentication successful.\n");
        return 1;
    } else {
        printf("Authentication failed.\n");
        return 0;
    }
}

int main() {
    if (!verify_password()) {
        exit(EXIT_FAILURE);
    }

    printf("Client starting...\n");

    int sock = 0;
    struct sockaddr_in serv_addr;
    unsigned char buffer[BUF_SIZE] = {0};
    unsigned char encrypted[BUF_SIZE] = {0};
    unsigned char decrypted[BUF_SIZE] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    printf("Connected to server\n");

    while (1) {
        printf("Enter message: ");
        fgets((char *)buffer, BUF_SIZE, stdin);
        buffer[strcspn((char *)buffer, "\n")] = '\0';

        int encrypted_len = aes_encrypt(buffer, strlen((char *)buffer), (unsigned char *)AES_KEY, (unsigned char *)AES_IV, encrypted);
        send(sock, encrypted, encrypted_len, 0);

        int bytes_read = read(sock, encrypted, BUF_SIZE);
        int decrypted_len = aes_decrypt(encrypted, bytes_read, (unsigned char *)AES_KEY, (unsigned char *)AES_IV, decrypted);
        decrypted[decrypted_len] = '\0';
        printf("Server: %s\n", decrypted);
    }

    close(sock);
    return 0;
}

