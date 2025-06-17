/**
 * IoTStrike Hardware Security Framework
 * Basic Cryptographic Engine Implementation
 * 
 * This module provides basic cryptographic functionality
 * for the IoTStrike framework without external dependencies.
 * 
 * Author: ibrahimsql
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include "../include/iotstrike.h"

// Simple XOR-based encryption (for demonstration)
static void simple_xor_encrypt(const unsigned char* data, unsigned char* output, 
                              size_t len, const unsigned char* key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = data[i] ^ key[i % key_len];
    }
}

// Simple hash function (basic checksum)
static uint32_t simple_hash(const unsigned char* data, size_t len) {
    uint32_t hash = 0x811c9dc5; // FNV offset basis
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193; // FNV prime
    }
    return hash;
}

// Simple random number generator
static uint32_t simple_random() {
    static uint32_t seed = 1;
    seed = seed * 1103515245 + 12345;
    return (seed / 65536) % 32768;
}

// Global state
static unsigned char g_aes_key[32] = {0};
static unsigned char g_aes_iv[16] = {0};
static int g_crypto_initialized = 0;

// C Interface Functions

int iotstrike_crypto_init() {
    if (g_crypto_initialized) {
        return IOTSTRIKE_SUCCESS;
    }
    
    // Initialize with current time as seed
    srand((unsigned int)time(NULL));
    
    // Generate default key and IV
    for (int i = 0; i < 32; i++) {
        g_aes_key[i] = (unsigned char)(simple_random() & 0xFF);
    }
    for (int i = 0; i < 16; i++) {
        g_aes_iv[i] = (unsigned char)(simple_random() & 0xFF);
    }
    
    g_crypto_initialized = 1;
    return IOTSTRIKE_SUCCESS;
}

void iotstrike_crypto_cleanup() {
    g_crypto_initialized = 0;
    memset(g_aes_key, 0, sizeof(g_aes_key));
    memset(g_aes_iv, 0, sizeof(g_aes_iv));
}

int iotstrike_aes_encrypt(const unsigned char* plaintext, size_t plaintext_len,
                         const unsigned char* key, size_t key_len,
                         unsigned char* ciphertext, size_t* ciphertext_len) {
    if (!plaintext || !key || !ciphertext || !ciphertext_len) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    if (*ciphertext_len < plaintext_len) {
        *ciphertext_len = plaintext_len;
        return IOTSTRIKE_ERROR_MEMORY;
    }
    
    // Simple XOR encryption
    simple_xor_encrypt(plaintext, ciphertext, plaintext_len, key, key_len);
    *ciphertext_len = plaintext_len;
    
    return IOTSTRIKE_SUCCESS;
}

int iotstrike_aes_decrypt(const unsigned char* ciphertext, size_t ciphertext_len,
                         const unsigned char* key, size_t key_len,
                         unsigned char* plaintext, size_t* plaintext_len) {
    if (!ciphertext || !key || !plaintext || !plaintext_len) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    if (*plaintext_len < ciphertext_len) {
        *plaintext_len = ciphertext_len;
        return IOTSTRIKE_ERROR_MEMORY;
    }
    
    // XOR decryption (same as encryption)
    simple_xor_encrypt(ciphertext, plaintext, ciphertext_len, key, key_len);
    *plaintext_len = ciphertext_len;
    
    return IOTSTRIKE_SUCCESS;
}

int iotstrike_sha256(const unsigned char* data, size_t data_len,
                    unsigned char* hash) {
    if (!data || !hash) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    // Simple hash (32 bytes)
    uint32_t hash_val = simple_hash(data, data_len);
    
    // Fill 32 bytes with variations of the hash
    for (int i = 0; i < 8; i++) {
        uint32_t val = hash_val ^ (i * 0x12345678);
        memcpy(hash + i * 4, &val, 4);
    }
    
    return IOTSTRIKE_SUCCESS;
}

int iotstrike_generate_random(unsigned char* buffer, size_t length) {
    if (!buffer) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    for (size_t i = 0; i < length; i++) {
        buffer[i] = (unsigned char)(simple_random() & 0xFF);
    }
    
    return IOTSTRIKE_SUCCESS;
}

int iotstrike_rsa_generate_keypair(int key_size, unsigned char* public_key,
                                  size_t* public_key_len, unsigned char* private_key,
                                  size_t* private_key_len) {
    if (!public_key || !public_key_len || !private_key || !private_key_len) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    // Generate dummy RSA keys (just random data for demo)
    size_t pub_size = key_size / 8;  // Convert bits to bytes
    size_t priv_size = key_size / 4; // Private key is larger
    
    if (*public_key_len < pub_size || *private_key_len < priv_size) {
        *public_key_len = pub_size;
        *private_key_len = priv_size;
        return IOTSTRIKE_ERROR_MEMORY;
    }
    
    // Fill with random data
    for (size_t i = 0; i < pub_size; i++) {
        public_key[i] = (unsigned char)(simple_random() & 0xFF);
    }
    for (size_t i = 0; i < priv_size; i++) {
        private_key[i] = (unsigned char)(simple_random() & 0xFF);
    }
    
    *public_key_len = pub_size;
    *private_key_len = priv_size;
    
    return IOTSTRIKE_SUCCESS;
}

// End of crypto_engine.cpp