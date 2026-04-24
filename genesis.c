#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/sha.h>
#include <gmp.h> // Equivalente a Boost Multiprecision

// Estructura básica para emular un vector simple de bytes
typedef struct {
    unsigned char *data;
    size_t size;
} ByteBuffer;

ByteBuffer create_buffer(size_t size) {
    ByteBuffer b;
    b.data = (unsigned char *)malloc(size);
    b.size = size;
    return b;
}

unsigned char* hex_to_bytes(const char* hex, size_t* out_len) {
    size_t len = strlen(hex);
    *out_len = len / 2;
    unsigned char* bytes = (unsigned char*)malloc(*out_len);
    for (size_t i = 0; i < *out_len; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
    return bytes;
}

void bytes_to_hex(const unsigned char* data, size_t len, char* out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

void reverse_bytes(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        unsigned char temp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}

void double_sha256(const unsigned char* data, size_t len, unsigned char* out) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, out);
}

void append_uint32_le(unsigned char** cursor, uint32_t value) {
    (*cursor)[0] = (value) & 0xff;
    (*cursor)[1] = (value >> 8) & 0xff;
    (*cursor)[2] = (value >> 16) & 0xff;
    (*cursor)[3] = (value >> 24) & 0xff;
    *cursor += 4;
}

void append_uint64_le(unsigned char** cursor, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        (*cursor)[i] = (value >> (8 * i)) & 0xff;
    }
    *cursor += 8;
}

void get_target(uint32_t nbits, mpz_t target) {
    uint32_t exponent = (nbits >> 24) & 0xff;
    uint32_t mantissa = nbits & 0x007fffff;
    mpz_set_ui(target, mantissa);
    if (exponent <= 3) {
        mpz_tdiv_q_2exp(target, target, 8 * (3 - exponent));
    } else {
        mpz_mul_2exp(target, target, 8 * (exponent - 3));
    }
}

void hash_to_int_little(const unsigned char* hash, mpz_t result) {
    mpz_set_ui(result, 0);
    mpz_t temp, shift;
    mpz_init(temp);
    mpz_init(shift);
    for (size_t i = 0; i < 32; ++i) {
        mpz_set_ui(temp, hash[i]);
        mpz_mul_2exp(shift, temp, 8 * i);
        mpz_add(result, result, shift);
    }
    mpz_clear(temp);
    mpz_clear(shift);
}

void create_merkle_root_exact(const char* pubkey_hex, const char* message, uint32_t nbits, double reward, char* out_merkle) {
    uint64_t satoshis = (uint64_t)(reward * 100000000.0);
    size_t msg_len = strlen(message);
    
    // ScriptSig
    unsigned char script_sig[512];
    unsigned char* p = script_sig;
    *p++ = 0x04;
    append_uint32_le(&p, nbits);
    *p++ = 0x01; *p++ = 0x04;
    if (msg_len < 76) { *p++ = (unsigned char)msg_len; } 
    else { *p++ = 0x4c; *p++ = (unsigned char)msg_len; }
    memcpy(p, message, msg_len); p += msg_len;
    size_t script_sig_len = p - script_sig;

    // ScriptPubKey
    size_t pubkey_len;
    unsigned char* pubkey_bytes = hex_to_bytes(pubkey_hex, &pubkey_len);
    unsigned char script_pubkey[128];
    p = script_pubkey;
    *p++ = (pubkey_len == 33) ? 0x21 : 0x41;
    memcpy(p, pubkey_bytes, pubkey_len); p += pubkey_len;
    *p++ = 0xac;
    size_t script_pubkey_len = p - script_pubkey;

    // Coinbase TX
    unsigned char coinbase[1024];
    p = coinbase;
    append_uint32_le(&p, 1); // version
    *p++ = 0x01; // in-counter
    memset(p, 0, 32); p += 32; // prev hash
    append_uint32_le(&p, 0xffffffff); // prev index
    *p++ = (unsigned char)script_sig_len;
    memcpy(p, script_sig, script_sig_len); p += script_sig_len;
    append_uint32_le(&p, 0xffffffff); // sequence
    *p++ = 0x01; // out-counter
    append_uint64_le(&p, satoshis);
    *p++ = (unsigned char)script_pubkey_len;
    memcpy(p, script_pubkey, script_pubkey_len); p += script_pubkey_len;
    append_uint32_le(&p, 0); // locktime

    unsigned char merkle_hash[32];
    double_sha256(coinbase, p - coinbase, merkle_hash);
    reverse_bytes(merkle_hash, 32);
    bytes_to_hex(merkle_hash, 32, out_merkle);

    free(pubkey_bytes);
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        printf("Usage: ./genesis PUBKEY MESSAGE NBITS REWARD\n");
        return 1;
    }

    const char* pubkey = argv[1];
    const char* message = argv[2];
    uint32_t nbits = (uint32_t)strtoul(argv[3], NULL, 16);
    double reward = atof(argv[4]);
    uint32_t ntime = (uint32_t)time(NULL);

    char merkle_root_hex[65];
    create_merkle_root_exact(pubkey, message, nbits, reward, merkle_root_hex);

    printf("Mining (Time: %u)\n", ntime);

    unsigned char header[80];
    unsigned char* p = header;
    append_uint32_le(&p, 1); // Version
    memset(p, 0, 32); p += 32; // Prev Hash
    
    size_t dummy;
    unsigned char* merkle_bytes = hex_to_bytes(merkle_root_hex, &dummy);
    reverse_bytes(merkle_bytes, 32);
    memcpy(p, merkle_bytes, 32); p += 32;
    append_uint32_le(&p, ntime);
    append_uint32_le(&p, nbits);

    mpz_t target, hash_val;
    mpz_init(target);
    mpz_init(hash_val);
    get_target(nbits, target);

    for (uint32_t nonce = 0; nonce < 0xffffffff; ++nonce) {
        unsigned char* nonce_ptr = header + 76;
        append_uint32_le(&nonce_ptr, nonce);

        unsigned char final_hash[32];
        double_sha256(header, 80, final_hash);
        hash_to_int_little(final_hash, hash_val);

        if (mpz_cmp(hash_val, target) <= 0) {
            reverse_bytes(final_hash, 32);
            char final_hash_hex[65];
            bytes_to_hex(final_hash, 32, final_hash_hex);

            printf("\n=== SUCCESS! ===\n");
            printf("PubKey: %s\nnTime: %u\nnNonce: %u\nMerkle: %s\nHash: %s\n", pubkey, ntime, nonce, merkle_root_hex, final_hash_hex);

            return 0;
        }
    }

    return 0;
}
