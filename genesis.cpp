#include <iostream> // g++ -O3 -static -std=c++17 genesis.cpp -o genesis -lcrypto
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstdint>
#include <algorithm>
#include <openssl/sha.h>
#include <boost/multiprecision/cpp_int.hpp>

using namespace std;
using namespace boost::multiprecision;

vector<unsigned char> hex_to_bytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

string bytes_to_hex(const vector<unsigned char>& data) {
    stringstream ss;
    ss << hex << nouppercase;

    for (unsigned char byte : data) {
        ss << setw(2) << setfill('0') << (int)byte;
    }

    return ss.str();
}

vector<unsigned char> reverse_bytes(vector<unsigned char> data) {
    reverse(data.begin(), data.end());
    return data;
}

vector<unsigned char> double_sha256(const vector<unsigned char>& data) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];

    SHA256(data.data(), data.size(), hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    return vector<unsigned char>(hash2, hash2 + SHA256_DIGEST_LENGTH);
}

void append_uint32_le(vector<unsigned char>& v, uint32_t value) {
    v.push_back((value) & 0xff);
    v.push_back((value >> 8) & 0xff);
    v.push_back((value >> 16) & 0xff);
    v.push_back((value >> 24) & 0xff);
}

void append_uint64_le(vector<unsigned char>& v, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        v.push_back((value >> (8 * i)) & 0xff);
    }
}

cpp_int get_target(uint32_t nbits) {
    uint32_t exponent = (nbits >> 24) & 0xff;
    uint32_t mantissa = nbits & 0x007fffff;

    cpp_int target = mantissa;

    if (exponent <= 3) {
        target >>= (8 * (3 - exponent));
    } else {
        target <<= (8 * (exponent - 3));
    }

    return target;
}

cpp_int hash_to_int_little(const vector<unsigned char>& hash) {
    cpp_int result = 0;

    for (size_t i = 0; i < hash.size(); ++i) {
        result += cpp_int(hash[i]) << (8 * i);
    }

    return result;
}

string create_merkle_root_exact(
    const string& pubkey,
    const string& message,
    uint32_t nbits,
    double reward
) {
    uint64_t satoshis = (uint64_t)(reward * 100000000.0);

    vector<unsigned char> msg_bytes(message.begin(), message.end());

    vector<unsigned char> script_sig;

    script_sig.push_back(0x04);
    append_uint32_le(script_sig, nbits);

    script_sig.push_back(0x01);
    script_sig.push_back(0x04);

    if (msg_bytes.size() < 76) {
        script_sig.push_back((unsigned char)msg_bytes.size());
    } else {
        script_sig.push_back(0x4c);
        script_sig.push_back((unsigned char)msg_bytes.size());
    }

    script_sig.insert(
        script_sig.end(),
        msg_bytes.begin(),
        msg_bytes.end()
    );

    vector<unsigned char> pubkey_bytes = hex_to_bytes(pubkey);

    vector<unsigned char> script_pubkey;

    if (pubkey_bytes.size() == 33) {
        script_pubkey.push_back(0x21);
    } else {
        script_pubkey.push_back(0x41);
    }

    script_pubkey.insert(
        script_pubkey.end(),
        pubkey_bytes.begin(),
        pubkey_bytes.end()
    );

    script_pubkey.push_back(0xac);

    vector<unsigned char> coinbase_tx;

    append_uint32_le(coinbase_tx, 1);

    coinbase_tx.push_back(0x01);

    for (int i = 0; i < 32; ++i) {
        coinbase_tx.push_back(0x00);
    }

    append_uint32_le(coinbase_tx, 0xffffffff);

    coinbase_tx.push_back((unsigned char)script_sig.size());
    coinbase_tx.insert(
        coinbase_tx.end(),
        script_sig.begin(),
        script_sig.end()
    );

    append_uint32_le(coinbase_tx, 0xffffffff);

    coinbase_tx.push_back(0x01);

    append_uint64_le(coinbase_tx, satoshis);

    coinbase_tx.push_back((unsigned char)script_pubkey.size());
    coinbase_tx.insert(
        coinbase_tx.end(),
        script_pubkey.begin(),
        script_pubkey.end()
    );

    append_uint32_le(coinbase_tx, 0);

    vector<unsigned char> merkle = double_sha256(coinbase_tx);
    merkle = reverse_bytes(merkle);

    return bytes_to_hex(merkle);
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        cout << "Usage:" << endl;
        cout << "./genesis PUBKEY MESSAGE NBITS REWARD" << endl;
        return 1;
    }

    string pubkey = argv[1];
    string message = argv[2];
    string bits_str = argv[3];
    double reward = stod(argv[4]);

    if (bits_str.rfind("0x", 0) == 0 || bits_str.rfind("0X", 0) == 0) {
        bits_str = bits_str.substr(2);
    }

    const uint32_t VERSION = 1;
    const uint32_t NBITS = stoul(bits_str, nullptr, 16);
    const uint32_t NTIME = 1777054286 //(uint32_t)time(nullptr);

    string merkle_root = create_merkle_root_exact(
        pubkey,
        message,
        NBITS,
        reward
    );

    cout << "Mining (Time: " << NTIME << ")" << endl;

    vector<unsigned char> header_prefix;

    append_uint32_le(header_prefix, VERSION);

    for (int i = 0; i < 32; ++i) {
        header_prefix.push_back(0x00);
    }

    vector<unsigned char> merkle_bytes = reverse_bytes(
        hex_to_bytes(merkle_root)
    );

    header_prefix.insert(
        header_prefix.end(),
        merkle_bytes.begin(),
        merkle_bytes.end()
    );

    append_uint32_le(header_prefix, NTIME);
    append_uint32_le(header_prefix, NBITS);

    cpp_int target = get_target(NBITS);

    for (uint32_t nonce = 0; nonce < 0xffffffff; ++nonce) {
        vector<unsigned char> block_header = header_prefix;

        append_uint32_le(block_header, nonce);

        vector<unsigned char> hash = double_sha256(block_header);
        cpp_int hash_value = hash_to_int_little(hash);

        if (hash_value <= target) {
            string final_hash = bytes_to_hex(
                reverse_bytes(hash)
            );

            cout << endl;
            cout << "=== SUCCESS! RESULTS FOR CHAINPARAMS ===" << endl;
            cout << "pszTimestamp:  \"" << message << "\"" << endl;
            cout << "nTime:         " << NTIME << endl;
            cout << "nNonce:        " << nonce << endl;
            cout << "nBits:         0x" << bits_str << endl;
            cout << "Merkle Root:   " << merkle_root << endl;
            cout << "Genesis Hash:  " << final_hash << endl;
            cout << "nVersion:      1" << endl;
            cout << "=========================================" << endl;
            return 0;
        }
    }

    cout << "No valid nonce found." << endl;
    return 1;
}
