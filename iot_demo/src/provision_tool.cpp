#include "common.hpp"
#include "mincosig.hpp"
#include "protocol.hpp"

#include <iostream>

using namespace iotproto;

static std::string arg_value(int argc, char** argv, const std::string& name, const std::string& def = "") {
    for (int i = 1; i + 1 < argc; ++i) if (argv[i] == name) return argv[i + 1];
    return def;
}

static bool has_arg(int argc, char** argv, const std::string& name) {
    for (int i = 1; i < argc; ++i) if (argv[i] == name) return true;
    return false;
}

static void usage() {
    std::cout <<
        "Usage:\n"
        "  provision_tool --hwid <device-cpu-serial> --token <Token> [options]\n\n"
        "Options:\n"
        "  --device-store <file>   default: device_store.conf\n"
        "  --ta-db <file>          default: ta_db.conf\n"
        "  --ta-key <file>         default: ta_key.conf\n\n"
        "This tool simulates manufacturing/provisioning. It generates:\n"
        "  device_store.conf: HWID, ciphertext_def, salt_d, pk2, Pub_TA\n"
        "  ta_db.conf: Token, Pub_def, salt_s, H(salt_d), sk2, v2, pk2\n"
        "  ta_key.conf: TA Ed25519 signing key pair\n";
}

int main(int argc, char** argv) {
    try {
        sodium_init_or_throw();
        if (has_arg(argc, argv, "--help") || argc == 1) { usage(); return 0; }

        const std::string hwid = arg_value(argc, argv, "--hwid");
        const std::string token = arg_value(argc, argv, "--token");
        if (hwid.empty() || token.empty()) {
            usage();
            return 1;
        }
        const std::string device_store_path = arg_value(argc, argv, "--device-store", "device_store.conf");
        const std::string ta_db_path = arg_value(argc, argv, "--ta-db", "ta_db.conf");
        const std::string ta_key_path = arg_value(argc, argv, "--ta-key", "ta_key.conf");

        std::map<std::string, std::string> ta_key;
        ByteVec ta_pub, ta_sec;
        try {
            ta_key = load_kv_file(ta_key_path);
            ta_pub = hex_decode(required_value(ta_key, "ta_pub"));
            ta_sec = hex_decode(required_value(ta_key, "ta_sec"));
            require_len(ta_pub, ED25519_PK_LEN, "ta_pub");
            require_len(ta_sec, ED25519_SK_LEN, "ta_sec");
            std::cout << "Loaded existing TA key: " << ta_key_path << "\n";
        } catch (...) {
            DefaultKeyPair ta = ed25519_keypair();
            ta_pub = ta.pub;
            ta_sec = ta.sec;
            save_kv_file(ta_key_path, {{"ta_pub", hex_encode(ta_pub)}, {"ta_sec", hex_encode(ta_sec)}});
            std::cout << "Generated new TA key: " << ta_key_path << "\n";
        }

        DefaultKeyPair def = ed25519_keypair();
        ByteVec salt_d = random_bytes(SALT_LEN);
        ByteVec salt_s = random_bytes(SALT_LEN);
        ByteVec h_salt_d = hash32(salt_d);
        ByteVec K = derive_default_key(token, salt_d, salt_s, hwid);
        ByteVec ciphertext_def = aead_encrypt(K, def.sec, str_bytes(hwid));

        auto server_share = mincosig::create_server_share_random();

        std::map<std::string, std::string> device_store = {
            {"hwid", hwid},
            {"ciphertext_def", hex_encode(ciphertext_def)},
            {"salt_d", hex_encode(salt_d)},
            {"pk2", hex_encode(server_share.pk2)},
            {"ta_pub", hex_encode(ta_pub)}
        };
        save_kv_file(device_store_path, device_store);

        std::map<std::string, std::string> ta_db = {
            {"hwid", hwid},
            {"token", hex_encode(str_bytes(token))},
            {"consumed", "0"},
            {"pub_def", hex_encode(def.pub)},
            {"salt_s", hex_encode(salt_s)},
            {"h_salt_d", hex_encode(h_salt_d)},
            {"sk2", hex_encode(server_share.sk2)},
            {"v2", hex_encode(server_share.v2)},
            {"pk2", hex_encode(server_share.pk2)},
            {"pub_usr", ""}
        };
        save_kv_file(ta_db_path, ta_db);

        sodium_memzero(def.sec.data(), def.sec.size());
        sodium_memzero(K.data(), K.size());
        sodium_memzero(server_share.sk2.data(), server_share.sk2.size());
        sodium_memzero(server_share.v2.data(), server_share.v2.size());

        std::cout << "Provisioning completed.\n"
                  << "  device store: " << device_store_path << "\n"
                  << "  TA database : " << ta_db_path << "\n"
                  << "  TA key      : " << ta_key_path << "\n"
                  << "  HWID        : " << hwid << "\n"
                  << "  Token       : " << token << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[provision_tool] error: " << e.what() << "\n";
        return 1;
    }
}
