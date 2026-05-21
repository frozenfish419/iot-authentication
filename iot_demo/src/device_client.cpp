#include "common.hpp"
#include "mincosig.hpp"
#include "net.hpp"
#include "protocol.hpp"

#include <fstream>
#include <iostream>

using namespace iotproto;
using namespace iotproto::net;

static std::string arg_value(int argc, char** argv, const std::string& name, const std::string& def = "") {
    for (int i = 1; i + 1 < argc; ++i) if (argv[i] == name) return argv[i + 1];
    return def;
}

static bool has_arg(int argc, char** argv, const std::string& name) {
    for (int i = 1; i < argc; ++i) if (argv[i] == name) return true;
    return false;
}

static uint64_t elapsed_since(uint64_t begin_ns) {
    return monotonic_time_ns() - begin_ns;
}

struct DevicePerf {
    uint64_t m1_device_generate_ns = 0;
    uint64_t m2_device_process_ns = 0;
    uint64_t m3_device_generate_ns = 0;
    uint64_t m4_device_process_ns = 0;
    uint64_t local_secret_store_ns = 0; // not counted as a protocol-message cost
};

static void print_device_perf(const DevicePerf& p) {
    std::cout << "\n[Device timing, network send/receive waiting excluded]\n"
              << "Message, device-side operation, time(ms)\n"
              << "M1, generate request, " << format_ms(p.m1_device_generate_ns) << "\n"
              << "M2, process response, " << format_ms(p.m2_device_process_ns) << "\n"
              << "M3, generate ownership message, " << format_ms(p.m3_device_generate_ns) << "\n"
              << "M4, process ACK, " << format_ms(p.m4_device_process_ns) << "\n"
              << "Extra, protect/store sk1||v1 locally, " << format_ms(p.local_secret_store_ns) << "\n";
}

static void append_device_perf_csv(const std::string& path, const DevicePerf& p) {
    if (path.empty()) return;
    const bool need_header = !std::ifstream(path).good();
    std::ofstream out(path, std::ios::app);
    if (!out) throw std::runtime_error("cannot open perf csv for append: " + path);
    if (need_header) out << "side,message,operation,time_ms\n";
    out << "device,M1,generate_request," << format_ms(p.m1_device_generate_ns) << "\n";
    out << "device,M2,process_response," << format_ms(p.m2_device_process_ns) << "\n";
    out << "device,M3,generate_ownership_message," << format_ms(p.m3_device_generate_ns) << "\n";
    out << "device,M4,process_ack," << format_ms(p.m4_device_process_ns) << "\n";
    out << "device,Extra,protect_store_local_secret," << format_ms(p.local_secret_store_ns) << "\n";
}

static void usage() {
    std::cout <<
        "Usage:\n"
        "  device_client --server <TA-IP> --port 9000 --store device_store.conf [options]\n\n"
        "Options:\n"
        "  --token <Token>       Provide Token non-interactively\n"
        "  --pwd <PWD>           Provide password non-interactively\n"
        "  --hwid <HWID>         Override /proc/cpuinfo CPU Serial\n"
        "  --out <file>          default: device_user_secret.conf\n"
        "  --perf-csv <file>     Append device-side timing results to CSV\n"
        "  --show-hwid           Print HWID detected from /proc/cpuinfo and exit\n";
}

int main(int argc, char** argv) {
    try {
        sodium_init_or_throw();
        if (has_arg(argc, argv, "--help")) { usage(); return 0; }
        if (has_arg(argc, argv, "--show-hwid")) {
            std::cout << read_hwid_from_cpuinfo() << "\n";
            return 0;
        }

        DevicePerf perf;

        const std::string server_ip = arg_value(argc, argv, "--server");
        if (server_ip.empty()) { usage(); return 1; }
        const uint16_t port = static_cast<uint16_t>(std::stoi(arg_value(argc, argv, "--port", "9000")));
        const std::string store_path = arg_value(argc, argv, "--store", "device_store.conf");
        const std::string out_path = arg_value(argc, argv, "--out", "device_user_secret.conf");
        const std::string perf_csv = arg_value(argc, argv, "--perf-csv");

        std::string token = arg_value(argc, argv, "--token");
        if (token.empty()) {
            std::cout << "Input Token: ";
            std::getline(std::cin, token);
        }
        std::string pwd = arg_value(argc, argv, "--pwd");
        if (pwd.empty()) {
            std::cout << "Input PWD: ";
            std::getline(std::cin, pwd);
        }

        std::map<std::string, std::string> st = load_kv_file(store_path);
        std::string hwid = arg_value(argc, argv, "--hwid");
        if (hwid.empty()) hwid = read_hwid_from_cpuinfo();
        const std::string stored_hwid = required_value(st, "hwid");
        if (hwid != stored_hwid) {
            throw std::runtime_error("HWID mismatch: current=" + hwid + ", stored=" + stored_hwid);
        }

        ByteVec ciphertext_def = hex_decode(required_value(st, "ciphertext_def"));
        ByteVec salt_d = hex_decode(required_value(st, "salt_d"));
        ByteVec pk2 = hex_decode(required_value(st, "pk2"));
        ByteVec ta_pub = hex_decode(required_value(st, "ta_pub"));
        mincosig::require_valid_point(pk2, "pk2 from device store");
        require_len(ta_pub, ED25519_PK_LEN, "ta_pub");

        uint64_t t0 = monotonic_time_ns();
        auto device_share = mincosig::create_device_share_from_pk2(pk2);

        X25519KeyPair eph = x25519_keypair();
        ByteVec N_d = random_bytes(NONCE_LEN);
        uint64_t T1 = unix_time_seconds();
        ByteVec H_salt_d = hash32(salt_d);
        ByteVec xid = compute_xid(token, hwid, eph.pub, N_d, H_salt_d, T1, device_share.pk1);
        ByteVec m_co = compute_mco(hwid, device_share.pub_usr, device_share.pk1, xid);
        auto sign_state = mincosig::device_begin_sign(device_share, m_co);

        Message m1;
        m1.type = MSG_M1;
        m1.fields = {str_bytes(token), eph.pub, N_d, H_salt_d, u64be(T1), device_share.pk1, sign_state.R1};
        perf.m1_device_generate_ns = elapsed_since(t0);

        TcpSocket sock = TcpSocket::connect_to(server_ip, port);
        send_message(sock, m1);
        std::cout << "M1 sent. xid=" << hex_encode(xid) << "\n";

        Message m2 = recv_message(sock);
        t0 = monotonic_time_ns();
        if (m2.type != MSG_M2 || m2.fields.size() != 7) throw std::runtime_error("expected M2 with 7 fields");
        const ByteVec Q_s = m2.fields[0];
        const ByteVec N_s = m2.fields[1];
        const uint64_t T2 = read_u64be(m2.fields[2]);
        const ByteVec alpha = m2.fields[3];
        const ByteVec c_salt = m2.fields[4];
        const ByteVec R = m2.fields[5];
        const ByteVec S2 = m2.fields[6];

        require_len(Q_s, X25519_PK_LEN, "Q_s");
        require_len(N_s, NONCE_LEN, "N_s");
        require_len(alpha, ED25519_SIG_LEN, "alpha");
        mincosig::require_valid_point(R, "R from M2");
        mincosig::require_scalar(S2, "S2 from M2");

        ByteVec Z = x25519_shared(eph.sec, Q_s);
        ByteVec session_key = derive_session_key(Z, N_d, N_s, xid);

        ByteVec salt_plain = aead_decrypt(session_key, c_salt, xid);
        if (salt_plain.size() != SALT_LEN + 8) throw std::runtime_error("bad C_salt plaintext length");
        ByteVec salt_s(salt_plain.begin(), salt_plain.begin() + SALT_LEN);
        uint64_t T2_inside = read_u64be(salt_plain, SALT_LEN);
        if (T2_inside != T2) throw std::runtime_error("T2 mismatch inside C_salt");

        ByteVec alpha_msg = build_alpha_msg(
            Q_s, eph.pub, N_s, N_d,
            xid, salt_s, T2,
            device_share.pk1, sign_state.R1,
            R, S2
        );

        if (!verify_ed25519(alpha_msg, alpha, ta_pub)) {
            throw std::runtime_error("alpha verification failed");
        }

        ByteVec K_def = derive_default_key(token, salt_d, salt_s, hwid);
        ByteVec pri_def = aead_decrypt(K_def, ciphertext_def, str_bytes(hwid));
        require_len(pri_def, ED25519_SK_LEN, "Pri_def");
        perf.m2_device_process_ns = elapsed_since(t0);
        std::cout << "M2 verified. TA authenticated.\n";

        t0 = monotonic_time_ns();
        mincosig::ServerPartial partial{R, S2};
        ByteVec sig_usr = mincosig::device_finish_signature(device_share, sign_state, partial);
        if (!mincosig::verify_signature(device_share.pub_usr, m_co, sig_usr)) {
            throw std::runtime_error("local collaborative signature self-check failed");
        }

        uint64_t T3 = unix_time_seconds();
        ByteVec beta_msg = build_beta_msg(hwid, device_share.pub_usr, device_share.pk1, eph.pub, Q_s, N_d, N_s, xid, R, T3);
        ByteVec beta = sign_ed25519(beta_msg, pri_def);

        ByteVec plain3 = concat({beta, sig_usr, u64be(T3)});
        ByteVec c3 = aead_encrypt(session_key, plain3, xid);
        Message m3;
        m3.type = MSG_M3;
        m3.fields = {xid, c3};
        perf.m3_device_generate_ns = elapsed_since(t0);

        send_message(sock, m3);
        std::cout << "M3 sent. Waiting for M4...\n";

        Message m4 = recv_message(sock);
        t0 = monotonic_time_ns();
        if (m4.type != MSG_M4 || m4.fields.size() != 1) throw std::runtime_error("expected M4");
        ByteVec plain4 = aead_decrypt(session_key, m4.fields[0], xid);
        if (plain4.size() != 12) throw std::runtime_error("bad M4 plaintext length");
        std::string ack(reinterpret_cast<char*>(plain4.data()), reinterpret_cast<char*>(plain4.data()) + 4);
        uint64_t T4 = read_u64be(plain4, 4);
        if (ack != "ACK1") throw std::runtime_error("bad ACK");
        perf.m4_device_process_ns = elapsed_since(t0);

        t0 = monotonic_time_ns();
        ByteVec K_usr = pbkdf_password_key(pwd, hwid);
        ByteVec C_usr = aead_encrypt(K_usr, concat({device_share.sk1, device_share.v1}), str_bytes(hwid));
        save_kv_file(out_path, {
            {"hwid", hwid},
            {"pub_usr", hex_encode(device_share.pub_usr)},
            {"pk1", hex_encode(device_share.pk1)},
            {"c_usr", hex_encode(C_usr)},
            {"note", "c_usr encrypts sk1||v1 with PBKDF(PWD,HWID); keep PWD safe"}
        });
        perf.local_secret_store_ns = elapsed_since(t0);

        std::cout << "Ownership binding completed.\n"
                  << "  Pub_usr: " << hex_encode(device_share.pub_usr) << "\n"
                  << "  Local protected secret written to: " << out_path << "\n"
                  << "  T4: " << T4 << "\n";
        print_device_perf(perf);
        append_device_perf_csv(perf_csv, perf);

        sodium_memzero(eph.sec.data(), eph.sec.size());
        sodium_memzero(Z.data(), Z.size());
        sodium_memzero(session_key.data(), session_key.size());
        sodium_memzero(K_def.data(), K_def.size());
        sodium_memzero(pri_def.data(), pri_def.size());
        sodium_memzero(K_usr.data(), K_usr.size());
        sodium_memzero(device_share.sk1.data(), device_share.sk1.size());
        sodium_memzero(device_share.v1.data(), device_share.v1.size());
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[device_client] error: " << e.what() << "\n";
        return 1;
    }
}
