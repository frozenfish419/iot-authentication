#pragma once

#include "common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace iotproto::net {

struct Message {
    uint8_t type = 0;
    std::vector<ByteVec> fields;
};

class TcpSocket {
public:
    TcpSocket();
    explicit TcpSocket(std::intptr_t fd);
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;
    ~TcpSocket();

    static void platform_init();
    static TcpSocket connect_to(const std::string& host, uint16_t port);
    static TcpSocket listen_on(uint16_t port, int backlog = 8);
    TcpSocket accept_one();

    void send_all(const unsigned char* data, size_t len);
    void recv_all(unsigned char* data, size_t len);
    void close();
    bool valid() const;

private:
    std::intptr_t fd_ = -1;
};

void send_message(TcpSocket& sock, const Message& msg);
Message recv_message(TcpSocket& sock);

} // namespace iotproto::net
