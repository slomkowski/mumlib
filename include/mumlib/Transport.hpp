#pragma once

#include "mumlib/CryptState.hpp"
#include "mumlib/VarInt.hpp"
#include "enums.hpp"

#include <boost/noncopyable.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/pool/pool.hpp>

#include <log4cpp/Category.hh>
#include <google/protobuf/message.h>

#include <chrono>
#include <utility>

namespace mumlib {

    constexpr int MAX_UDP_LENGTH = 1024;
    constexpr int MAX_TCP_LENGTH = 129 * 1024; // 128 kB + some reserve

    using namespace std;
    using namespace boost::asio;
    using namespace boost::asio::ip;

    typedef function<bool(MessageType, uint8_t *, int)> ProcessControlMessageFunction;

    typedef function<bool(AudioPacketType, uint8_t *, int)> ProcessEncodedAudioPacketFunction;

    class TransportException : public MumlibException {
    public:
        TransportException(string message) : MumlibException(std::move(message)) { }
    };

    class Transport : boost::noncopyable {
    public:
        Transport(io_service &ioService,
                  ProcessControlMessageFunction processControlMessageFunc,
                  ProcessEncodedAudioPacketFunction processEncodedAudioPacketFunction,
                  bool noUdp = false);

        ~Transport();

        void connect(string host,
                     int port,
                     string user,
                     string password);

        void disconnect();

        void reconnect();

        ConnectionState getConnectionState() {
            return state;
        }

        bool isUdpActive();

        void sendControlMessage(MessageType type, google::protobuf::Message &message);

        void sendEncodedAudioPacket(uint8_t *buffer, int length);

    private:
        log4cpp::Category &logger;

        io_service &ioService;

        pair<string, int> connectionParams;

        pair<string, string> credentials;

        ProcessControlMessageFunction processMessageFunction;

        ProcessEncodedAudioPacketFunction processEncodedAudioPacketFunction;

        const bool noUdp;

        volatile bool udpActive;

        ConnectionState state;

        udp::socket udpSocket;
        ip::udp::endpoint udpReceiverEndpoint;
        uint8_t udpIncomingBuffer[MAX_UDP_LENGTH];
        CryptState cryptState;

        ssl::context sslContext;
        ssl::stream<tcp::socket> sslSocket;
        uint8_t *sslIncomingBuffer;

        deadline_timer pingTimer;
        std::chrono::time_point<std::chrono::system_clock> lastReceivedUdpPacketTimestamp;

        boost::pool<> asyncBufferPool;

        void pingTimerTick(const boost::system::error_code &e);

        void sslConnectHandler(const boost::system::error_code &error);

        void sslHandshakeHandler(const boost::system::error_code &error);

        void doReceiveSsl();

        void sendSsl(uint8_t *buff, int length);

        void sendSslAsync(uint8_t *buff, int length);

        void sendControlMessagePrivate(MessageType type, google::protobuf::Message &message);

        void sendSslPing();

        void sendVersion();

        void sendAuthentication();

        void processMessageInternal(MessageType messageType, uint8_t *buffer, int length);

        void doReceiveUdp();

        void sendUdpAsync(uint8_t *buff, int length);

        void sendUdpPing();

        void throwTransportException(string message);

        void processAudioPacket(uint8_t *buff, int length);
    };


}
