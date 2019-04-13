#pragma once

#include <mumlib/CryptState.hpp>
#include <mumlib/VarInt.hpp>
#include <mumlib/enums.hpp>

#include <boost/noncopyable.hpp>
#include <boost/bind.hpp>
#include <boost/pool/pool.hpp>
#ifdef MUMLIB_USE_LOG4CPP
#include <MUMLIB_USE_LOG4CPP/Category.hh>
#endif
#include <google/protobuf/message.h>

#include <chrono>

namespace mumlib {

    constexpr int MAX_UDP_LENGTH = 1024;
    constexpr int MAX_TCP_LENGTH = 129 * 1024; // 128 kB + some reserve

    using namespace std;
    using namespace boost::asio;
    using namespace boost::asio::ip;

    typedef function<bool(MessageType, uint8_t *, int)> ProcessControlMessageFunction;

    typedef function<bool(AudioPacketType, uint8_t *, int)> ProcessEncodedAudioPacketFunction;
#ifdef MUMLIB_USE_EXCEPTIONS
    class TransportException : public MumlibException {
    public:
        TransportException(string message) : MumlibException(message) { }
    };
#endif

    class Transport : boost::noncopyable {
    public:
        Transport(io_service &ioService,
                  ProcessControlMessageFunction processControlMessageFunc,
                  ProcessEncodedAudioPacketFunction processEncodedAudioPacketFunction,
                  MumlibConfiguration MumblConfig,
                  bool noUdp = true);

        ~Transport();

        void connect(string host,
                     int port,
                     string user,
                     string password);

        void disconnect();

        ConnectionState getConnectionState() {
            return state;
        }

        bool isUdpActive();

        void sendControlMessage(MessageType type, google::protobuf::Message &message);

        void sendEncodedAudioPacket(uint8_t *buffer, int length);

        void set_callback(Callback *cb)
        {
            this->cb = cb;
        }

    private:
#ifdef MUMLIB_USE_LOG4CPP
        MUMLIB_USE_LOG4CPP::Category &logger;
#endif

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
        ssl::stream<tcp::socket> *sslSocket; //must be created after context already configured
        uint8_t *sslIncomingBuffer;

        deadline_timer pingTimer;
        std::chrono::time_point<std::chrono::system_clock> lastReceivedUdpPacketTimestamp;

        boost::pool<> asyncBufferPool;

        MumlibConfiguration MumbleConfig;
        //session related data
        std::string name;
        uint32_t session;
        //
        Callback *cb = nullptr;

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
#ifdef MUMLIB_USE_EXCEPTIONS
        void throwTransportException(string message);
#endif

        void processAudioPacket(uint8_t *buff, int length);
    };


}
