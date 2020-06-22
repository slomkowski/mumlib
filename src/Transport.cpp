#include "mumlib/Transport.hpp"

#if defined(__MSYS__) && defined(__URUSSTUDIO__)
#include "Mumble.pb-msys.h"
#else
#include "Mumble.pb.h"
#endif

#include <boost/array.hpp>
#include <boost/format.hpp>

using namespace std;

static boost::posix_time::seconds PING_INTERVAL(4);

const long CLIENT_VERSION = 0x01020A;
const string CLIENT_RELEASE("Mumlib");
const string CLIENT_OS("OS Unknown");
const string CLIENT_OS_VERSION("1");

static map<MumbleProto::Reject_RejectType, string> rejectMessages = {
        {MumbleProto::Reject_RejectType_None,              "no reason provided"},
        {MumbleProto::Reject_RejectType_WrongVersion,      "wrong version"},
        {MumbleProto::Reject_RejectType_InvalidUsername,   "invalid username"},
        {MumbleProto::Reject_RejectType_WrongUserPW,       "wrong user password"},
        {MumbleProto::Reject_RejectType_WrongServerPW,     "wrong server password"},
        {MumbleProto::Reject_RejectType_UsernameInUse,     "username in use"},
        {MumbleProto::Reject_RejectType_ServerFull,        "server full"},
        {MumbleProto::Reject_RejectType_NoCertificate,     "no certificate provided"},
        {MumbleProto::Reject_RejectType_AuthenticatorFail, "authenticator fail"}
};

mumlib::Transport::Transport(
        io_service &ioService,
        mumlib::ProcessControlMessageFunction processMessageFunc,
        ProcessEncodedAudioPacketFunction processEncodedAudioPacketFunction,
        bool noUdp,
        std::string cert_file,
        std::string privkey_file) :
        logger(log4cpp::Category::getInstance("mumlib.Transport")),
        ioService(ioService),
        processMessageFunction(std::move(processMessageFunc)),
        processEncodedAudioPacketFunction(std::move(processEncodedAudioPacketFunction)),
        noUdp(noUdp),
        state(ConnectionState::NOT_CONNECTED),
        ping_state(PingState::NONE),
        udpSocket(ioService),
        sslContext(ssl::context::sslv23),
        sslContextHelper(sslContext, cert_file, privkey_file),
        sslSocket(ioService, sslContext),
        pingTimer(ioService, PING_INTERVAL),
        asyncBufferPool(static_cast<const unsigned long>(max(MAX_UDP_LENGTH, MAX_TCP_LENGTH))) {

    sslIncomingBuffer = new uint8_t[MAX_TCP_LENGTH];

    pingTimer.async_wait(boost::bind(&Transport::pingTimerTick, this, _1));
}

mumlib::Transport::~Transport() {
    //disconnect();
    delete[] sslIncomingBuffer;
}

void mumlib::Transport::connect(
        std::string host,
        int port,
        std::string user,
        std::string password) {

    boost::system::error_code errorCode;

    connectionParams = make_pair(host, port);
    credentials = make_pair(user, password);

    udpActive = false;
    state = ConnectionState::IN_PROGRESS;

    logger.warn("Verify_mode");
    sslSocket.set_verify_mode(boost::asio::ssl::verify_peer);

    logger.warn("set_verify_callback");

    //todo for now it accepts every certificate, move it to callback
    sslSocket.set_verify_callback([](bool preverified, boost::asio::ssl::verify_context &ctx) {
        return true;
    });

    logger.warn("Trying connection...");

    try {
        if (not noUdp) {
            ip::udp::resolver resolverUdp(ioService);
            ip::udp::resolver::query queryUdp(ip::udp::v4(), host, to_string(port));
            udpReceiverEndpoint = *resolverUdp.resolve(queryUdp);
            udpSocket.open(ip::udp::v4());

            boost::array<char, 1> send_buf  = { 0 };
            udpSocket.send_to(boost::asio::buffer(send_buf), udpReceiverEndpoint);

            doReceiveUdp();
            logger.warn("noUdp try");
        }

        logger.warn("after noUdp try");

        ip::tcp::resolver resolverTcp(ioService);
        logger.warn("resolverTcp");
        ip::tcp::resolver::query queryTcp(host, to_string(port));
        logger.warn("queryTcp");

        async_connect(sslSocket.lowest_layer(), resolverTcp.resolve(queryTcp),
                      bind(&Transport::sslConnectHandler, this, boost::asio::placeholders::error));
        logger.warn("async_connect try");
    } catch (runtime_error &exp) {
        throwTransportException(string("failed to establish connection: ") + exp.what());
    }
}

void mumlib::Transport::disconnect()
{
    ioService.stop();

    if (state != ConnectionState::NOT_CONNECTED) {
        boost::system::error_code errorCode;

        // todo perform different operations for each ConnectionState

        sslSocket.lowest_layer().close(errorCode);

        udpSocket.shutdown(boost::asio::ip::udp::socket::shutdown_both, errorCode);
        udpSocket.close(errorCode);
        if (errorCode) {
            logger.warn("Not ping: UDP socket close returned error: %s.", errorCode.message().c_str());
        }

        state = ConnectionState::NOT_CONNECTED;
        printf("Not Connected\n");
    }

    printf("Disconnected\n");
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void mumlib::Transport::sendVersion() {
    MumbleProto::Version version;

    version.set_version(CLIENT_VERSION);
    version.set_os(CLIENT_OS);
    version.set_release(CLIENT_RELEASE);
    version.set_os_version(CLIENT_OS_VERSION);

    logger.warn("Sending version information.");

    sendControlMessagePrivate(MessageType::VERSION, version);
}

void mumlib::Transport::sendAuthentication() {
    string user, password;
    tie(user, password) = credentials;

    MumbleProto::Authenticate authenticate;
    authenticate.set_username(user);
    authenticate.set_password(password);
    authenticate.clear_celt_versions();
    authenticate.clear_tokens();
    authenticate.set_opus(true);

    logger.warn("Sending authententication.");

    sendControlMessagePrivate(MessageType::AUTHENTICATE, authenticate);
}

void mumlib::Transport::sendSslPing() {

    if (ping_state == PingState::PING) {
        logger.warn("Continue sending SSL ping.");
        disconnect();
        return;
    }

    ping_state = PingState::PING;

    MumbleProto::Ping ping;

    ping.set_timestamp(std::time(nullptr));

    logger.warn("Sending SSL ping.");

    sendControlMessagePrivate(MessageType::PING, ping);
}


bool mumlib::Transport::isUdpActive() {
    return udpActive;
}

void mumlib::Transport::doReceiveUdp()
{
    udpSocket.async_receive_from(
            buffer(udpIncomingBuffer, MAX_UDP_LENGTH),
            udpReceiverEndpoint,
            [this](const boost::system::error_code &ec, size_t bytesTransferred) {
                if (!ec and bytesTransferred > 0) {
                    //logger.warn("Received UDP packet of %d B.", bytesTransferred);

                    if (not cryptState.isValid()) {
                        throwTransportException("received UDP packet before: CRYPT SETUP message");
                    } else {
                        lastReceivedUdpPacketTimestamp = std::chrono::system_clock::now();

                        if (udpActive == false) {
                            udpActive = true;
                            logger.warn("UDP is up.");
                        }

                        uint8_t plainBuffer[1024];
                        const int plainBufferLength = static_cast<const int>(bytesTransferred - 4);

                        bool success = cryptState.decrypt(
                                udpIncomingBuffer, plainBuffer, static_cast<unsigned int>(bytesTransferred));

                        if (not success) {
                            throwTransportException("UDP packet: decryption failed");
                        }

                        processAudioPacket(plainBuffer, plainBufferLength);
                    }

                    doReceiveUdp();
                } else if (ec == boost::asio::error::operation_aborted) {
                    boost::system::error_code errorCode;
                    logger.warn("UDP receive function cancelled.");
                    if (ping_state == PingState::PING) {
                        logger.warn("UDP receive function cancelled PONG.");
                    }
                } else {
                    throwTransportException("UDP receive failed: " + ec.message());
                }
            });
}

void mumlib::Transport::sslConnectHandler(const boost::system::error_code &error) {
    if (!error) {
        sslSocket.async_handshake(ssl::stream_base::client,
                                  boost::bind(&Transport::sslHandshakeHandler, this,
                                              boost::asio::placeholders::error));
    }
    else {
        disconnect();
    }
}

void mumlib::Transport::sslHandshakeHandler(const boost::system::error_code &error)
{
    boost::system::error_code errorCode = error;
    if (!error) {
        doReceiveSsl();

        sendVersion();
        sendAuthentication();
    }
    else {
        throwTransportException((boost::format("Handshake failed: %s.") % error.message()).str());
    }
}

void mumlib::Transport::pingTimerTick(const boost::system::error_code &e) {
    if (state == ConnectionState::CONNECTED) {

        sendSslPing();

        if (not noUdp) {
            using namespace std::chrono;

            logger.warn("pingTimerTick: Sending UDP ping.");
            sendUdpPing();

            if (udpActive) {
                const int lastUdpReceivedMilliseconds = duration_cast<milliseconds>(
                        system_clock::now() - lastReceivedUdpPacketTimestamp).count();

                if (lastUdpReceivedMilliseconds > PING_INTERVAL.total_milliseconds() + 1000) {
                    logger.warn("Didn't receive UDP ping in %d ms, falling back to TCP.", lastUdpReceivedMilliseconds);
                }
            }
        }
    }

    if ((state == ConnectionState::NOT_CONNECTED) && (ping_state == PingState::PING)) {
        logger.warn("pingTimerTick disconnect!.");
        disconnect();
    }

    logger.warn("TimerTick!.");
    pingTimer.expires_at(pingTimer.expires_at() + PING_INTERVAL);
    pingTimer.async_wait(boost::bind(&Transport::pingTimerTick, this, _1));
}

void mumlib::Transport::sendUdpAsync(uint8_t *buff, int length) {
    if (length > MAX_UDP_LENGTH - 4) {
        throwTransportException("maximum allowed: data length is %d" + to_string(MAX_UDP_LENGTH - 4));
    }

    auto *encryptedMsgBuff = asyncBufferPool.malloc();
    const int encryptedMsgLength = length + 4;

    cryptState.encrypt(buff, reinterpret_cast<uint8_t *>(encryptedMsgBuff), static_cast<unsigned int>(length));

    //logger.warn("Sending %d B of data UDP asynchronously.", encryptedMsgLength);

    udpSocket.async_send_to(
            boost::asio::buffer(encryptedMsgBuff, static_cast<size_t>(length + 4)),
            udpReceiverEndpoint,
            [this, encryptedMsgBuff](const boost::system::error_code &ec, size_t bytesTransferred) {
                asyncBufferPool.free(encryptedMsgBuff);
                if (!ec and bytesTransferred > 0) {
                    //logger.warn("Sent %d B via UDP.", bytesTransferred);
                } else {
                    throwTransportException("UDP send failed: " + ec.message());
                }
            });
}

void mumlib::Transport::doReceiveSsl() {
    async_read(
            sslSocket,
            boost::asio::buffer(sslIncomingBuffer, MAX_TCP_LENGTH),
            [this](const boost::system::error_code &error, size_t bytesTransferred) -> size_t {
                if (bytesTransferred < 6) {
                    // we need the message header to determine the payload length
                    return 6 - bytesTransferred;
                }

                const int payloadSize = ntohl(*reinterpret_cast<uint32_t *>(sslIncomingBuffer + 2));
                const int wholeMessageLength = payloadSize + 6;
                size_t remaining = wholeMessageLength - bytesTransferred;
                remaining = max(remaining, (size_t) 0);

                if (wholeMessageLength > MAX_TCP_LENGTH) {
                    throwTransportException(
                            (boost::format("message bigger (%d B) than max allowed size (%d B)")
                             % wholeMessageLength % MAX_TCP_LENGTH).str());
                }

                return remaining;
            },
            [this](const boost::system::error_code &ec, size_t bytesTransferred) {
                if (!ec and bytesTransferred > 0) {

                    int messageType = ntohs(*reinterpret_cast<uint16_t *>(sslIncomingBuffer));

                    //logger.warn("Received %d B of data (%d B payload, type %d).", bytesTransferred,
                    //             bytesTransferred - 6, messageType);

                    processMessageInternal(
                            static_cast<MessageType>(messageType),
                            &sslIncomingBuffer[6],
                            static_cast<int>(bytesTransferred - 6));

                    doReceiveSsl();
                } else {
                    logger.error("SSL receiver error: %s. Bytes transferred: %d.",
                                 ec.message().c_str(), bytesTransferred);
                    //todo temporarily disable exception throwing until issue #6 is solved
                    //throwTransportException("receive failed: " + ec.message());
                }
            });
}

void mumlib::Transport::processMessageInternal(MessageType messageType, uint8_t *buffer, int length) {
    switch (messageType) {

        case MessageType::UDPTUNNEL: {
            //logger.warn("Received %d B of encoded audio data via TCP.", length);
            processAudioPacket(buffer, length);
        }
            break;
        case MessageType::AUTHENTICATE: {
            logger.warn("Authenticate message received after authenticated.");
        }
            break;
        case MessageType::PING: {
            MumbleProto::Ping ping;
            ping.ParseFromArray(buffer, length);
            stringstream log;
            log << "Received ping.";
            if (ping.has_good()) {
                log << " good: " << ping.good();
            }
            if (ping.has_late()) {
                log << " late: " << ping.late();
            }
            if (ping.has_lost()) {
                log << " lost: " << ping.lost();
            }
            if (ping.has_tcp_ping_avg()) {
                log << " TCP avg: " << ping.tcp_ping_avg() << " ms";
            }
            if (ping.has_udp_ping_avg()) {
                log << " UDP avg: " << ping.udp_ping_avg() << " ms";
            }

            //logger.warn(log.str());
            ping_state = PingState::PONG;
        }
            break;
        case MessageType::REJECT: {
            MumbleProto::Reject reject;
            reject.ParseFromArray(buffer, length);

            stringstream errorMesg;
            errorMesg << "failed to authenticate";

            if (reject.has_type()) {
                errorMesg << ": " << rejectMessages.at(reject.type());
            }

            if (reject.has_reason()) {
                errorMesg << ", reason: " << reject.reason();
            }

            throwTransportException(errorMesg.str());
        }
            break;
        case MessageType::SERVERSYNC: {
            state = ConnectionState::CONNECTED;

            logger.warn("SERVERSYNC. Calling external ProcessControlMessageFunction.");

            processMessageFunction(messageType, buffer, length);
        }
            break;
        case MessageType::CRYPTSETUP: {
            if (not noUdp) {
                MumbleProto::CryptSetup cryptsetup;
                cryptsetup.ParseFromArray(buffer, length);

                if (cryptsetup.client_nonce().length() != AES_BLOCK_SIZE
                    or cryptsetup.server_nonce().length() != AES_BLOCK_SIZE
                    or cryptsetup.key().length() != AES_BLOCK_SIZE) {
                    throwTransportException("one of cryptographic: parameters has invalid length");
                }

                cryptState.setKey(
                        reinterpret_cast<const unsigned char *>(cryptsetup.key().c_str()),
                        reinterpret_cast<const unsigned char *>(cryptsetup.client_nonce().c_str()),
                        reinterpret_cast<const unsigned char *>(cryptsetup.server_nonce().c_str()));

                if (not cryptState.isValid()) {
                    throwTransportException("crypt setup: data not valid");
                }

                logger.warn("Set up cryptography for UDP transport. Sending UDP ping.");

                sendUdpPing();

            } else {
                logger.warn("Ignoring crypt setup message, because UDP is disabled.");
            }
        }
            break;
        default: {
            logger.warn("Calling external ProcessControlMessageFunction.");
            processMessageFunction(messageType, buffer, length);
        }
            break;
    }
}

void mumlib::Transport::sendUdpPing()
{
    //logger.warn("Sending UDP ping.");

    vector<uint8_t> message;
    message.push_back(0x20);

    auto timestampVarint = VarInt(static_cast<int64_t>(time(nullptr))).getEncoded();
    message.insert(message.end(), timestampVarint.begin(), timestampVarint.end());

    sendUdpAsync(&message[0], static_cast<int>(message.size()));
}

void mumlib::Transport::sendSsl(uint8_t *buff, int length) {

    if (length > MAX_TCP_LENGTH) {
        logger.warn("Sending %d B of data via SSL. Maximal allowed data length to receive is %d B.", length,
                    MAX_TCP_LENGTH);
    }

    //logger.warn("Sending %d bytes of data.", length);

    if (!buff) {
        return;
    }

    try {
        write(sslSocket, boost::asio::buffer(buff, static_cast<size_t>(length)));
    } catch (boost::system::system_error &err) {
        throwTransportException(std::string("SSL send failed: ") + err.what());
    }
}

void mumlib::Transport::sendSslAsync(uint8_t *buff, int length) {
    if (length > MAX_TCP_LENGTH) {
        logger.warn("Sending %d B of data via SSL. Maximal allowed data length to receive is %d B.", length,
                    MAX_TCP_LENGTH);
    }

    auto *asyncBuff = asyncBufferPool.malloc();

    memcpy(asyncBuff, buff, static_cast<size_t>(length));

    //logger.warn("Sending %d B of data asynchronously.", length);

    async_write(
            sslSocket,
            boost::asio::buffer(asyncBuff, static_cast<size_t>(length)),
            [this, asyncBuff](const boost::system::error_code &ec, size_t bytesTransferred) {
                asyncBufferPool.free(asyncBuff);
                //logger.warn("Sent %d B.", bytesTransferred);
                if (!ec and bytesTransferred > 0) {

                } else {
                    throwTransportException("async SSL send failed: " + ec.message());
                }
            });
}

void mumlib::Transport::sendControlMessage(MessageType type, google::protobuf::Message &message) {
    if (state != ConnectionState::CONNECTED) {
        logger.warn("sendControlMessage: Connection not established.");
        return;
    }
    sendControlMessagePrivate(type, message);
}

void mumlib::Transport::sendControlMessagePrivate(MessageType type, google::protobuf::Message &message) {


    const uint16_t type_network = htons(static_cast<uint16_t>(type));

    const int size = message.ByteSize();
    const uint32_t size_network = htonl((uint32_t) size);

    const int length = sizeof(type_network) + sizeof(size_network) + size;

    uint8_t buff[MAX_UDP_LENGTH];

    memcpy(buff, &type_network, sizeof(type_network));

    memcpy(buff + sizeof(type_network), &size_network, sizeof(size_network));

    message.SerializeToArray(buff + sizeof(type_network) + sizeof(size_network), size);

    sendSsl(buff, length);
}

void mumlib::Transport::throwTransportException(string message) {
    state = ConnectionState::FAILED;

    throw TransportException(std::move(message));
}

mumlib::SslContextHelper::SslContextHelper(ssl::context &ctx, std::string cert_file, std::string privkey_file) {
    if ( cert_file.size() > 0 ) {
        ctx.use_certificate_file(cert_file, ssl::context::file_format::pem);
    }
    if ( privkey_file.size() > 0 ) {
        ctx.use_private_key_file(privkey_file, ssl::context::file_format::pem);
    }
}


void mumlib::Transport::sendEncodedAudioPacket(uint8_t *buffer, int length) {
    if (state != ConnectionState::CONNECTED) {
        logger.warn("sendEncodedAudioPacket: Connection not established.");
        return;
    }

    if (udpActive) {
        //logger.warn("Sending %d B of audio data via UDP.", length);
        sendUdpAsync(buffer, length);
    } else {
        //logger.warn("Sending %d B of audio data via TCP.", length);

        const uint16_t netUdptunnelType = htons(static_cast<uint16_t>(MessageType::UDPTUNNEL));

        const uint32_t netLength = htonl(static_cast<uint32_t>(length));

        const int packet = sizeof(netUdptunnelType) + sizeof(netLength) + length;

        uint8_t packetBuff[MAX_UDP_LENGTH];

        memcpy(packetBuff, &netUdptunnelType, sizeof(netUdptunnelType));
        memcpy(packetBuff + sizeof(netUdptunnelType), &netLength, sizeof(netLength));
        memcpy(packetBuff + sizeof(netUdptunnelType) + sizeof(netLength), buffer, static_cast<size_t>(length));

        sendSsl(packetBuff, length + sizeof(netUdptunnelType) + sizeof(netLength));
    }
}

void mumlib::Transport::processAudioPacket(uint8_t *buff, int length) {
    auto type = static_cast<AudioPacketType >((buff[0] & 0xE0) >> 5);
    switch (type) {
        case AudioPacketType::CELT_Alpha:
        case AudioPacketType::Speex:
        case AudioPacketType::CELT_Beta:
        case AudioPacketType::OPUS:
            processEncodedAudioPacketFunction(type, buff, length);
            //logger.warn("audio typehex: 0x%2x typedec: %d", buff[0], type);
            break;
        case AudioPacketType::Ping:
            break;
        default:
            logger.error("Not recognized audio type: %xd.", buff[0]);
    }
}

