#include "mumlib/Transport.hpp"

#include "Mumble.pb.h"

#include <boost/format.hpp>

using namespace std;

static boost::posix_time::seconds PING_INTERVAL(5);

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
        bool noUdp) :
        logger(log4cpp::Category::getInstance("mumlib.Transport")),
        ioService(ioService),
        processMessageFunction(processMessageFunc),
        processEncodedAudioPacketFunction(processEncodedAudioPacketFunction),
        noUdp(noUdp),
        state(ConnectionState::NOT_CONNECTED),
        udpSocket(ioService),
        sslContext(ssl::context::sslv23),
        sslSocket(ioService, sslContext),
        pingTimer(ioService, PING_INTERVAL),
        asyncBufferPool(max(MAX_UDP_LENGTH, MAX_TCP_LENGTH)) {

    sslIncomingBuffer = new uint8_t[MAX_TCP_LENGTH];

    pingTimer.async_wait(boost::bind(&Transport::pingTimerTick, this, _1));
}

mumlib::Transport::~Transport() {
    disconnect();
    delete[] sslIncomingBuffer;
}

void mumlib::Transport::connect(
        std::string host,
        int port,
        std::string user,
        std::string password) {

    state = ConnectionState::IN_PROGRESS;

    connectionParams = make_pair(host, port);
    credentials = make_pair(user, password);

    udpActive = false;

    sslSocket.set_verify_mode(boost::asio::ssl::verify_peer);

    //todo for now it accepts every certificate, move it to callback
    sslSocket.set_verify_callback([](bool preverified, boost::asio::ssl::verify_context &ctx) {
        return true;
    });

    try {
        if (not noUdp) {
            ip::udp::resolver resolverUdp(ioService);
            ip::udp::resolver::query queryUdp(ip::udp::v4(), host, to_string(port));
            udpReceiverEndpoint = *resolverUdp.resolve(queryUdp);
            udpSocket.open(ip::udp::v4());

            doReceiveUdp();
        }

        ip::tcp::resolver resolverTcp(ioService);
        ip::tcp::resolver::query queryTcp(host, to_string(port));

        async_connect(sslSocket.lowest_layer(), resolverTcp.resolve(queryTcp),
                      bind(&Transport::sslConnectHandler, this, boost::asio::placeholders::error));
    } catch (runtime_error &exp) {
        throwTransportException(string("failed to establish connection: ") + exp.what());
    }
}

void mumlib::Transport::disconnect() {

    if (state != ConnectionState::NOT_CONNECTED) {
        boost::system::error_code errorCode;

        // todo perform different operations for each ConnectionState

        sslSocket.shutdown(errorCode);
        if (errorCode) {
            logger.warn("SSL socket shutdown returned an error: %s.", errorCode.message().c_str());
        }

        sslSocket.lowest_layer().shutdown(tcp::socket::shutdown_both, errorCode);
        if (errorCode) {
            logger.warn("SSL socket lowest layer shutdown returned an error: %s.", errorCode.message().c_str());
        }

        udpSocket.close(errorCode);
        if (errorCode) {
            logger.warn("UDP socket close returned error: %s.", errorCode.message().c_str());
        }

        state = ConnectionState::NOT_CONNECTED;
    }
}


void mumlib::Transport::sendVersion() {
    MumbleProto::Version version;

    version.set_version(CLIENT_VERSION);
    version.set_os(CLIENT_OS);
    version.set_release(CLIENT_RELEASE);
    version.set_os_version(CLIENT_OS_VERSION);

    logger.info("Sending version information.");

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

    logger.info("Sending authententication.");

    sendControlMessagePrivate(MessageType::AUTHENTICATE, authenticate);
}

void mumlib::Transport::sendSslPing() {
    MumbleProto::Ping ping;
    ping.set_timestamp(std::time(nullptr));

    logger.debug("Sending SSL ping.");

    sendControlMessagePrivate(MessageType::PING, ping);
}


bool mumlib::Transport::isUdpActive() {
    return udpActive;
}

void mumlib::Transport::doReceiveUdp() {
    if (state == ConnectionState::NOT_CONNECTED) {
        return;
    }

    udpSocket.async_receive_from(
            buffer(udpIncomingBuffer, MAX_UDP_LENGTH),
            udpReceiverEndpoint,
            [this](const boost::system::error_code &ec, size_t bytesTransferred) {
                if (!ec and bytesTransferred > 0) {
                    logger.debug("Received UDP packet of %d B.", bytesTransferred);

                    if (not cryptState.isValid()) {
                        throwTransportException("received UDP packet before CRYPT SETUP message");
                    } else {
                        lastReceivedUdpPacketTimestamp = std::chrono::system_clock::now();

                        if (udpActive == false) {
                            udpActive = true;
                            logger.notice("UDP is up.");
                        }

                        uint8_t plainBuffer[1024];
                        const int plainBufferLength = bytesTransferred - 4;

                        bool success = cryptState.decrypt(
                                udpIncomingBuffer, plainBuffer, bytesTransferred);

                        if (not success) {
                            throwTransportException("UDP packet decryption failed");
                        }

                        processAudioPacket(plainBuffer, plainBufferLength);
                    }

                    doReceiveUdp();
                } else if (ec == boost::asio::error::operation_aborted) {
                    logger.debug("UDP receive function cancelled.");
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
        throwTransportException((boost::format("Connect failed: %s.") % error.message()).str());
    }
}

void mumlib::Transport::sslHandshakeHandler(const boost::system::error_code &error) {
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

            sendUdpPing();

            if (udpActive) {
                const int lastUdpReceivedMilliseconds = duration_cast<milliseconds>(
                        system_clock::now() - lastReceivedUdpPacketTimestamp).count();

                if (lastUdpReceivedMilliseconds > PING_INTERVAL.total_milliseconds() + 1000) {
                    udpActive = false;
                    logger.warn("Didn't receive UDP ping in %d ms, falling back to TCP.", lastUdpReceivedMilliseconds);
                }
            }
        }
    }

    pingTimer.expires_at(pingTimer.expires_at() + PING_INTERVAL);
    pingTimer.async_wait(boost::bind(&Transport::pingTimerTick, this, _1));
}

void mumlib::Transport::sendUdpAsync(uint8_t *buff, int length) {
    if (length > MAX_UDP_LENGTH - 4) {
        throwTransportException("maximum allowed data length is %d" + to_string(MAX_UDP_LENGTH - 4));
    }

    auto *encryptedMsgBuff = asyncBufferPool.malloc();
    const int encryptedMsgLength = length + 4;

    cryptState.encrypt(buff, reinterpret_cast<uint8_t *>(encryptedMsgBuff), length);

    logger.debug("Sending %d B of data UDP asynchronously.", encryptedMsgLength);

    udpSocket.async_send_to(
            boost::asio::buffer(encryptedMsgBuff, length + 4),
            udpReceiverEndpoint,
            [this, encryptedMsgBuff](const boost::system::error_code &ec, size_t bytesTransferred) {
                asyncBufferPool.free(encryptedMsgBuff);
                if (!ec and bytesTransferred > 0) {
                    logger.debug("Sent %d B via UDP.", bytesTransferred);
                } else {
                    throwTransportException("UDP send failed: " + ec.message());
                }
            });
}

void mumlib::Transport::doReceiveSsl() {
    if (state == ConnectionState::NOT_CONNECTED) {
        return;
    }

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

                    logger.debug("Received %d B of data (%d B payload, type %d).", bytesTransferred,
                                 bytesTransferred - 6, messageType);

                    processMessageInternal(
                            static_cast<MessageType>(messageType),
                            &sslIncomingBuffer[6],
                            bytesTransferred - 6);

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
            logger.debug("Received %d B of encoded audio data via TCP.", length);
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
            logger.debug(log.str());
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

            logger.debug("SERVERSYNC. Calling external ProcessControlMessageFunction.");
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
                    throwTransportException("one of cryptographic parameters has invalid length");
                }

                cryptState.setKey(
                        reinterpret_cast<const unsigned char *>(cryptsetup.key().c_str()),
                        reinterpret_cast<const unsigned char *>(cryptsetup.client_nonce().c_str()),
                        reinterpret_cast<const unsigned char *>(cryptsetup.server_nonce().c_str()));

                if (not cryptState.isValid()) {
                    throwTransportException("crypt setup data not valid");
                }

                logger.info("Set up cryptography for UDP transport. Sending UDP ping.");

                sendUdpPing();

            } else {
                logger.info("Ignoring crypt setup message, because UDP is disabled.");
            }
        }
            break;
        default: {
            logger.debug("Calling external ProcessControlMessageFunction.");
            processMessageFunction(messageType, buffer, length);
        }
            break;
    }
}

void mumlib::Transport::sendUdpPing() {
    if (state == ConnectionState::NOT_CONNECTED) {
        logger.debug("State changed to NOT_CONNECTED, skipping UDP ping.");
        return;
    }

    logger.debug("Sending UDP ping.");

    vector<uint8_t> message;
    message.push_back(0x20);

    auto timestampVarint = VarInt(time(nullptr)).getEncoded();
    message.insert(message.end(), timestampVarint.begin(), timestampVarint.end());

    sendUdpAsync(&message[0], message.size());
}

void mumlib::Transport::sendSsl(uint8_t *buff, int length) {
    if (length > MAX_TCP_LENGTH) {
        logger.warn("Sending %d B of data via SSL. Maximal allowed data length to receive is %d B.", length,
                    MAX_TCP_LENGTH);
    }

    logger.debug("Sending %d bytes of data.", length);

    try {
        write(sslSocket, boost::asio::buffer(buff, length));
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

    memcpy(asyncBuff, buff, length);

    logger.debug("Sending %d B of data asynchronously.", length);

    async_write(
            sslSocket,
            boost::asio::buffer(asyncBuff, length),
            [this, asyncBuff](const boost::system::error_code &ec, size_t bytesTransferred) {
                asyncBufferPool.free(asyncBuff);
                logger.debug("Sent %d B.", bytesTransferred);
                if (!ec and bytesTransferred > 0) {

                } else {
                    throwTransportException("async SSL send failed: " + ec.message());
                }
            });
}

void mumlib::Transport::sendControlMessage(MessageType type, google::protobuf::Message &message) {
    if (state != ConnectionState::CONNECTED) {
        logger.warn("Connection not established.");
        return;
    }
    sendControlMessagePrivate(type, message);
}

void mumlib::Transport::sendControlMessagePrivate(MessageType type, google::protobuf::Message &message) {


    const uint16_t type_network = htons(static_cast<uint16_t>(type));

    const int size = message.ByteSize();
    const uint32_t size_network = htonl(size);

    const int length = sizeof(type_network) + sizeof(size_network) + size;

    uint8_t buff[MAX_TCP_LENGTH];

    memcpy(buff, &type_network, sizeof(type_network));

    memcpy(buff + sizeof(type_network), &size_network, sizeof(size_network));

    message.SerializeToArray(buff + sizeof(type_network) + sizeof(size_network), size);

    sendSsl(buff, length);
}

void mumlib::Transport::throwTransportException(string message) {
    state = ConnectionState::FAILED;

    throw TransportException(message);
}

void mumlib::Transport::sendEncodedAudioPacket(uint8_t *buffer, int length) {
    if (state != ConnectionState::CONNECTED) {
        logger.warn("Connection not established.");
        return;
    }

    if (udpActive) {
        logger.debug("Sending %d B of audio data via UDP.", length);
        sendUdpAsync(buffer, length);
    } else {
        logger.debug("Sending %d B of audio data via TCP.", length);

        const uint16_t netUdptunnelType = htons(static_cast<uint16_t>(MessageType::UDPTUNNEL));

        const uint32_t netLength = htonl(length);

        const int packet = sizeof(netUdptunnelType) + sizeof(netLength) + length;

        uint8_t packetBuff[MAX_TCP_LENGTH];

        memcpy(packetBuff, &netUdptunnelType, sizeof(netUdptunnelType));
        memcpy(packetBuff + sizeof(netUdptunnelType), &netLength, sizeof(netLength));
        memcpy(packetBuff + sizeof(netUdptunnelType) + sizeof(netLength), buffer, length);

        sendSslAsync(packetBuff, length + sizeof(netUdptunnelType) + sizeof(netLength));
    }
}

void mumlib::Transport::processAudioPacket(uint8_t *buff, int length) {
    AudioPacketType type = static_cast<AudioPacketType >((buff[0] & 0xE0) >> 5);
    switch (type) {
        case AudioPacketType::CELT_Alpha:
        case AudioPacketType::Speex:
        case AudioPacketType::CELT_Beta:
        case AudioPacketType::OPUS:
            processEncodedAudioPacketFunction(type, buff, length);
            break;
        case AudioPacketType::Ping:
            break;
        default:
            logger.error("Not recognized audio type: %xd.", buff[0]);
    }
}

