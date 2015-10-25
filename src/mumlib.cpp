#include "mumlib.hpp"

#include "mumlib/CryptState.hpp"
#include "mumlib/VarInt.hpp"
#include "mumlib/enums.hpp"
#include "mumlib/Transport.hpp"
#include "mumlib/Audio.hpp"

#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <log4cpp/Category.hh>

#include <mumble.pb.h>

using namespace std;
using namespace boost::asio;

using namespace mumlib;

namespace mumlib {
    struct _Mumlib_Private : boost::noncopyable {
        bool externalIoService;
        io_service *ioService;

        Callback *callback;

        Transport *transport;

        Audio *audio;

        log4cpp::Category *logger;

        bool processIncomingTcpMessage(MessageType messageType, uint8_t *buffer, int length) {
            switch (messageType) {
                case MessageType::VERSION: {
                    MumbleProto::Version version;
                    version.ParseFromArray(buffer, length);
                    callback->version_callback(
                            version.version() >> 16,
                            version.version() >> 8 & 0xff,
                            version.version() & 0xff,
                            version.release(),
                            version.os(),
                            version.os_version());
                }
                    break;
                case MessageType::SERVERSYNC: {
                    MumbleProto::ServerSync serverSync;
                    serverSync.ParseFromArray(buffer, length);
                    callback->serversync_callback(
                            serverSync.welcome_text(),
                            serverSync.session(),
                            serverSync.max_bandwidth(),
                            serverSync.permissions()
                    );
                }
                    break;
                case MessageType::CHANNELREMOVE: {
                    MumbleProto::ChannelRemove channelRemove;
                    channelRemove.ParseFromArray(buffer, length);
                    callback->channelremove_callback(channelRemove.channel_id());
                }
                    break;
                case MessageType::CHANNELSTATE: {
                    MumbleProto::ChannelState channelState;
                    channelState.ParseFromArray(buffer, length);

                    int32_t channel_id = channelState.has_channel_id() ? channelState.channel_id() : -1;
                    int32_t parent = channelState.has_parent() ? channelState.parent() : -1;


                    bool temporary = channelState.has_temporary() ? channelState.temporary()
                                                                  : false; //todo make sure it's correct to assume it's false
                    int position = channelState.has_position() ? channelState.position() : 0;

                    vector<uint32_t> links;
                    std::copy(channelState.links().begin(), channelState.links().end(), links.begin());

                    vector<uint32_t> links_add;
                    std::copy(channelState.links_add().begin(), channelState.links_add().end(), links_add.begin());

                    vector<uint32_t> links_remove;
                    std::copy(channelState.links_remove().begin(), channelState.links_remove().end(),
                              links_remove.begin());

                    callback->channelstate_callback(
                            channelState.name(),
                            channel_id,
                            parent,
                            channelState.description(),
                            links,
                            links_add,
                            links_remove,
                            temporary,
                            position
                    );
                }
                    break;
                case MessageType::USERREMOVE: {
                    MumbleProto::UserRemove user_remove;
                    user_remove.ParseFromArray(buffer, length);

                    int32_t actor = user_remove.has_actor() ? user_remove.actor() : -1;
                    bool ban = user_remove.has_ban() ? user_remove.ban()
                                                     : false; //todo make sure it's correct to assume it's false

                    callback->userremove_callback(
                            user_remove.session(),
                            actor,
                            user_remove.reason(),
                            ban
                    );
                }
                    break;
                case MessageType::USERSTATE: // 9
//                    return MessageType::private_process_userstate(context, message, message_size);

                    break;
                case MessageType::BANLIST: // 10
//                    return MessageType::private_process_banlist(context, message, message_size);

                    break;
                case MessageType::TEXTMESSAGE: // 11
//                    return MessageType::private_process_textmessage(context, message, message_size);

                    break;
                case MessageType::PERMISSIONDENIED: // 12
//                    return MessageType::private_process_permissiondenied(context, message, message_size);

                    break;
                case MessageType::ACL: // 13
//                    return MessageType::private_process_acl(context, message, message_size);

                    break;
                case MessageType::QUERYUSERS: // 14
//                    return MessageType::private_process_queryusers(context, message, message_size);

                    break;
                case MessageType::CONTEXTACTIONMODIFY: // 16
//                    return MessageType::private_process_contextactionmodify(context, message, message_size);

                    break;
                case MessageType::CONTEXTACTION: // 17
//                    return MessageType::private_process_contextaction(context, message, message_size);

                    break;
                case MessageType::USERLIST: // 18
//                    return MessageType::private_process_userlist(context, message, message_size);

                    break;
                case MessageType::PERMISSIONQUERY: // 20
//                    return MessageType::private_process_permission_query(context, message, message_size);

                    break;
                case MessageType::CODECVERSION: // 21
//                    return MessageType::private_process_codecversion(context, message, message_size);

                    break;
                case MessageType::USERSTATS: // 22
//                    return MessageType::private_process_userstats(context, message, message_size);

                    break;
                case MessageType::REQUESTBLOB: // 23
//                    return MessageType::private_process_requestblob(context, message, message_size);

                    break;
                case MessageType::SERVERCONFIG: // 24
//                    return MessageType::private_process_serverconfig(context, message, message_size);

                    break;
                case MessageType::SUGGESTCONFIG: // 25
//                    return MessageType::private_process_suggestconfig(context, message, message_size);
                    break;
                default:
                    throw MumlibException("unknown message type: " + to_string(static_cast<int>(messageType)));
            }
            return true;
        }

        bool processAudioPacket(AudioPacketType type, uint8_t *buffer, int length) {
            logger->info("Got %d B of encoded audio data.", length);
            int16_t pcmData[5000];
            audio->decodeAudioPacket(type, buffer, length, pcmData, 5000);
        }

    };


    ConnectionState Mumlib::getConnectionState() {
        return impl->transport->getConnectionState();
    }
}

mumlib::Mumlib::Mumlib() : impl(new _Mumlib_Private) {
    impl->logger = &(log4cpp::Category::getInstance("Mumlib.Mumlib"));
    impl->externalIoService = false;
    impl->ioService = new io_service();
    impl->audio = new Audio();
    impl->transport = new Transport(
            *(impl->ioService),
            boost::bind(&_Mumlib_Private::processIncomingTcpMessage, impl, _1, _2, _3),
            boost::bind(&_Mumlib_Private::processAudioPacket, impl, _1, _2, _3)
    );
}

mumlib::Mumlib::Mumlib(io_service &ioService) : impl(new _Mumlib_Private) {
    //todo do this constructor
    throw mumlib::MumlibException("not implented yet");
}

mumlib::Mumlib::~Mumlib() {

    if (not impl->externalIoService) {
        delete impl->ioService;
    }

    delete impl;
}

void mumlib::Mumlib::setCallback(Callback &callback) {
    impl->callback = &callback;
}

void mumlib::Mumlib::connect(string host, int port, string user, string password) {
    impl->transport->connect(host, port, user, password);
}

void mumlib::Mumlib::disconnect() {
    impl->transport->disconnect();
}

void mumlib::Mumlib::run() {
    if (impl->externalIoService) {
        throw MumlibException("can't call run() when using external io_service");
    }

    impl->ioService->run();
}

void mumlib::Mumlib::sendAudioData(int16_t *pcmData, int pcmLength) {
    uint8_t encodedData[5000];
    int length = impl->audio->encodeAudioPacket(0, pcmData, pcmLength, encodedData, 5000);
    impl->transport->sendEncodedAudioPacket(encodedData, length);
}