#include "mumlib/CryptState.hpp"
#include "mumlib/VarInt.hpp"
#include "mumlib/enums.hpp"
#include "mumlib/Transport.hpp"
#include "mumlib/Audio.hpp"

#include "mumlib.hpp"

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <log4cpp/Category.hh>

#include <Mumble.pb.h>

using namespace std;
using namespace boost::asio;

using namespace mumlib;

namespace mumlib {
    struct _Mumlib_Private : boost::noncopyable {
        log4cpp::Category &logger = log4cpp::Category::getInstance("mumlib.Mumlib");

        bool externalIoService;
        io_service &ioService;

        Callback &callback;

        Transport transport;

        Audio audio;

        int sessionId = 0;
        int channelId = 0;

        _Mumlib_Private(Callback &callback)
                : _Mumlib_Private(callback, *(new io_service())) {
            externalIoService = false;
        }

        _Mumlib_Private(Callback &callback, io_service &ioService)
                : callback(callback),
                  ioService(ioService),
                  externalIoService(true),
                  transport(ioService, boost::bind(&_Mumlib_Private::processIncomingTcpMessage, this, _1, _2, _3),
                            boost::bind(&_Mumlib_Private::processAudioPacket, this, _1, _2, _3)) { }

        virtual ~_Mumlib_Private() {
            if (not externalIoService) {
                delete &ioService;
            }
        }

        bool processAudioPacket(AudioPacketType type, uint8_t *buffer, int length) {
            logger.info("Got %d B of encoded audio data.", length);
            try {
                auto incomingAudioPacket = audio.decodeIncomingAudioPacket(buffer, length);

                if (type == AudioPacketType::OPUS) {
                    int16_t pcmData[5000];
                    auto status = audio.decodeOpusPayload(incomingAudioPacket.audioPayload,
                                                          incomingAudioPacket.audioPayloadLength,
                                                          pcmData,
                                                          5000);

                    callback.audio(incomingAudioPacket.target,
                                   incomingAudioPacket.sessionId,
                                   incomingAudioPacket.sequenceNumber,
                                   pcmData,
                                   status.first);
                } else {
                    logger.warn("Incoming audio packet doesn't contain Opus data, calling unsupportedAudio callback.");
                    callback.unsupportedAudio(incomingAudioPacket.target,
                                              incomingAudioPacket.sessionId,
                                              incomingAudioPacket.sequenceNumber,
                                              incomingAudioPacket.audioPayload,
                                              incomingAudioPacket.audioPayloadLength);
                }

            } catch (mumlib::AudioException &exp) {
                logger.error("Audio decode error: %s.", exp.what());
            }

            return true;
        }

    private:

        bool processIncomingTcpMessage(MessageType messageType, uint8_t *buffer, int length) {
            switch (messageType) {
                case MessageType::VERSION: {
                    MumbleProto::Version version;
                    version.ParseFromArray(buffer, length);
                    callback.version(
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

                    sessionId = serverSync.session();

                    callback.serverSync(
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
                    callback.channelRemove(channelRemove.channel_id());
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

                    this->channelId = channel_id;

                    callback.channelState(
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

                    callback.userRemove(
                            user_remove.session(),
                            actor,
                            user_remove.reason(),
                            ban
                    );
                }
                    break;
                case MessageType::USERSTATE: {
                    MumbleProto::UserState userState;
                    userState.ParseFromArray(buffer, length);

                    // There are far too many things in this structure. Culling to the ones that are probably important
                    int32_t session = userState.has_session() ? userState.session() : -1;
                    int32_t actor = userState.has_actor() ? userState.actor() : -1;
                    int32_t user_id = userState.has_user_id() ? userState.user_id() : -1;
                    int32_t channel_id = userState.has_channel_id() ? userState.channel_id() : -1;
                    int32_t mute = userState.has_mute() ? userState.mute() : -1;
                    int32_t deaf = userState.has_deaf() ? userState.deaf() : -1;
                    int32_t suppress = userState.has_suppress() ? userState.suppress() : -1;
                    int32_t self_mute = userState.has_self_mute() ? userState.self_mute() : -1;
                    int32_t self_deaf = userState.has_self_deaf() ? userState.self_deaf() : -1;
                    int32_t priority_speaker = userState.has_priority_speaker() ? userState.priority_speaker() : -1;
                    int32_t recording = userState.has_recording() ? userState.recording() : -1;

                    callback.userState(session,
                                       actor,
                                       userState.name(),
                                       user_id,
                                       channel_id,
                                       mute,
                                       deaf,
                                       suppress,
                                       self_mute,
                                       self_deaf,
                                       userState.comment(),
                                       priority_speaker,
                                       recording);
                }
                    break;
                case MessageType::BANLIST: {
                    MumbleProto::BanList ban_list;
                    ban_list.ParseFromArray(buffer, length);
                    for (int i = 0; i < ban_list.bans_size(); i++) {
                        auto ban = ban_list.bans(i);

                        const uint8_t *ip_data = reinterpret_cast<const uint8_t *>(ban.address().c_str());
                        uint32_t ip_data_size = ban.address().size();
                        int32_t duration = ban.has_duration() ? ban.duration() : -1;

                        callback.banList(
                                ip_data,
                                ip_data_size,
                                ban.mask(),
                                ban.name(),
                                ban.hash(),
                                ban.reason(),
                                ban.start(),
                                duration);
                    }
                }
                    break;
                case MessageType::TEXTMESSAGE: {
                    MumbleProto::TextMessage text_message;
                    text_message.ParseFromArray(buffer, length);

                    int32_t actor = text_message.has_actor() ? text_message.actor() : -1;

                    vector<uint32_t> sessions;
                    for (int i = 0; i < text_message.session_size(); ++i) {
                        sessions.push_back(text_message.session(i));
                    }

                    vector<uint32_t> channel_ids;
                    for (int i = 0; i < text_message.channel_id_size(); ++i) {
                        channel_ids.push_back(text_message.channel_id(i));
                    }

                    vector<uint32_t> tree_ids;
                    for (int i = 0; i < text_message.tree_id_size(); ++i) {
                        tree_ids.push_back(text_message.tree_id(i));
                    }

                    callback.textMessage(actor, sessions, channel_ids, tree_ids, text_message.message());
                }
                    break;
                case MessageType::PERMISSIONDENIED: // 12
                    logger.warn("PermissionDenied Message: support not implemented yet");
                    break;
                case MessageType::ACL: // 13
                    logger.warn("ACL Message: support not implemented yet.");
                    break;
                case MessageType::QUERYUSERS: // 14
                    logger.warn("QueryUsers Message: support not implemented yet");
                    break;
                case MessageType::CONTEXTACTIONMODIFY: // 16
                    logger.warn("ContextActionModify Message: support not implemented yet");
                    break;
                case MessageType::CONTEXTACTION: // 17
                    logger.warn("ContextAction Message: support not implemented yet");
                    break;
                case MessageType::USERLIST: // 18
                    logger.warn("UserList Message: support not implemented yet");
                    break;
                case MessageType::VOICETARGET:
                    logger.warn("VoiceTarget Message: I don't think the server ever sends this structure.");
                    break;
                case MessageType::PERMISSIONQUERY: {
                    MumbleProto::PermissionQuery permissionQuery;
                    permissionQuery.ParseFromArray(buffer, length);

                    int32_t channel_id = permissionQuery.has_channel_id() ? permissionQuery.channel_id() : -1;
                    uint32_t permissions = permissionQuery.has_permissions() ? permissionQuery.permissions() : 0;
                    uint32_t flush = permissionQuery.has_flush() ? permissionQuery.flush() : -1;

                    callback.permissionQuery(channel_id, permissions, flush);
                }
                    break;
                case MessageType::CODECVERSION: {
                    MumbleProto::CodecVersion codecVersion;
                    codecVersion.ParseFromArray(buffer, length);

                    int32_t alpha = codecVersion.alpha();
                    int32_t beta = codecVersion.beta();
                    uint32_t prefer_alpha = codecVersion.prefer_alpha();
                    int32_t opus = codecVersion.has_opus() ? codecVersion.opus() : 0;

                    callback.codecVersion(alpha, beta, prefer_alpha, opus);
                }
                    break;
                case MessageType::USERSTATS:
                    logger.warn("UserStats Message: support not implemented yet");
                    break;
                case MessageType::REQUESTBLOB: // 23
                    logger.warn("RequestBlob Message: I don't think this is sent by the server.");
                    break;
                case MessageType::SERVERCONFIG: {
                    MumbleProto::ServerConfig serverConfig;
                    serverConfig.ParseFromArray(buffer, length);

                    uint32_t max_bandwidth = serverConfig.has_max_bandwidth() ? serverConfig.max_bandwidth() : 0;
                    uint32_t allow_html = serverConfig.has_allow_html() ? serverConfig.allow_html() : 0;
                    uint32_t message_length = serverConfig.has_message_length() ? serverConfig.message_length() : 0;
                    uint32_t image_message_length = serverConfig.has_image_message_length()
                                                    ? serverConfig.image_message_length() : 0;

                    callback.serverConfig(max_bandwidth, serverConfig.welcome_text(), allow_html, message_length,
                                          image_message_length);
                }
                    break;
                case MessageType::SUGGESTCONFIG: // 25
                    logger.warn("SuggestConfig Message: support not implemented yet");
                    break;
                default:
                    throw MumlibException("unknown message type: " + to_string(static_cast<int>(messageType)));
            }
            return true;
        }


    };

    Mumlib::Mumlib(Callback &callback)
            : impl(new _Mumlib_Private(callback)) {
    }

    Mumlib::Mumlib(Callback &callback, io_service &ioService)
            : impl(new _Mumlib_Private(callback, ioService)) { }

    Mumlib::~Mumlib() {
        disconnect();

        delete impl;
    }

    ConnectionState Mumlib::getConnectionState() {
        return impl->transport.getConnectionState();
    }

    void Mumlib::connect(string host, int port, string user, string password) {
        impl->transport.connect(host, port, user, password);
    }

    void Mumlib::disconnect() {
        if (not impl->externalIoService) {
            impl->ioService.reset();
        }
        if (impl->transport.getConnectionState() != ConnectionState::NOT_CONNECTED) {
            impl->transport.disconnect();
        }
    }

    void Mumlib::run() {
        if (impl->externalIoService) {
            throw MumlibException("can't call run() when using external io_service");
        }

        impl->ioService.run();
    }

    void Mumlib::sendAudioData(int16_t *pcmData, int pcmLength) {
        uint8_t encodedData[5000];
        int length = impl->audio.encodeAudioPacket(0, pcmData, pcmLength, encodedData, 5000);
        impl->transport.sendEncodedAudioPacket(encodedData, length);
    }

    void Mumlib::sendTextMessage(string message) {
        MumbleProto::TextMessage textMessage;
        textMessage.set_actor(impl->sessionId);
        textMessage.add_channel_id(impl->channelId);
        textMessage.set_message(message);
        impl->transport.sendControlMessage(MessageType::TEXTMESSAGE, textMessage);
    }

    void Mumlib::joinChannel(int channel_id) {
        MumbleProto::UserState userState;
        userState.set_channel_id(channel_id);
        impl->transport.sendControlMessage(MessageType::USERSTATE, userState);
    }
}
