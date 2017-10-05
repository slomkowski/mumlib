#include "mumlib/include/mumlib/Callback.hpp"

#include <boost/noncopyable.hpp>
#ifdef MUMLIB_USE_LOG4CPP
#include <MUMLIB_USE_LOG4CPP/Category.hh>
#endif

using namespace std;
using namespace mumlib;

namespace mumlib {
    struct _BasicCallback_Private : boost::noncopyable {
    public:
#ifdef MUMLIB_USE_LOG4CPP
        _BasicCallback_Private() :
            logger(MUMLIB_USE_LOG4CPP::Category::getInstance("mumlib.BasicCallback")) { }
        MUMLIB_USE_LOG4CPP::Category &logger;
#else
        _BasicCallback_Private() { }
#endif
    };

}

mumlib::BasicCallback::BasicCallback() {
    impl = new _BasicCallback_Private();
}

mumlib::BasicCallback::~BasicCallback() {
    delete impl;
}

void mumlib::BasicCallback::version(
        uint16_t major,
        uint8_t minor,
        uint8_t patch,
        string release,
        string os,
        string os_version) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("version: v%d.%d.%d. %s/%s/%s\n", major, minor, patch, release.c_str(), os.c_str(),
                       os_version.c_str());
#endif
}

void mumlib::BasicCallback::audio(
        int target,
        int sessionId,
        int sequenceNumber,
        int16_t *pcmData,
        uint32_t pcm_data_size) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("audio: %d bytes of raw PCM data, target: %d, session: %d, seq: %d.",
                       pcm_data_size, target, sessionId, sequenceNumber);
#endif
}

void BasicCallback::unsupportedAudio(
        int target,
        int sessionId,
        int sequenceNumber,
        uint8_t *encoded_audio_data,
        uint32_t encoded_audio_data_size) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("unsupportedAudio: received %d bytes of encoded data, target: %d, session: %d, seq: %d.",
                       encoded_audio_data_size, target, sessionId, sequenceNumber);
#endif
}

void BasicCallback::serverSync(string welcome_text, int32_t session, int32_t max_bandwidth, int64_t permissions) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("serverSync: text: %s, session: %d, max bandwidth: %d, permissions: %d", welcome_text.c_str(),
                       session,
                       max_bandwidth, permissions);
#endif
}

void BasicCallback::channelRemove(uint32_t channel_id) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("channelRemove: %d", channel_id);
#endif
}

void BasicCallback::channelState(string name, int32_t channel_id, int32_t parent, string description,
                                 vector<uint32_t> links, vector<uint32_t> inks_add, vector<uint32_t> links_remove,
                                 bool temporary, int32_t position) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("channelState: %d: %s, %s", channel_id, name.c_str(), description.c_str());
#endif
}

void BasicCallback::userRemove(uint32_t session, int32_t actor, string reason, bool ban) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("userRemove: session: %d, actor: %d, reason: %s, ban: %d.", session, actor, reason.c_str(), ban);
#endif
}

void BasicCallback::userState(int32_t session, int32_t actor, string name, int32_t user_id, int32_t channel_id,
                              int32_t mute, int32_t deaf, int32_t suppress, int32_t self_mute, int32_t self_deaf,
                              string comment, int32_t priority_speaker, int32_t recording) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("userState: %s: mute: %d, deaf: %d, suppress: %d, self mute: %d, self deaf: %d",
                       name.c_str(), mute, deaf, suppress, self_mute, self_deaf);
#endif
}

void BasicCallback::banList(const uint8_t *ip_data, uint32_t ip_data_size, uint32_t mask, string name, string hash,
                            string reason, string start, int32_t duration) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("banList: %s, hash: %s, reason: %s", name.c_str(), hash.c_str(), reason.c_str());
#endif
}

void BasicCallback::textMessage(
        uint32_t actor,
        std::vector<uint32_t> session,
        std::vector<uint32_t> channel_id,
        std::vector<uint32_t> tree_id,
        string message) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("textMessage: %d: %s", actor, message.c_str());
#endif
}

void BasicCallback::permissionDenied(int32_t permission, int32_t channel_id, int32_t session, string reason,
                                     int32_t deny_type, string name) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("permissionDenied: %s %s", name.c_str(), reason.c_str());
#endif
}

void BasicCallback::queryUsers(uint32_t n_ids, uint32_t *ids, uint32_t n_names, string *names) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("queryUsers: %d users", n_names); //todo make it more high-level
#endif
}

void BasicCallback::contextActionModify(string action, string text, uint32_t m_context, uint32_t operation) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("contextActionModify: ");
#endif
}

void BasicCallback::contextAction(int32_t session, int32_t channel_id, string action) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("contextAction.");
#endif
}

void BasicCallback::userList(uint32_t user_id, string name, string last_seen, int32_t last_channel) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("userList.");
#endif
}

void BasicCallback::permissionQuery(int32_t channel_id, uint32_t permissions, int32_t flush) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("permissionQuery.");
#endif
}

void BasicCallback::codecVersion(int32_t alpha, int32_t beta, uint32_t prefer_alpha, int32_t opus) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("codecVersion.");
#endif
}

void BasicCallback::serverConfig(uint32_t max_bandwidth, string welcome_text, uint32_t allow_html,
                                 uint32_t message_length, uint32_t image_message_length) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("serverConfig: %s", welcome_text.c_str());
#endif
}

void BasicCallback::suggestConfig(uint32_t version, uint32_t positional, uint32_t push_to_talk) {
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("suggestConfig.");
#endif
}

void BasicCallback::disconnected()
{
#ifdef MUMLIB_USE_LOG4CPP
    impl->logger.debug("Disconnected from server.");
#endif
}
