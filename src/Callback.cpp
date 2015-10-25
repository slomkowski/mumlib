#include "mumlib/Callback.hpp"

#include <boost/core/noncopyable.hpp>
#include <log4cpp/Category.hh>

using namespace std;
using namespace mumlib;

namespace mumlib {
    struct _BasicCallback_Private : boost::noncopyable {
    public:
        _BasicCallback_Private() : logger(log4cpp::Category::getInstance("BasicCallback")) { }

        log4cpp::Category &logger;
    };
}

mumlib::BasicCallback::BasicCallback() {
    impl = new _BasicCallback_Private();
}

mumlib::BasicCallback::~BasicCallback() {
    delete impl;
}

void mumlib::BasicCallback::version_callback(
        uint16_t major,
        uint8_t minor,
        uint8_t patch,
        string release,
        string os,
        string os_version) {
    impl->logger.debug("Version Callback: v%d.%d.%d. %s/%s/%s\n", major, minor, patch, release.c_str(), os.c_str(),
                       os_version.c_str());
}

void mumlib::BasicCallback::audio_callback(
        uint8_t *pcm_data,
        uint32_t pcm_data_size) {
    impl->logger.debug("Received %d bytes of raw PCM data.", pcm_data_size);
}

void mumlib::BasicCallback::unsupported_audio_callback(
        uint8_t *encoded_audio_data,
        uint32_t encoded_audio_data_size) {
    impl->logger.debug("Received %d bytes of encoded audio data.", encoded_audio_data_size);
}

void mumlib::BasicCallback::serversync_callback(
        string welcome_text,
        int32_t session,
        int32_t max_bandwidth,
        int64_t permissions) {
    impl->logger.debug("Text: %s, session: %d, max bandwidth: %d, permissions: %d", welcome_text.c_str(), session,
                       max_bandwidth, permissions);
}

void mumlib::BasicCallback::channelremove_callback(uint32_t channel_id) { }

void mumlib::BasicCallback::channelstate_callback(
        string name,
        int32_t channel_id,
        int32_t parent,
        string description,
        vector<uint32_t> links,
        vector<uint32_t> inks_add,
        vector<uint32_t> links_remove,
        bool temporary,
        int32_t position) {
    impl->logger.debug("Obtained channel state %d: %s, %s", channel_id, name.c_str(), description.c_str());
}

void mumlib::BasicCallback::userremove_callback(
        uint32_t session,
        int32_t actor,
        string reason,
        bool ban) { }

void mumlib::BasicCallback::userstate_callback(
        int32_t session,
        int32_t actor,
        string name,
        int32_t user_id,
        int32_t channel_id,
        int32_t mute,
        int32_t deaf,
        int32_t suppress,
        int32_t self_mute,
        int32_t self_deaf,
        string comment,
        int32_t priority_speaker,
        int32_t recording) { }

void mumlib::BasicCallback::banlist_callback(
        uint8_t *ip_data,
        uint32_t ip_data_size,
        uint32_t mask,
        string name,
        string hash,
        string reason,
        string start,
        int32_t duration) { }

void mumlib::BasicCallback::textmessage_callback(
        uint32_t actor,
        uint32_t n_session,
        uint32_t *session,
        uint32_t n_channel_id,
        uint32_t *channel_id,
        uint32_t n_tree_id,
        uint32_t *tree_id,
        string message) { }

void mumlib::BasicCallback::permissiondenied_callback(
        int32_t permission,
        int32_t channel_id,
        int32_t session,
        string reason,
        int32_t deny_type,
        string name) { }

void mumlib::BasicCallback::acl_callback() { }

void mumlib::BasicCallback::queryusers_callback(
        uint32_t n_ids,
        uint32_t *ids,
        uint32_t n_names,
        string *names) { }

void mumlib::BasicCallback::cryptsetup_callback(
        uint32_t key_size,
        uint8_t *key,
        uint32_t client_nonce_size,
        uint8_t *client_nonce,
        uint32_t server_nonce_size,
        uint8_t *server_nonce) { }

void mumlib::BasicCallback::contextactionmodify_callback(
        string action,
        string text,
        uint32_t m_context,
        uint32_t operation) { }

void mumlib::BasicCallback::contextaction_callback(
        int32_t session,
        int32_t channel_id,
        string action) { }

void mumlib::BasicCallback::userlist_callback(
        uint32_t user_id,
        string name,
        string last_seen,
        int32_t last_channel) { }

void mumlib::BasicCallback::voicetarget_callback() { }

void mumlib::BasicCallback::permissionquery_callback(
        int32_t channel_id,
        uint32_t permissions,
        int32_t flush) { }

void mumlib::BasicCallback::codecversion_callback(
        int32_t alpha,
        int32_t beta,
        uint32_t prefer_alpha,
        int32_t opus) { }

void mumlib::BasicCallback::userstats_callback() { }

void mumlib::BasicCallback::requestblob_callback() { }

void mumlib::BasicCallback::serverconfig_callback(
        uint32_t max_bandwidth,
        string welcome_text,
        uint32_t allow_html,
        uint32_t message_length,
        uint32_t image_message_length) { }

void mumlib::BasicCallback::suggestconfig_callback(
        uint32_t version,
        uint32_t positional,
        uint32_t push_to_talk) { }
