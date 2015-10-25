#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace mumlib {

    using namespace std;

    class Callback {
    public:
        virtual void version_callback(
                uint16_t major,
                uint8_t minor,
                uint8_t patch,
                string release,
                string os,
                string os_version) { };

        virtual void audio_callback(
                uint8_t *pcm_data,
                uint32_t pcm_data_size) { };

        virtual void unsupported_audio_callback(
                uint8_t *encoded_audio_data,
                uint32_t encoded_audio_data_size) { };

        virtual void serversync_callback(
                string welcome_text,
                int32_t session,
                int32_t max_bandwidth,
                int64_t permissions) { };

        virtual void channelremove_callback(uint32_t channel_id) { };

        virtual void channelstate_callback(
                string name,
                int32_t channel_id,
                int32_t parent,
                string description,
                vector<uint32_t> links,
                vector<uint32_t> inks_add,
                vector<uint32_t> links_remove,
                bool temporary,
                int32_t position) { };

        virtual void userremove_callback(
                uint32_t session,
                int32_t actor,
                string reason,
                bool ban) { };

        virtual void userstate_callback(
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
                int32_t recording) { };

        virtual void banlist_callback(
                uint8_t *ip_data,
                uint32_t ip_data_size,
                uint32_t mask,
                string name,
                string hash,
                string reason,
                string start,
                int32_t duration) { };

        virtual void textmessage_callback(
                uint32_t actor,
                uint32_t n_session,
                uint32_t *session,
                uint32_t n_channel_id,
                uint32_t *channel_id,
                uint32_t n_tree_id,
                uint32_t *tree_id,
                string message) { };

        virtual void permissiondenied_callback(
                int32_t permission,
                int32_t channel_id,
                int32_t session,
                string reason,
                int32_t deny_type,
                string name) { };

        virtual void acl_callback() { };

        virtual void queryusers_callback(
                uint32_t n_ids,
                uint32_t *ids,
                uint32_t n_names,
                string *names) { };

        virtual void cryptsetup_callback(
                uint32_t key_size,
                uint8_t *key,
                uint32_t client_nonce_size,
                uint8_t *client_nonce,
                uint32_t server_nonce_size,
                uint8_t *server_nonce) { };

        virtual void contextactionmodify_callback(
                string action,
                string text,
                uint32_t m_context,
                uint32_t operation) { };

        virtual void contextaction_callback(
                int32_t session,
                int32_t channel_id,
                string action) { };

        virtual void userlist_callback(
                uint32_t user_id,
                string name,
                string last_seen,
                int32_t last_channel) { };

        virtual void voicetarget_callback() { };

        virtual void permissionquery_callback(
                int32_t channel_id,
                uint32_t permissions,
                int32_t flush) { };

        virtual void codecversion_callback(
                int32_t alpha,
                int32_t beta,
                uint32_t prefer_alpha,
                int32_t opus) { };

        virtual void userstats_callback() { };

        virtual void requestblob_callback() { };

        virtual void serverconfig_callback(
                uint32_t max_bandwidth,
                string welcome_text,
                uint32_t allow_html,
                uint32_t message_length,
                uint32_t image_message_length) { };

        virtual void suggestconfig_callback(
                uint32_t version,
                uint32_t positional,
                uint32_t push_to_talk) { };

    };

    class _BasicCallback_Private;

    class BasicCallback : public Callback {
    public:
        BasicCallback();

        ~BasicCallback();

        virtual void version_callback(
                uint16_t major,
                uint8_t minor,
                uint8_t patch,
                string release,
                string os,
                string os_version);

        virtual void audio_callback(
                uint8_t *pcm_data,
                uint32_t pcm_data_size);

        virtual void unsupported_audio_callback(
                uint8_t *encoded_audio_data,
                uint32_t encoded_audio_data_size);

        virtual void serversync_callback(
                string welcome_text,
                int32_t session,
                int32_t max_bandwidth,
                int64_t permissions);

        virtual void channelremove_callback(uint32_t channel_id);

        virtual void channelstate_callback(
                string name,
                int32_t channel_id,
                int32_t parent,
                string description,
                vector<uint32_t> links,
                vector<uint32_t> inks_add,
                vector<uint32_t> links_remove,
                bool temporary,
                int32_t position);

        virtual void userremove_callback(
                uint32_t session,
                int32_t actor,
                string reason,
                bool ban);

        virtual void userstate_callback(
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
                int32_t recording);

        virtual void banlist_callback(
                uint8_t *ip_data,
                uint32_t ip_data_size,
                uint32_t mask,
                string name,
                string hash,
                string reason,
                string start,
                int32_t duration);

        virtual void textmessage_callback(
                uint32_t actor,
                uint32_t n_session,
                uint32_t *session,
                uint32_t n_channel_id,
                uint32_t *channel_id,
                uint32_t n_tree_id,
                uint32_t *tree_id,
                string message);

        virtual void permissiondenied_callback(
                int32_t permission,
                int32_t channel_id,
                int32_t session,
                string reason,
                int32_t deny_type,
                string name);

        virtual void acl_callback();

        virtual void queryusers_callback(
                uint32_t n_ids,
                uint32_t *ids,
                uint32_t n_names,
                string *names);

        virtual void cryptsetup_callback(
                uint32_t key_size,
                uint8_t *key,
                uint32_t client_nonce_size,
                uint8_t *client_nonce,
                uint32_t server_nonce_size,
                uint8_t *server_nonce);

        virtual void contextactionmodify_callback(
                string action,
                string text,
                uint32_t m_context,
                uint32_t operation);

        virtual void contextaction_callback(
                int32_t session,
                int32_t channel_id,
                string action);

        virtual void userlist_callback(
                uint32_t user_id,
                string name,
                string last_seen,
                int32_t last_channel);

        virtual void voicetarget_callback();

        virtual void permissionquery_callback(
                int32_t channel_id,
                uint32_t permissions,
                int32_t flush);

        virtual void codecversion_callback(
                int32_t alpha,
                int32_t beta,
                uint32_t prefer_alpha,
                int32_t opus);

        virtual void userstats_callback();

        virtual void requestblob_callback();

        virtual void serverconfig_callback(
                uint32_t max_bandwidth,
                string welcome_text,
                uint32_t allow_html,
                uint32_t message_length,
                uint32_t image_message_length);

        virtual void suggestconfig_callback(
                uint32_t version,
                uint32_t positional,
                uint32_t push_to_talk);

    private:
        _BasicCallback_Private *impl;
    };
}