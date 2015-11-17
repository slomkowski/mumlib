#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace mumlib {

    using namespace std;

    class Callback {
    public:
        virtual void version(
                uint16_t major,
                uint8_t minor,
                uint8_t patch,
                string release,
                string os,
                string os_version) { };

        virtual void audio(
                int target,
                int sessionId,
                int sequenceNumber,
                int16_t *pcm_data,
                uint32_t pcm_data_size) { };

        virtual void unsupportedAudio(
                int target,
                int sessionId,
                int sequenceNumber,
                uint8_t *encoded_audio_data,
                uint32_t encoded_audio_data_size) { };

        virtual void serverSync(
                string welcome_text,
                int32_t session,
                int32_t max_bandwidth,
                int64_t permissions) { };

        virtual void channelRemove(uint32_t channel_id) { };

        virtual void channelState(
                string name,
                int32_t channel_id,
                int32_t parent,
                string description,
                vector<uint32_t> links,
                vector<uint32_t> inks_add,
                vector<uint32_t> links_remove,
                bool temporary,
                int32_t position) { };

        virtual void userRemove(
                uint32_t session,
                int32_t actor,
                string reason,
                bool ban) { };

        virtual void userState(
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

        virtual void banList(
                const uint8_t *ip_data,
                uint32_t ip_data_size,
                uint32_t mask,
                string name,
                string hash,
                string reason,
                string start,
                int32_t duration) { };

        virtual void textMessage(
                uint32_t actor,
                std::vector<uint32_t> session,
                std::vector<uint32_t> channel_id,
                std::vector<uint32_t> tree_id,
                string message) { };

        virtual void permissionDenied(
                int32_t permission,
                int32_t channel_id,
                int32_t session,
                string reason,
                int32_t deny_type,
                string name) { };

        virtual void queryUsers(
                uint32_t n_ids,
                uint32_t *ids,
                uint32_t n_names,
                string *names) { };

        virtual void contextActionModify(
                string action,
                string text,
                uint32_t m_context,
                uint32_t operation) { };

        virtual void contextAction(
                int32_t session,
                int32_t channel_id,
                string action) { };

        virtual void userList(
                uint32_t user_id,
                string name,
                string last_seen,
                int32_t last_channel) { };

        virtual void permissionQuery(
                int32_t channel_id,
                uint32_t permissions,
                int32_t flush) { };

        virtual void codecVersion(
                int32_t alpha,
                int32_t beta,
                uint32_t prefer_alpha,
                int32_t opus) { };

        virtual void serverConfig(
                uint32_t max_bandwidth,
                string welcome_text,
                uint32_t allow_html,
                uint32_t message_length,
                uint32_t image_message_length) { };

        virtual void suggestConfig(
                uint32_t version,
                uint32_t positional,
                uint32_t push_to_talk) { };

    };

    class _BasicCallback_Private;

    class BasicCallback : public Callback {
    public:
        BasicCallback();

        ~BasicCallback();

        virtual void version(
                uint16_t major,
                uint8_t minor,
                uint8_t patch,
                string release,
                string os,
                string os_version) override;

        virtual void audio(
                int target,
                int sessionId,
                int sequenceNumber,
                int16_t *pcm_data,
                uint32_t pcm_data_size) override;

        virtual void unsupportedAudio(
                int target,
                int sessionId,
                int sequenceNumber,
                uint8_t *encoded_audio_data,
                uint32_t encoded_audio_data_size) override;

        virtual void serverSync(
                string welcome_text,
                int32_t session,
                int32_t max_bandwidth,
                int64_t permissions);

        virtual void channelRemove(uint32_t channel_id) override;

        virtual void channelState(
                string name,
                int32_t channel_id,
                int32_t parent,
                string description,
                vector<uint32_t> links,
                vector<uint32_t> inks_add,
                vector<uint32_t> links_remove,
                bool temporary,
                int32_t position) override;

        virtual void userRemove(
                uint32_t session,
                int32_t actor,
                string reason,
                bool ban) override;

        virtual void userState(
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
                int32_t recording) override;

        virtual void banList(
                const uint8_t *ip_data,
                uint32_t ip_data_size,
                uint32_t mask,
                string name,
                string hash,
                string reason,
                string start,
                int32_t duration) override;

        virtual void textMessage(
                uint32_t actor,
                std::vector<uint32_t> session,
                std::vector<uint32_t> channel_id,
                std::vector<uint32_t> tree_id,
                string message) override;

        virtual void permissionDenied(
                int32_t permission,
                int32_t channel_id,
                int32_t session,
                string reason,
                int32_t deny_type,
                string name) override;

        virtual void queryUsers(
                uint32_t n_ids,
                uint32_t *ids,
                uint32_t n_names,
                string *names) override;

        virtual void contextActionModify(
                string action,
                string text,
                uint32_t m_context,
                uint32_t operation) override;

        virtual void contextAction(
                int32_t session,
                int32_t channel_id,
                string action) override;

        virtual void userList(
                uint32_t user_id,
                string name,
                string last_seen,
                int32_t last_channel) override;

        virtual void permissionQuery(
                int32_t channel_id,
                uint32_t permissions,
                int32_t flush) override;

        virtual void codecVersion(
                int32_t alpha,
                int32_t beta,
                uint32_t prefer_alpha,
                int32_t opus) override;

        virtual void serverConfig(
                uint32_t max_bandwidth,
                string welcome_text,
                uint32_t allow_html,
                uint32_t message_length,
                uint32_t image_message_length) override;

        virtual void suggestConfig(
                uint32_t version,
                uint32_t positional,
                uint32_t push_to_talk) override;

    private:
        _BasicCallback_Private *impl;
    };
}