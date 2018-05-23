#pragma once

#include "mumlib/Callback.hpp"

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>

#include <string>
#include <mumlib/enums.hpp>

namespace mumlib {

    constexpr int DEFAULT_OPUS_ENCODER_BITRATE = 16000;
    constexpr int DEFAULT_OPUS_SAMPLE_RATE = 48000;
    constexpr int DEFAULT_OPUS_NUM_CHANNELS = 1;

    using namespace std;
    using namespace boost::asio;

    class MumlibException : public runtime_error {
    public:
        MumlibException(string message) : runtime_error(message) { }
    };

    struct MumlibConfiguration {
        int opusEncoderBitrate = DEFAULT_OPUS_ENCODER_BITRATE;
        int opusSampleRate = DEFAULT_OPUS_SAMPLE_RATE;
        int opusChannels = DEFAULT_OPUS_NUM_CHANNELS;
        // additional fields will be added in the future
    };

    struct MumbleUser {
        int32_t sessionId;
        string name;
    };

    struct MumbleChannel {
        int32_t channelId;
        string name;
        string description;
    };

    struct _Mumlib_Private;


    class Mumlib : boost::noncopyable {
    public:
        explicit Mumlib(Callback &callback);

        Mumlib(Callback &callback, io_service &ioService);

        Mumlib(Callback &callback, MumlibConfiguration &configuration);

        Mumlib(Callback &callback, io_service &ioService, MumlibConfiguration &configuration);

        virtual ~Mumlib();

        void connect(string host, int port, string user, string password);

        void disconnect();

        void run();

        ConnectionState getConnectionState();

        int getChannelId();

        vector<MumbleUser> getListAllUser();

        vector<MumbleChannel> getListAllChannel();

        void sendAudioData(int16_t *pcmData, int pcmLength);

        void sendAudioDataTarget(int targetId, int16_t *pcmData, int pcmLength);

        void sendTextMessage(std::string message);

        void joinChannel(int channelId);

        void joinChannel(std::string channelName);

        void sendVoiceTarget(int targetId, mumlib::VoiceTargetType type, int sessionId);

        void sendVoiceTarget(int targetId, mumlib::VoiceTargetType type, std::string name, int &error);

        void sendUserState(mumlib::UserState state, bool val);

        void sendUserState(mumlib::UserState state, std::string value);
        
    private:
        _Mumlib_Private *impl;

        int getChannelIdBy(std::string channelName);

        int getUserIdBy(std::string userName);

        bool isSessionIdValid(int sessionId);

        bool isChannelIdValid(int channelId);
    };
}
