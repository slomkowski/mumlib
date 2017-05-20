#pragma once

#include "mumlib/Callback.hpp"

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>

#include <string>
#include <mumlib/enums.hpp>

namespace mumlib {

    constexpr int DEFAULT_OPUS_ENCODER_BITRATE = 16000;

    using namespace std;
    using namespace boost::asio;

    class MumlibException : public runtime_error {
    public:
        MumlibException(string message) : runtime_error(message) { }
    };

    struct MumlibConfiguration {
        int opusEncoderBitrate = DEFAULT_OPUS_ENCODER_BITRATE;
        // additional fields will be added in the future
    };

    struct _Mumlib_Private;


    class Mumlib : boost::noncopyable {
    public:
        Mumlib(Callback &callback);

        Mumlib(Callback &callback, io_service &ioService);

        Mumlib(Callback &callback, MumlibConfiguration &configuration);

        Mumlib(Callback &callback, io_service &ioService, MumlibConfiguration &configuration);

        virtual ~Mumlib();

        void connect(string host, int port, string user, string password);

        void disconnect();

        void run();

        ConnectionState getConnectionState();

        void sendAudioData(int16_t *pcmData, int pcmLength);

        void sendTextMessage(std::string message);

        void joinChannel(int channelId);

        void self_mute(int muteness);

        void self_deaf(int deafness);

    private:
        _Mumlib_Private *impl;
    };
}
