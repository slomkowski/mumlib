#pragma once

#include <mumlib/Transport.hpp>

#include <opus/opus.h>

#include <chrono>

namespace mumlib {

    constexpr int SAMPLE_RATE = 48000;
#ifdef MUMLIB_USE_EXCEPTIONS
    class MumlibException;

    class AudioException : public MumlibException {
    public:
        AudioException(string message) : MumlibException(message) { }
    };
#endif

    struct IncomingAudioPacket {
        AudioPacketType type;
        int target;
        int64_t sessionId;
        int64_t sequenceNumber;
        uint8_t *audioPayload;
        int audioPayloadLength;
    };

    class Audio : boost::noncopyable {
    public:
        Audio(int opusEncoderBitrate = DEFAULT_OPUS_ENCODER_BITRATE);

        virtual ~Audio();

        IncomingAudioPacket decodeIncomingAudioPacket(uint8_t *inputBuffer, int inputBufferLength);

        std::pair<int, bool> decodeOpusPayload(uint8_t *inputBuffer,
                                               int inputLength,
                                               int16_t *pcmBuffer,
                                               int pcmBufferSize);

        int encodeAudioPacket(
                int target,
                int16_t *inputPcmBuffer,
                int inputLength,
                uint8_t *outputBuffer,
                int outputBufferSize = MAX_UDP_LENGTH);

        void setOpusEncoderBitrate(int bitrate);

        int getOpusEncoderBitrate();

        void resetEncoder();

    private:
#ifdef MUMLIB_USE_LOG4CPP
        MUMLIB_USE_LOG4CPP::Category &logger;
#endif

        OpusDecoder *opusDecoder;
        OpusEncoder *opusEncoder;

        int64_t outgoingSequenceNumber;

        std::chrono::time_point<std::chrono::system_clock> lastEncodedAudioPacketTimestamp;
    };
}
