#pragma once

#include "Transport.hpp"

#include <opus/opus.h>

#include <chrono>

namespace mumlib {

    class MumlibException;

    class AudioException : public MumlibException {
    public:
        explicit AudioException(string message) : MumlibException(message) { }
    };

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
        Audio(int opusSampleRate, int opusEncoderBitrate);

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
        log4cpp::Category &logger;

        OpusDecoder *opusDecoder;
        OpusEncoder *opusEncoder;

        int64_t outgoingSequenceNumber;
        int sampleRate;

        std::chrono::time_point<std::chrono::system_clock> lastEncodedAudioPacketTimestamp;
    };
}