#pragma once

#include "Transport.hpp"

#include <opus.h>

#include <chrono>

namespace mumlib {

    constexpr int SAMPLE_RATE = 48000;

    class MumlibException;

    class AudioException : public MumlibException {
    public:
        AudioException(string message) : MumlibException(message) { }
    };

    class Audio : boost::noncopyable {
    public:
        Audio();

        ~Audio();


        int decodeAudioPacket(AudioPacketType type, uint8_t *inputBuffer, int inputLength, int16_t *pcmBuffer,
                              int pcmBufferSize);

        int encodeAudioPacket(
                int target,
                int16_t *inputPcmBuffer,
                int inputLength,
                uint8_t *outputBuffer,
                int outputBufferSize = MAX_UDP_LENGTH);

        void resetEncoder();

    private:
        log4cpp::Category &logger;

        OpusDecoder *opusDecoder;
        OpusEncoder *opusEncoder;

        int64_t outgoingSequenceNumber;

        std::chrono::time_point<std::chrono::system_clock> lastEncodedAudioPacketTimestamp;
    };
}