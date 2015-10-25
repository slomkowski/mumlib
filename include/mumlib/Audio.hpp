#pragma once

#include "Transport.hpp"

#include <opus.h>

namespace mumlib {

    constexpr int SAMPLE_RATE = 48000;

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

    private:
        log4cpp::Category &logger;

        OpusDecoder *opusDecoder;
        OpusEncoder *opusEncoder;

        int64_t outgoingSequenceNumber;
    };
}