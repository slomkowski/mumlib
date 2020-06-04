#pragma once

#include "Transport.hpp"

#include <opus/opus.h>

#include <speex/speex_jitter.h>

#include <chrono>
#include <map>

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
        explicit Audio(int sampleRate=DEFAULT_OPUS_SAMPLE_RATE,
                       int bitrate=DEFAULT_OPUS_ENCODER_BITRATE,
                       int channels=DEFAULT_OPUS_NUM_CHANNELS);

        virtual ~Audio();

        IncomingAudioPacket decodeIncomingAudioPacket(uint8_t *inputBuffer, int inputBufferLength);

        void addFrameToBuffer(uint8_t *inputBuffer, int inputLength, int sequence);

        // todo: mix audio
        void mixAudio(uint8_t *dest, uint8_t *src, int bufferOffset, int inputLength);

        void resizeBuffer();

        std::pair<int, bool> decodeOpusPayload(int sessionId,
                                               int16_t *pcmBuffer,
                                               int pcmBufferSize);
        
        std::pair<int, bool> decodeOpusPayload(uint8_t *inputBuffer,
                                               int inputLength,
                                               int sessionId,
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

        void resetJitterBuffer();

    private:
        log4cpp::Category &logger;

        std::map<int, OpusDecoder *> opusDecoders;
        OpusEncoder *opusEncoder;
        JitterBuffer *jbBuffer;

        int64_t outgoingSequenceNumber;

        unsigned int iSampleRate;
        unsigned int iChannels;
        unsigned int iFrameSize;
        unsigned int iAudioBufferSize;

        float *fFadeIn;
        float *fFadeOut;

        std::chrono::time_point<std::chrono::system_clock> lastEncodedAudioPacketTimestamp;
    };
}
