#include "mumlib/Audio.hpp"

#include <boost/format.hpp>

static boost::posix_time::seconds RESET_SEQUENCE_NUMBER_INTERVAL(2);

namespace {

OpusDecoder* CreateOpusDecoder(int sampleRate, int channels)
{
    int error;
    OpusDecoder* decoder = nullptr;

    decoder = opus_decoder_create(sampleRate, channels, &error);
    if (error != OPUS_OK) {
        throw mumlib::AudioException((boost::format("failed to initialize OPUS decoder: %s") % opus_strerror(error)).str());
    }

    return decoder;
}

} // anonymous namespace

mumlib::Audio::Audio(int sampleRate, int bitrate, int channels)
        : logger(log4cpp::Category::getInstance("mumlib.Audio")),
          opusEncoder(nullptr),
          outgoingSequenceNumber(0),
          iSampleRate(sampleRate),
          iChannels(channels) {

    int error, ret;
    iFrameSize = sampleRate / 100;
    iAudioBufferSize = iFrameSize;
    iAudioBufferSize *= 12;

    opusEncoder = opus_encoder_create(sampleRate, channels, OPUS_APPLICATION_VOIP, &error);
    if (error != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize OPUS encoder: %s") % opus_strerror(error)).str());
    }

    ret = opus_encoder_ctl(opusEncoder, OPUS_SET_BITRATE(bitrate));
    if (ret != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize transmission bitrate to %d B/s: %s")
                            % bitrate % opus_strerror(ret)).str());
    }
    ret = opus_encoder_ctl(opusEncoder, OPUS_SET_VBR(0));
    if (ret != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize variable bitrate: %s") 
                            % opus_strerror(ret)).str());
    }
    ret = opus_encoder_ctl(opusEncoder, OPUS_SET_VBR_CONSTRAINT(0));
    if (ret != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize variable bitrate constraint: %s") 
                            % opus_strerror(ret)).str());
    }
    ret = opus_encoder_ctl(opusEncoder, OPUS_SET_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
    if (ret != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize bandwidth narrow: %s") 
                            % opus_strerror(ret)).str());
    }
    ret = opus_encoder_ctl(opusEncoder, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
    if (ret != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize maximum bandwidth narrow: %s") 
                            % opus_strerror(ret)).str());
    }

    opus_encoder_ctl(opusEncoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));

    resetEncoder();

    jbBuffer = jitter_buffer_init(iFrameSize);
    int margin = 10 * iFrameSize;
    jitter_buffer_ctl(jbBuffer, JITTER_BUFFER_SET_MARGIN, &margin);

    fFadeIn = new float[iFrameSize];
    fFadeOut = new float[iFrameSize];

    // Sine function to represent fade in/out. Period is FRAME_SIZE.
    float mul = static_cast<float>(M_PI / 2.0 * static_cast<double>(iFrameSize));
    for(unsigned int i = 0; i < iFrameSize; i++) {
        fFadeIn[i] = fFadeOut[iFrameSize - 1 - 1] = sinf(static_cast<float>(i) * mul);
    }
}

mumlib::Audio::~Audio() {
    for (const auto decoder : opusDecoders) {
        opus_decoder_destroy(decoder.second);
    }

    if (opusEncoder) {
        opus_encoder_destroy(opusEncoder);
    }

    jitter_buffer_destroy(jbBuffer);

    delete[] fFadeIn;
    delete[] fFadeOut;
}

void mumlib::Audio::setOpusEncoderBitrate(int bitrate) {
    int error = opus_encoder_ctl(opusEncoder, OPUS_SET_BITRATE(bitrate));
    if (error != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize transmission bitrate to %d B/s: %s")
                              % bitrate % opus_strerror(error)).str());
    }
}

int mumlib::Audio::getOpusEncoderBitrate() {
    opus_int32 bitrate;
    int error = opus_encoder_ctl(opusEncoder, OPUS_GET_BITRATE(&bitrate));
    if (error != OPUS_OK) {
        throw AudioException((boost::format("failed to read Opus bitrate: %s") % opus_strerror(error)).str());
    }
    return bitrate;
}

void mumlib::Audio::addFrameToBuffer(uint8_t *inputBuffer, int inputLength, int sequence) {
    int dataPointer = 0;
    VarInt varInt(inputBuffer);
    int opusDataLength = varInt.getValue();
    dataPointer += varInt.getEncoded().size();
    bool lastPacket = (opusDataLength & 0x2000) != 0;
    opusDataLength &= 0x1fff;

    auto *packet = reinterpret_cast<const unsigned char *>(&inputBuffer[dataPointer]);
    int frame = opus_packet_get_nb_frames(packet, opusDataLength);
    int samples = frame * opus_packet_get_samples_per_frame(packet, iSampleRate);
    int channel = opus_packet_get_nb_channels(packet);

    if(not sequence) {
        resetJitterBuffer();
    }

    logger.info("Opus packet, frame: %d, samples: %d, channel: %d", frame, samples, channel);

    JitterBufferPacket jbPacket;
    jbPacket.data = reinterpret_cast<char *>(&inputBuffer[dataPointer]);
    jbPacket.len = opusDataLength;
    jbPacket.span = samples;
    jbPacket.timestamp = iFrameSize * sequence;
    jbPacket.user_data = lastPacket;
        
    jitter_buffer_put(jbBuffer, &jbPacket);
}

std::pair<int, bool> mumlib::Audio::decodeOpusPayload(int sessionId, int16_t *pcmBuffer, int pcmBufferSize) {
    int avail = 0;
    spx_uint32_t remaining = 0;
    jitter_buffer_ctl(jbBuffer, JITTER_BUFFER_GET_AVAILABLE_COUNT, &avail);
    jitter_buffer_remaining_span(jbBuffer, remaining);
    int timestamp = jitter_buffer_get_pointer_timestamp(jbBuffer);

    char data[4096];
    JitterBufferPacket jbPacket;
    jbPacket.data = data;
    jbPacket.len = 4096;

    spx_int32_t startofs = 0;
    int opusDataLength;
    int outputSize;
    spx_uint32_t lastPacket;

    if(jitter_buffer_get(jbBuffer, &jbPacket, iFrameSize, &startofs) == JITTER_BUFFER_OK) {
        opusDataLength = jbPacket.len;
        lastPacket = jbPacket.user_data;
    } else {
        jitter_buffer_update_delay(jbBuffer, &jbPacket, NULL);
    }
    OpusDecoder* &opusDecoder = opusDecoders[sessionId];
    if (!opusDecoder) {
        opusDecoder = CreateOpusDecoder(iSampleRate, iChannels);
    }
    if(opusDataLength) {
        outputSize = opus_decode(opusDecoder, 
                                    reinterpret_cast<const unsigned char *>(jbPacket.data),
                                    jbPacket.len, 
                                    pcmBuffer, 
                                    pcmBufferSize, 0);
    } else {
        outputSize = opus_decode(opusDecoder, 
                                    NULL, 0, pcmBuffer, pcmBufferSize, 0);        
    }

    if(outputSize < 0) {
        outputSize = iFrameSize;
        memset(pcmBuffer, 0, iFrameSize * sizeof(float));
    }

    if(lastPacket) {
        for(unsigned int i = 0; i < iFrameSize; i++)
            pcmBuffer[i] *= fFadeOut[i];
    }

    for (int i = outputSize / iFrameSize; i > 0; --i) {
        jitter_buffer_tick(jbBuffer);
    }
    
    logger.debug("%d B of Opus data decoded to %d PCM samples, last packet: %d.",
                 opusDataLength, outputSize, lastPacket);

    return std::make_pair(outputSize, lastPacket);
}

void mumlib::Audio::mixAudio(uint8_t *dest, uint8_t *src, int bufferOffset, int inputLength) {
    for(int i = 0; i < inputLength; i++) {
        float mix = 0;

        // Clip to [-1,1]
        if(mix > 1)
            mix = 1;
        else if(mix < -1)
            mix = -1;
        dest[i + bufferOffset] = mix;
    }
}

std::pair<int, bool>  mumlib::Audio::decodeOpusPayload(uint8_t *inputBuffer,
                                                       int inputLength,
                                                       int sessionId,
                                                       int16_t *pcmBuffer,
                                                       int pcmBufferSize) {
    int64_t opusDataLength;

    int dataPointer = 0;
    VarInt varInt(inputBuffer);
    opusDataLength = varInt.getValue();
    dataPointer += varInt.getEncoded().size();

    bool lastPacket = (opusDataLength & 0x2000) != 0;
    opusDataLength = opusDataLength & 0x1fff;

    if (inputLength < opusDataLength + dataPointer) {
        throw AudioException((boost::format("invalid Opus payload (%d B): header %d B, expected Opus data length %d B")
                              % inputLength % dataPointer % opusDataLength).str());
    }

    // Issue #3 (Users speaking simultaneously)
    // https://mf4.xiph.org/jenkins/view/opus/job/opus/ws/doc/html/group__opus__decoder.html
    // Opus is a stateful codec with overlapping blocks and as a result Opus packets are not coded independently of each other. 
    // Packets must be passed into the decoder serially and in the correct order for a correct decode. 
    // Lost packets can be replaced with loss concealment by calling the decoder with a null pointer and zero length for the missing packet.
    // A single codec state may only be accessed from a single thread at a time and any required locking must be performed by the caller. 
    // Separate streams must be decoded with separate decoder states and can be decoded in parallel unless the library was compiled with NONTHREADSAFE_PSEUDOSTACK defined.
    auto *packet = reinterpret_cast<const unsigned char *>(&inputBuffer[dataPointer]);
    int frame = opus_packet_get_nb_frames(packet, opusDataLength);
    int samples = frame * opus_packet_get_samples_per_frame(packet, iSampleRate);
    OpusDecoder* &opusDecoder = opusDecoders[sessionId];
    if (!opusDecoder) {
        opusDecoder = CreateOpusDecoder(iSampleRate, iChannels);
    }
    int outputSize = opus_decode(opusDecoder,
                                 packet,
                                 opusDataLength,
                                 pcmBuffer,
                                 pcmBufferSize,
                                 0);

    if (outputSize <= 0) {
        throw AudioException((boost::format("failed to decode %d B of OPUS data: %s") % inputLength %
                              opus_strerror(outputSize)).str());
    }

    logger.debug("%d B of Opus data decoded to %d PCM samples, last packet: %d.",
                 opusDataLength, outputSize, lastPacket);

    return std::make_pair(outputSize, lastPacket);
}

int mumlib::Audio::encodeAudioPacket(int target, int16_t *inputPcmBuffer, int inputLength, uint8_t *outputBuffer,
                                     int outputBufferSize) {

    using namespace std::chrono;

    const int lastAudioPacketSentInterval = duration_cast<milliseconds>(
            system_clock::now() - lastEncodedAudioPacketTimestamp).count();

    if (lastAudioPacketSentInterval > RESET_SEQUENCE_NUMBER_INTERVAL.total_milliseconds() + 1000) {
        logger.notice("Last audio packet was sent %d ms ago, resetting encoder.", lastAudioPacketSentInterval);
        resetEncoder();
    }

    std::vector<uint8_t> header;

    header.push_back(static_cast<unsigned char &&>(0x80 | target));

    auto sequenceNumberEnc = VarInt(outgoingSequenceNumber).getEncoded();
    header.insert(header.end(), sequenceNumberEnc.begin(), sequenceNumberEnc.end());

    uint8_t tmpOpusBuffer[1024];
    const int outputSize = opus_encode(opusEncoder,
                                       inputPcmBuffer,
                                       inputLength,
                                       tmpOpusBuffer,
                                       min(outputBufferSize, 1024)
    );

    if (outputSize <= 0) {
        throw AudioException((boost::format("failed to encode %d B of PCM data: %s") % inputLength %
                              opus_strerror(outputSize)).str());
    }

    auto outputSizeEnc = VarInt(outputSize).getEncoded();
    header.insert(header.end(), outputSizeEnc.begin(), outputSizeEnc.end());

    memcpy(outputBuffer, &header[0], header.size());
    memcpy(outputBuffer + header.size(), tmpOpusBuffer, (size_t) outputSize);

    int incrementNumber = 100 * inputLength / iSampleRate;

    outgoingSequenceNumber += incrementNumber;

    lastEncodedAudioPacketTimestamp = std::chrono::system_clock::now();

    return static_cast<int>(outputSize + header.size());
}

void mumlib::Audio::resetEncoder() {
    int status = opus_encoder_ctl(opusEncoder, OPUS_RESET_STATE, nullptr);

    if (status != OPUS_OK) {
        throw AudioException((boost::format("failed to reset encoder: %s") % opus_strerror(status)).str());
    }

    outgoingSequenceNumber = 0;
}

void mumlib::Audio::resetJitterBuffer() {
    logger.debug("Last audio packet, resetting jitter buffer");
    jitter_buffer_reset(jbBuffer);
}

mumlib::IncomingAudioPacket mumlib::Audio::decodeIncomingAudioPacket(uint8_t *inputBuffer, int inputBufferLength) {
    mumlib::IncomingAudioPacket incomingAudioPacket{};

    incomingAudioPacket.type = static_cast<AudioPacketType >((inputBuffer[0] & 0xE0) >> 5);
    incomingAudioPacket.target = inputBuffer[0] & 0x1F;

    std::array<int64_t *, 2> varInts = {&incomingAudioPacket.sessionId, &incomingAudioPacket.sequenceNumber};

    int dataPointer = 1;
    for (int64_t *val : varInts) {
        VarInt varInt(&inputBuffer[dataPointer]);
        *val = varInt.getValue();
        dataPointer += varInt.getEncoded().size();
    }

    incomingAudioPacket.audioPayload = &inputBuffer[dataPointer];
    incomingAudioPacket.audioPayloadLength = inputBufferLength - dataPointer;

    if (dataPointer >= inputBufferLength) {
        throw AudioException((boost::format("invalid incoming audio packet (%d B): header %d B") % inputBufferLength %
                              dataPointer).str());
    }

    //logger.debug(
/*
    printf(
            "Received %d B of audio packet, %d B header, %d B payload (target: %d, sessionID: %ld, seq num: %ld).\n",
            inputBufferLength,
            dataPointer,
            incomingAudioPacket.audioPayloadLength,
            incomingAudioPacket.target,
            incomingAudioPacket.sessionId,
            incomingAudioPacket.sequenceNumber);
*/
    return incomingAudioPacket;
}


