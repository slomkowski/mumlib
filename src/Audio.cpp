#include "mumlib/Audio.hpp"

#include <boost/format.hpp>

static boost::posix_time::seconds RESET_SEQUENCE_NUMBER_INTERVAL(5);

mumlib::Audio::Audio(int opusSampleRate, int opusEncoderBitrate, int channels)
        : logger(log4cpp::Category::getInstance("mumlib.Audio")),
          opusDecoder(nullptr),
          opusEncoder(nullptr),
          outgoingSequenceNumber(0) {

    int error;
    this->sampleRate = opusSampleRate;

    opusDecoder = opus_decoder_create(opusSampleRate, channels, &error);
    if (error != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize OPUS decoder: %s") % opus_strerror(error)).str());
    }

    opusEncoder = opus_encoder_create(opusSampleRate, channels, OPUS_APPLICATION_VOIP, &error);
    if (error != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize OPUS encoder: %s") % opus_strerror(error)).str());
    }

    opus_encoder_ctl(opusEncoder, OPUS_SET_VBR(0));

    setOpusEncoderBitrate(opusEncoderBitrate);

    resetEncoder();
}

mumlib::Audio::~Audio() {
    if (opusDecoder) {
        opus_decoder_destroy(opusDecoder);
    }

    if (opusEncoder) {
        opus_encoder_destroy(opusEncoder);
    }
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

std::pair<int, bool>  mumlib::Audio::decodeOpusPayload(uint8_t *inputBuffer,
                                                       int inputLength,
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

    int frame = opus_packet_get_nb_frames(&inputBuffer[dataPointer], opusDataLength);
    int samples = frame * opus_packet_get_samples_per_frame(&inputBuffer[dataPointer], sampleRate);
    int outputSize = opus_decode(opusDecoder,
                                 reinterpret_cast<const unsigned char *>(&inputBuffer[dataPointer]),
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
        logger.debug("Last audio packet was sent %d ms ago, resetting encoder.", lastAudioPacketSentInterval);
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

    int incrementNumber = 100 * inputLength / sampleRate;

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

    logger.debug(
            "Received %d B of audio packet, %d B header, %d B payload (target: %d, sessionID: %ld, seq num: %ld).",
            inputBufferLength,
            dataPointer,
            incomingAudioPacket.audioPayloadLength,
            incomingAudioPacket.target,
            incomingAudioPacket.sessionId,
            incomingAudioPacket.sequenceNumber);

    return incomingAudioPacket;
}


