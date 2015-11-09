#include "mumlib/Audio.hpp"

#include <boost/format.hpp>

static boost::posix_time::seconds RESET_SEQUENCE_NUMBER_INTERVAL(5);

mumlib::Audio::Audio()
        : logger(log4cpp::Category::getInstance("mumlib.Audio")),
          opusDecoder(nullptr),
          opusEncoder(nullptr),
          outgoingSequenceNumber(0) {

    int error;

    opusDecoder = opus_decoder_create(SAMPLE_RATE, 1, &error);
    if (error != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize OPUS decoder: %s") % opus_strerror(error)).str());
    }

    opusEncoder = opus_encoder_create(SAMPLE_RATE, 1, OPUS_APPLICATION_VOIP, &error);
    if (error != OPUS_OK) {
        throw AudioException((boost::format("failed to initialize OPUS encoder: %s") % opus_strerror(error)).str());
    }

    opus_encoder_ctl(opusEncoder, OPUS_SET_VBR(0));

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

int mumlib::Audio::decodeAudioPacket(AudioPacketType type,
                                     uint8_t *inputBuffer,
                                     int inputLength,
                                     int16_t *pcmBuffer,
                                     int pcmBufferSize) {

    if (type != AudioPacketType::OPUS) {
        throw AudioException("codecs other than OPUS are not supported");
    }

    int target = inputBuffer[0] & 0x1F;

    int64_t sessionId;
    int64_t sequenceNumber;
    int64_t opusDataLength;

    std::array<int64_t *, 3> varInts = {&sessionId, &sequenceNumber, &opusDataLength};

    int dataPointer = 1;
    for (int64_t *val : varInts) {
        VarInt varInt(&inputBuffer[dataPointer]);
        *val = varInt.getValue();
        dataPointer += varInt.getEncoded().size();
    }

    bool lastPacket = (opusDataLength & 0x2000) != 0;
    opusDataLength = opusDataLength & 0x1fff;

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

    logger.debug(
            "Received %d B of OPUS data, decoded to %d B (target: %d, sessionID: %ld, seq num: %ld, last: %d).",
            opusDataLength,
            outputSize,
            target,
            sessionId,
            sequenceNumber,
            lastPacket);


    return outputSize;
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

    header.push_back(0x80 | target);

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
    memcpy(outputBuffer + header.size(), tmpOpusBuffer, outputSize);

    int incrementNumber = 100 * inputLength / SAMPLE_RATE;

    outgoingSequenceNumber += incrementNumber;

    lastEncodedAudioPacketTimestamp = std::chrono::system_clock::now();

    return outputSize + header.size();
}

void mumlib::Audio::resetEncoder() {
    int status = opus_encoder_ctl(opusEncoder, OPUS_RESET_STATE, nullptr);

    if (status != OPUS_OK) {
        throw AudioException((boost::format("failed to reset encoder: %s") % opus_strerror(status)).str());
    }

    outgoingSequenceNumber = 0;
}
