#include "mumlib/Audio.hpp"

#include <boost/format.hpp>

static boost::posix_time::seconds RESET_SEQUENCE_NUMBER_INTERVAL(5);

mumlib::Audio::Audio(int opusEncoderBitrate)
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

mumlib::IncomingAudioPacket mumlib::Audio::decodeIncomingAudioPacket(uint8_t *inputBuffer, int inputBufferLength) {
    mumlib::IncomingAudioPacket incomingAudioPacket;

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


