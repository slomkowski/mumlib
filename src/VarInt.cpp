#include "mumlib/VarInt.hpp"

#include <boost/format.hpp>

mumlib::VarInt::VarInt(int64_t value) : value(value) { }

mumlib::VarInt::VarInt(uint8_t *encoded) : value(parseVariant(encoded)) { }

mumlib::VarInt::VarInt(std::vector<uint8_t> encoded) : value(parseVariant(&encoded[0])) { }

/*
 * This code was taken from Mumble source code
 * https://github.com/mumble-voip/mumble/blob/master/src/PacketDataStream.h
 */
int64_t mumlib::VarInt::parseVariant(const uint8_t *buffer) {
    int64_t v = buffer[0];
    if ((v & 0x80) == 0x00) {
        return (v & 0x7F);
    } else if ((v & 0xC0) == 0x80) {
        return (v & 0x3F) << 8 | buffer[1];
    } else if ((v & 0xF0) == 0xF0) {
        switch (v & 0xFC) {
            case 0xF0:
                return buffer[1] << 24 | buffer[2] << 16 | buffer[3] << 8 | buffer[4];
            case 0xF4:
                //throw VarIntException("currently unsupported 8-byte varint size");
            case 0xF8:
            case 0xFC:
                //throw VarIntException("currently negative varints aren't supported");
            default:
                break;
        }
    } else if ((v & 0xF0) == 0xE0) {
        return (v & 0x0F) << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3];
    } else if ((v & 0xE0) == 0xC0) {
        return (v & 0x1F) << 16 | buffer[1] << 8 | buffer[2];
    }

    return 0;
    //throw VarIntException("invalid varint");
}

std::vector<uint8_t> mumlib::VarInt::getEncoded() const {
    std::vector<uint8_t> encoded;
    int64_t i = this->value;

    if ((i & 0x8000000000000000LL) && (~i < 0x100000000LL)) {
        i = ~i;
        if (i <= 0x3) {
            encoded.push_back(static_cast<unsigned char &&>(0xFC | i));
            return encoded;
        } else {
            encoded.push_back(0xF8);
        }
    }

    if (i < 0x80) {
        encoded.push_back(static_cast<unsigned char &&>(i));
    } else if (i < 0x4000) {
        encoded.push_back(static_cast<unsigned char &&>(0x80 | (i >> 8)));
        encoded.push_back(static_cast<unsigned char &&>(i & 0xFF));
    } else if (i < 0x200000) {
        encoded.push_back(static_cast<unsigned char &&>(0xC0 | (i >> 16)));
        encoded.push_back(static_cast<unsigned char &&>((i >> 8) & 0xFF));
        encoded.push_back(static_cast<unsigned char &&>(i & 0xFF));
    } else if (i < 0x10000000) {
        encoded.push_back(static_cast<unsigned char &&>(0xE0 | (i >> 24)));
        encoded.push_back(static_cast<unsigned char &&>((i >> 16) & 0xFF));
        encoded.push_back(static_cast<unsigned char &&>((i >> 8) & 0xFF));
        encoded.push_back(static_cast<unsigned char &&>(i & 0xFF));
    } else {
        encoded.push_back(0xF4);
        encoded.push_back(static_cast<unsigned char &&>((i >> 56) & 0xFF));
        encoded.push_back(static_cast<unsigned char &&>((i >> 48) & 0xFF));
        encoded.push_back(static_cast<unsigned char &&>((i >> 40) & 0xFF));
        encoded.push_back(static_cast<unsigned char &&>((i >> 32) & 0xFF));
        encoded.push_back(static_cast<unsigned char &&>((i >> 24) & 0xFF));
        encoded.push_back(static_cast<unsigned char &&>((i >> 16) & 0xFF));
        encoded.push_back(static_cast<unsigned char &&>((i >> 8) & 0xFF));
        encoded.push_back(static_cast<unsigned char &&>(i & 0xFF));
    }

    return encoded;
}
