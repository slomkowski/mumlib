#pragma once

#include <mumlib.hpp>

#include <stdint.h>
#include <vector>
#include <string>

namespace mumlib {
#ifdef MUMLIB_USE_EXCEPTIONS
    class VarIntException : public MumlibException {
    public:
        VarIntException(std::string message) : MumlibException(message) { }
    };
#endif

    class VarInt {
    public:
        VarInt(uint8_t *encoded);

        VarInt(std::vector<uint8_t> encoded);

        VarInt(int64_t value);

        int64_t getValue() const {
            return this->value;
        }

        std::vector<uint8_t> getEncoded() const;

    private:
        const int64_t value;

        int64_t parseVariant(uint8_t *buffer);
    };
}
