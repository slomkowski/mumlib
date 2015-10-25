#pragma once

#include "mumlib/Callback.hpp"

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>

#include <string>
#include <mumlib/enums.hpp>

namespace mumlib {

    using namespace std;
    using namespace boost::asio;

    class MumlibException : public runtime_error {
    public:
        MumlibException(string message) : runtime_error(message) { }
    };

    struct _Mumlib_Private;


    class Mumlib : boost::noncopyable {
    public:
        Mumlib();

        Mumlib(io_service &ioService);

        ~Mumlib();

        void setCallback(Callback &callback);

        void connect(string host, int port, string user, string password);

        void disconnect();

        void run();

        ConnectionState getConnectionState();

        void sendAudioData(int16_t *pcmData, int pcmLength);

    private:
        _Mumlib_Private *impl;
    };
}