**I do not maintain this project and [mumsi](https://github.com/slomkowski/mumsi) any longer, but some new features and bugfixes have been implemented in the [forks](https://github.com/slomkowski/mumlib/network). Check them out!**

# mumlib - simple Mumble client library

Fairy simple Mumble library written in C++, using *boost::asio* asynchronous networking framework. Library supports:

* audio streaming through TCP and UDP channel
* text messaging

Todo:

* channel support
* user information
* remaining server messages (ACL, user stats etc)

## Dependencies

* Boost libraries
* OpenSSL
* *log4cpp*
* Opus library
* Google Protobuf: libraries and compiler
* CMake

## Build

The library uses CMake build system:

```
mkdir build && cd build
cmake ..
make
```

## Usage

Sample usage is covered in *mumlib_example.cpp* file. Basically, you should extend *mumlib::Callback* class
to implement your own handlers.

To use a client certificate, you'll need a PEM certificate and private key without a passphrase. These are assed in the MumlibConfig struct to the Mumlib object constructor. Support for passphrase still needs to be added.

## Credits

2015 Michał Słomkowski. The code is published under the terms of Lesser General Public License Version 3.

The library contains code from following 3rd party projects:

* official Mumble Client: https://github.com/mumble-voip/mumble
* *libmumble*: https://github.com/cornejo/libmumble
