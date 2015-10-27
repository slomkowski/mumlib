#include "mumlib.hpp"

#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"

#include <thread>
#include <cmath>
#include <mumlib/Audio.hpp>

void audioSenderThreadFunction(mumlib::Mumlib *mum) {
    while (mum->getConnectionState() != mumlib::ConnectionState::FAILED) {
        if (mum->getConnectionState() == mumlib::ConnectionState::CONNECTED) {
            constexpr double FREQUENCY = 1000; // Hz
            constexpr int BUFF_SIZE = mumlib::SAMPLE_RATE / 100; // 10 ms
            int16_t buff[BUFF_SIZE];

            for (int i = 0; i < BUFF_SIZE; ++i) {
                buff[i] = 10000 * std::sin(2.0 * M_PI * FREQUENCY * ((double) i) / ((double) mumlib::SAMPLE_RATE));
            }

            mum->sendAudioData(buff, BUFF_SIZE);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

int main(int argc, char *argv[]) {

    log4cpp::Appender *appender1 = new log4cpp::OstreamAppender("console", &std::cout);
    appender1->setLayout(new log4cpp::BasicLayout());
    log4cpp::Category &logger = log4cpp::Category::getRoot();
    logger.setPriority(log4cpp::Priority::NOTICE);
    logger.addAppender(appender1);

    if (argc < 3) {
        logger.crit("Usage: %s {server} {password}", argv[0]);
        return 1;
    }

    mumlib::BasicCallback callback;
    mumlib::Mumlib mum(callback);

    mum.connect(argv[1], 64738, "mumlib_example", argv[2]);

    std::thread audioSenderThread(audioSenderThreadFunction, &mum);

    mum.run();

    return 0;
}