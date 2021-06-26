#include "mumlib.hpp"

#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"

#include <chrono>
#include <thread>
#include <mumlib/Transport.hpp>

class MyCallback : public mumlib::BasicCallback {
public:
    mumlib::Mumlib *mum;

    log4cpp::Category &logger = log4cpp::Category::getRoot();

    virtual void audio(int target,
                       int sessionId,
                       int sequenceNumber,
                       int16_t *pcm_data,
                       uint32_t pcm_data_size) override {
        logger.notice("Received audio: pcm_data_size: %d", pcm_data_size);
        mum->sendAudioData(pcm_data, pcm_data_size);
    }

    virtual void textMessage(
            uint32_t actor,
            std::vector<uint32_t> session,
            std::vector<uint32_t> channel_id,
            std::vector<uint32_t> tree_id,
            std::string message) override {
        mumlib::BasicCallback::textMessage(actor, session, channel_id, tree_id, message);
        logger.notice("Received text message: %s", message.c_str());
        mum->sendTextMessage("someone said: " + message);
    }
};

int main(int argc, char *argv[]) {

    log4cpp::Appender *appender1 = new log4cpp::OstreamAppender("console", &std::cout);
    appender1->setLayout(new log4cpp::BasicLayout());
    log4cpp::Category &logger = log4cpp::Category::getRoot();
    logger.setPriority(log4cpp::Priority::NOTICE);
    logger.addAppender(appender1);

    if (argc < 3 || argc == 4 || argc > 5) {
        logger.crit("Usage: %s {server} {password} [{certfile} {keyfile}]", argv[0]);
        return 1;
    }

    MyCallback myCallback;

    while (true) {
        try {
            mumlib::MumlibConfiguration conf;
            conf.opusEncoderBitrate = 16000;
            if ( argc > 3 && argc <= 5 ) {
                conf.cert_file = argv[3];
                conf.privkey_file = argv[4];
            }
            mumlib::Mumlib mum(myCallback, conf);
            myCallback.mum = &mum;
            mum.connect(argv[1], 1234, "mumlib_example2", argv[2]);
            mum.run();
        } catch (mumlib::TransportException &exp) {
            logger.error("TransportException: %s.", exp.what());

            logger.notice("Attempting to reconnect in 5 s.");
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}
