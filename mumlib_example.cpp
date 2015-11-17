#include "mumlib.hpp"

#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"

class MyCallback : public mumlib::BasicCallback {
public:
    mumlib::Mumlib *mum;

    virtual void audio(int target,
                       int sessionId,
                       int sequenceNumber,
                       int16_t *pcm_data,
                       uint32_t pcm_data_size) override {
        mum->sendAudioData(pcm_data, pcm_data_size);
    }

    virtual void textMessage(
            uint32_t actor,
            std::vector<uint32_t> session,
            std::vector<uint32_t> channel_id,
            std::vector<uint32_t> tree_id,
            std::string message) override {
        mumlib::BasicCallback::textMessage(actor, session, channel_id, tree_id, message);
        mum->sendTextMessage("someone said: " + message);
    }
};

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

    MyCallback myCallback;
    mumlib::Mumlib mum(myCallback);
    myCallback.mum = &mum;

    mum.connect(argv[1], 64738, "mumlib_example", argv[2]);

    mum.run();

    return 0;
}