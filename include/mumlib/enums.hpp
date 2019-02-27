#pragma once

namespace mumlib {
    enum class MessageType {
        VERSION = 0,
        UDPTUNNEL = 1,
        AUTHENTICATE = 2,
        PING = 3,
        REJECT = 4,
        SERVERSYNC = 5,
        CHANNELREMOVE = 6,
        CHANNELSTATE = 7,
        USERREMOVE = 8,
        USERSTATE = 9,
        BANLIST = 10,
        TEXTMESSAGE = 11,
        PERMISSIONDENIED = 12,
        ACL = 13,
        QUERYUSERS = 14,
        CRYPTSETUP = 15,
        CONTEXTACTIONMODIFY = 16,
        CONTEXTACTION = 17,
        USERLIST = 18,
        VOICETARGET = 19,
        PERMISSIONQUERY = 20,
        CODECVERSION = 21,
        USERSTATS = 22,
        REQUESTBLOB = 23,
        SERVERCONFIG = 24,
        SUGGESTCONFIG = 25
    };

    enum class ConnectionState {
        NOT_CONNECTED,
        IN_PROGRESS,
        CONNECTED,
        FAILED
    };

    enum class AudioPacketType {
        CELT_Alpha,
        Ping,
        Speex,
        CELT_Beta,
        OPUS
    };
    
    enum class UserState {
        MUTE,
        DEAF,
        SUPPRESS,
        SELF_MUTE,
        SELF_DEAF,
        COMMENT,
        PRIORITY_SPEAKER,
        RECORDING
    };

}
