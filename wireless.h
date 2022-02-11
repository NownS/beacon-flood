#pragma once
#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push,1)

typedef struct _RadiotapHdr final{
    uint8_t headerRevision_;
    uint8_t headerPad_;
    uint16_t hlen_;

    uint16_t hlen() {return hlen_;}
} RadiotapHdr;
typedef RadiotapHdr *PRadiotabHdr;

typedef struct _Dot11Hdr {
    uint8_t versionTypeSubtype = 0x80;
    uint8_t flags_ = 0;
    uint16_t duration_ = 0;
    Mac destination_ = Mac::broadcastMac();
    Mac source_;
    Mac bssid_;
    uint16_t numbers = 0;

    uint16_t duration() {return duration_;}
    Mac destination() {return destination_;}
    Mac source() {return source_;}
    Mac bssid() {return bssid_;}
} Dot11Hdr;
typedef Dot11Hdr *PDot11Hdr;

struct Dot11WirelessMgntFixed {
    uint64_t timestamp_ = 0;
    uint16_t beaconInterval_ = 64;
    uint16_t capabilitiesInfo_ = 1;
};
typedef Dot11WirelessMgntFixed *PDot11WirelessMgntFixed;

struct Dot11WirelessMgntTagged {
    uint8_t eid_;
    uint8_t length_;
};
typedef Dot11WirelessMgntTagged *PDot11WirelessMgntTagged;

typedef struct _SimpleRadiotapHdr final{
    uint8_t headerRevision_ = 0;
    uint8_t headerPad_ = 0;
    uint16_t hlen_ = 8;
    uint32_t present_ = 0x00000000;

    uint16_t hlen() {return hlen_;}
} SimpleRadiotapHdr;
typedef SimpleRadiotapHdr *PSimpleRadiotabHdr;

typedef struct _RestTag {       //use mdk3
    uint8_t rates_eid = 1;
    uint8_t rates_length = 4;
    uint8_t rates[4] = {0x82, 0x84, 0x8b, 0x96};

    uint8_t channel_eid = 3;
    uint8_t channel_length = 1;
    uint8_t channel;

    uint8_t CF_eid = 4;
    uint8_t CF_length = 6;
    uint8_t CF[6] = {1, 2, 0, 0, 0, 0};

    uint8_t TIM_eid = 5;
    uint8_t TIM_length = 4;
    uint8_t TIM[4] = {0, 1, 0, 0};

} RestTag;


#pragma pack(pop)

