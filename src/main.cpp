// Shoot in the feet!

#include <cstdio>
#include <cstring>
#include <ctime>

#include <iostream>
#include <vector>
#include <array>
#include <algorithm>

extern "C" {
#include "osdep.h"
}

#include "oui.h"

/*
 * TODO:
 * 1. Two modes, fake & flood
 * 2. syslog
 * 3. getopt
 */

struct MAC_Addr
{
    std::array<std::uint8_t, 6> val;

    MAC_Addr() : val()
    {
        std::memset(val.data(), 0, 6);
    }

    MAC_Addr(std::uint8_t b0, std::uint8_t b1, std::uint8_t b2,
             std::uint8_t b3, std::uint8_t b4, std::uint8_t b5) :
        val()
    {
        val[0] = b0;
        val[1] = b1;
        val[2] = b2;
        val[3] = b3;
        val[4] = b4;
        val[5] = b5;
    }

    MAC_Addr(std::uint8_t OUI[3],
    std::uint8_t b3, std::uint8_t b4, std::uint8_t b5) :
        val()
    {
        val[0] = OUI[0];
        val[1] = OUI[1];
        val[2] = OUI[2];
        val[3] = b3;
        val[4] = b4;
        val[5] = b5;
    }
} __attribute__((packed));

std::uint8_t WLAN_PROBE_FRAME[] = {
    0x40, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
};
constexpr unsigned int WLAN_PROBE_FRAME_SIZE = sizeof(WLAN_PROBE_FRAME);

std::uint8_t WLAN_SUPPORTED_RATES[] = {
    0x01, 0x04, 0x02, 0x04, 0x0B, 0x16, 0x32, 0x08,
    0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C,
};
constexpr unsigned int WLAN_SUPPORTED_RATES_SIZE = sizeof(WLAN_SUPPORTED_RATES);

int send_packet(struct wif* wi_out, void *buf, size_t count)
{
    unsigned char *pkt = static_cast<unsigned char *>(buf);
    if (wi_write(wi_out, pkt, count, NULL) == -1) {
        perror("wi_write()");
        return -1;
    }
    return 0;
}

int send_probe_packet(wif *wi_out, MAC_Addr mac, int &sequence, int channel)
{
    // Frame skeleton
    int len = WLAN_PROBE_FRAME_SIZE;
    unsigned char frame_body[4096];
    std::memcpy(frame_body, WLAN_PROBE_FRAME, len);

    // MAC address
    if (wi_get_channel(wi_out) != channel) {
        wi_set_channel(wi_out, channel);
    }
    std::memcpy(frame_body + 10, mac.val.data(), 6);

    // Sequence number
    frame_body[22] = (sequence & 0x0000000F) << 4;
    frame_body[23] = (sequence & 0x00000FF0) >> 4;

    // ESSID
    frame_body[len + 1] = 0;
    len += 2;

    // Supported Rates
    std::memcpy(frame_body + len, WLAN_SUPPORTED_RATES, WLAN_SUPPORTED_RATES_SIZE);
    len += WLAN_SUPPORTED_RATES_SIZE;

//    printf("probing as %02X:%02X:%02X:%02X:%02X:%02X @C%d, sent %d times\n",
//           mac.val[0], mac.val[1], mac.val[2], mac.val[3], mac.val[4], mac.val[5],
//            channel, sequence);

    if (send_packet(wi_out, frame_body, len) == 0) {
        sequence++;
    }
    return 0;
}

int randint(int hi)
{
    return std::rand() % hi;
}

std::vector<MAC_Addr> generate_random_MACs(int ouiNumber, int macPerOUI)
{
    std::vector<MAC_Addr> addrs;
    std::srand(std::time(0));

    if (ouiNumber > OUI_DEFS_SIZE)
        ouiNumber = OUI_DEFS_SIZE;
    addrs.reserve(ouiNumber);

    for (int i = 0; i < ouiNumber; ++i) {
        for (int j = 0; j < macPerOUI; ++j) {
            MAC_Addr mac(OUI_DEFS[randint(ouiNumber)], randint(0xFF), randint(0xFF), randint(0xFF));
            addrs.push_back(mac);
        }
    }

    return addrs;
}


int main(int argc, char *argv[])
{
    char iface[] = "wlan0";

    wif *wi_out = wi_open(iface);

    if (!wi_out) {
        std::fprintf(stderr, "failed to init iface %s\n", iface);
        return 1;
    }

    std::vector<MAC_Addr> macs = generate_random_MACs(100, 10000);
    std::vector<int> seqs(macs.size());
    // randomize seqs

    std::printf("%lu macs in total\n", macs.size());

    for (int repeat = 0; repeat < 2; ++repeat) {
        for (unsigned int j = 0; j < macs.size(); ++j) {
            auto mac = macs[j];
            std::printf("probing as %02X:%02X:%02X:%02X:%02X:%02X on 12 channels\n",
                        mac.val[0], mac.val[1], mac.val[2], mac.val[3], mac.val[4], mac.val[5]);

            for (int channel = 1; channel <= 11; ++channel) {
                send_probe_packet(wi_out, macs[j], seqs[j], channel);
//                usleep(500);
            }
        }
    }

    return 0;
}
