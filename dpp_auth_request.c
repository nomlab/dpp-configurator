#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/wireless.h> 


#define MAC_ADDR_LEN 6


// DPPアクションフレームの構造体
typedef struct {
    uint8_t category;
    uint8_t action;
    uint8_t oui[3];
    uint8_t oui_type;
    uint8_t crypto_suite;
    uint8_t frame_type;
    uint8_t dpp_body[];
} dpp_action_frame_t;

// 802.11フレームの基本ヘッダ構造体
typedef struct {
    uint8_t frame_control[2];
    uint16_t duration;
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    uint16_t sequence_control;
} ieee80211_header_t;

// 固定部分の管理フレームヘッダ
typedef struct {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities;
} ieee80211_beacon_fixed_parameters_t;

// ビーコンフレーム全体
typedef struct {
    ieee80211_header_t header;
    ieee80211_beacon_fixed_parameters_t fixed_parameters;
} ieee80211_beacon_frame_t;

// 関数プロトタイプ
void create_dpp_action_frame(uint8_t *frame, size_t *frame_len);
void generate_dpp_elements(uint8_t *public_key, uint8_t *nonce, uint8_t *auth_tag);

void set_monitor_mode(const char *ifname) {
    int sockfd;
    struct ifreq ifr;
    struct iwreq iwr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // インターフェースをダウンさせる
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    ifr.ifr_flags &= ~IFF_UP;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // モニターモードに設定する
    strncpy(iwr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIWMODE, &iwr) < 0) {
        perror("SIOCGIWMODE");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    iwr.u.mode = IW_MODE_MONITOR;
    if (ioctl(sockfd, SIOCSIWMODE, &iwr) < 0) {
        perror("SIOCSIWMODE");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // インターフェースを再度アップさせる
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);
}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *dev = "wlp1s0"; // 使用するデバイス名に変更してください

    set_monitor_mode(dev);

    // デバイスをオープン
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // DPPアクションフレームを作成
    uint8_t frame[256];
    size_t frame_len;
    create_dpp_action_frame(frame, &frame_len);

    // フレームを送信
    while (1) {
        if (pcap_sendpacket(handle, frame, frame_len) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 2;
        }

        // 100ミリ秒待つ
        usleep(100 * 1000);
    }

    // クローズ
    pcap_close(handle);

    return 0;
}

void create_dpp_action_frame(uint8_t *frame, size_t *frame_len) {
    // Radiotapヘッダの設定
    // radiotapヘッダーの設定
    uint8_t radiotap_header[] = {
        0x00, 0x00, // radiotap version
        0x0a, 0x00, // radiotap header length
        0x00, 0x00, 0x00, 0x00, // bitmap
        0x02, // rate
        0x00 // padding
    };

    // 802.11ヘッダの設定
    ieee80211_header_t ieee80211_header;
    ieee80211_header.frame_control[0] = 0xD0; // Management frame subtype (Action)
    ieee80211_header.frame_control[1] = 0x00;
    ieee80211_header.duration = 0;
    memcpy(ieee80211_header.addr1, "\xff\xff\xff\xff\xff\xff", MAC_ADDR_LEN); // Broadcast address
    memcpy(ieee80211_header.addr2, "\x00\x11\x22\x33\x44\x55", MAC_ADDR_LEN); // Source address
    memcpy(ieee80211_header.addr3, "\xff\xff\xff\xff\xff\xff", MAC_ADDR_LEN); // BSSID
    ieee80211_header.sequence_control = 0;

    // DPPアクションフレームの設定
    uint8_t public_key[64];
    uint8_t boot_hash[64];
    uint8_t protocol_key[128];
    uint8_t channnel[4];
    uint8_t wrapped_data[82];


    // DPPボディのサイズを計算
    size_t dpp_body_len = 32 + 32 + 64 + 2 + 41;
    uint8_t *dpp_body = malloc(dpp_body_len);

    // https://www.wi-fi.org/system/files/Wi-Fi_Easy_Connect_Specification_v3.0.pdf
    // 上記のページの p149 を参考に dppframe の body を埋めた．
    // しかし，wireshark でパケットを確認すると，p149 のパケット例と異なるパケットになっていた． 
    memcpy(dpp_body, "\x92\x2d\xdd\x7a\x3e\xd6\x9f\x46\x12\x5d\x77\x2b\xbe\x60\x17\xcd\x4e\x03\x87\x0d\xc0\x14\x50\x9e\x38\xb5\x46\x28\xe1\x57\xa8\x7d", 32);
    memcpy(dpp_body + 32, "\x5d\x46\x7a\x09\x76\x02\x92\xfc\x15\xd3\x17\x92\xb0\xa5\xb0\x50\xdb\x8b\xf6\xad\x80\x7d\x71\xb2\xd9\x3f\x4d\x1c\x2e\x65\xd8\x81", 32);
    memcpy(dpp_body + 32, "\x50\xa5\x32\xae\x2a\x07\x20\x72\x76\x41\x8d\x2f\xa6\x30\x29\x5d\x45\x56\x9b\xe4\x25\xaa\x63\x4f\x02\x01\x4d\x00\xa7\xd1\xf6\x1a\xe1\x4f\x35\xa5\xa8\x58\xbc\xca\xd9\x0d\x12\x6c\x46\x59\x4c\x49\xef\x82\x65\x5e\x78\x88\x8e\x15\xa3\x2d\x91\x6a\xc2\x17\x24\x91", 64);
    memcpy(dpp_body + 64, "\x51\x01", 2);
    memcpy(dpp_body + 2, "\x86\x8f\x47\x8f\xc5\x99\xac\x3f\xa8\x15\x2b\x97\x5e\xff\x8b\xe4\xe7\x1b\x18\x9d\xbe\xfb\xc3\x18\x5b\x1d\x7f\x38\x64\xe8\x96\xf9\x13\xcb\xa3\xd9\x60\x13\x26\xf2\x78", 41);

    dpp_action_frame_t dpp_frame;
    dpp_frame.category = 0x04; // Public Action frame
    dpp_frame.action = 0x09;   // DPP
    dpp_frame.oui[0] = 0x50;
    dpp_frame.oui[1] = 0x6f;
    dpp_frame.oui[2] = 0x9a;
    dpp_frame.oui_type = 0x1a;
    dpp_frame.crypto_suite = 0x01; // Crypto Suite (例: 0x01)
    dpp_frame.frame_type = 0x00; // DPP Frame Type (例: DPP Authentication Request)

    // DPPアクションフレーム全体のサイズを計算
    size_t dpp_frame_len = sizeof(dpp_action_frame_t) + dpp_body_len;
    uint8_t *ptr = frame;

    // Radiotapヘッダをコピー
    memcpy(ptr, radiotap_header, sizeof(radiotap_header));
    ptr += sizeof(radiotap_header);
    // 802.11ヘッダをコピー
    memcpy(ptr, &ieee80211_header, sizeof(ieee80211_header_t));
    ptr += sizeof(ieee80211_header_t);

    // DPPアクションフレームをコピー
    memcpy(ptr, &dpp_frame, sizeof(dpp_action_frame_t));
    ptr += sizeof(dpp_action_frame_t);
    memcpy(ptr, dpp_body, dpp_body_len);
    ptr += dpp_body_len;

    *frame_len = ptr - frame; // フレーム全体の長さを計算

    free(dpp_body);
}
