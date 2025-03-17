#include "crypto.h"
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <net/if.h>
#include <linux/wireless.h> 
#include <openssl/aes.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
struct timespec start_time;

//const uint8_t TARGET_MAC[6] = {0x34, 0x85, 0x18, 0x82, 0x4a, 0x28};// Set target mac addr (ex. {0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

uint8_t TARGET_MAC[6];
uint8_t SRC_MAC[6];

#define u8 unsigned char
#define MBEDTLS_AES_BLOCK_SIZE 16
#define SHA256_MAC_LEN 32
static const u8 zero[AES_BLOCK_SIZE];
#define MAC_ADDR_LEN 6
#define ATTR_ID_LEN 2
#define ATTR_ID_LEN_LEN 2
#define BOOT_KEY_LEN 32
#define PROT_KEY_LEN 64
#define DPP_OUI 4
#define DPP_HDR_LEN (DPP_OUI + 2) /* OUI, OUI Type, Crypto Suite, DPP frame type */

#define IEEE80211_ACTION_FLAG_LEN 24
#define IEEE80211_CAT_LEN 1
#define IEEE80211_PUB_ACTION_LEN 1
#define IEEE80211_GAS_LEN (6 + DPP_OUI + 1)
#define IEEE80211_CAT_HEADER_LEN (IEEE80211_CAT_LEN + IEEE80211_PUB_ACTION_LEN)
#define IEEE80211_ACTION_HEADER_LEN (IEEE80211_CAT_HEADER_LEN + DPP_HDR_LEN)
#define IEEE80211_GAS_HEADER_LEN (IEEE80211_CAT_HEADER_LEN + IEEE80211_GAS_LEN)

#define IEEE80211_RADIOTAP_TSFT 0
#define IEEE80211_RADIOTAP_FLAGS 1
#define IEEE80211_RADIOTAP_RATE 2
#define IEEE80211_RADIOTAP_CHANNEL 3
#define IEEE80211_RADIOTAP_DB_ANTSIGNAL 5
#define IEEE80211_RADIOTAP_ANTENNA 11
#define IEEE80211_RADIOTAP_RX_FLAGS 14
#define IEEE80211_RADIOTAP_TS 22
#define IEEE80211_RADIOTAP_NS 29
#define IEEE80211_RADIOTAP_EXT 31
#define Confsize 100
u8 configObj[Confsize];
size_t config_length = 0;

static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// radiotapヘッダーの設定
struct ieee80211_radiotap_header {
        uint8_t        it_version;     /* set to 0 */
        uint8_t        it_pad;
        uint16_t       it_len;         /* entire length */
        uint32_t       it_present[3];     /* fields present */
        uint64_t tsft;
        uint8_t flags;
        uint8_t rate;
        uint16_t channel_freq;
        uint16_t channel_flags;
        uint8_t db_antsignal;
        //uint8_t anntena;
        //uint16_t rx_flags;
        uint32_t ns;
        uint32_t ext_fields;
        uint8_t dbm_antsignal;
        uint64_t ts2;
        uint16_t  accuracy;
        uint8_t  sp;
        uint8_t af;
        uint8_t as1;
        uint8_t an1;
        //uint8_t as2;
        //uint8_t an2;
} __attribute__((__packed__));

struct ieee80211_radiotap_header rt_header;

void init_radiotap_header() {
    memset(&rt_header, 0, sizeof(struct ieee80211_radiotap_header));
    rt_header.it_version = 0;
    rt_header.it_len = sizeof(struct ieee80211_radiotap_header); // エンディアンを考慮
    rt_header.it_present[0] = (1 << IEEE80211_RADIOTAP_TSFT) |
                           (1 << IEEE80211_RADIOTAP_FLAGS) |
                           (1 << IEEE80211_RADIOTAP_RATE) | 
                           (1 << IEEE80211_RADIOTAP_CHANNEL) |
                           (1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL) |
                           //(1 << IEEE80211_RADIOTAP_ANTENNA) |
                           (1 << IEEE80211_RADIOTAP_RX_FLAGS) |
                           (1 << IEEE80211_RADIOTAP_TS) |
                           (1 << IEEE80211_RADIOTAP_NS) |
                           (1 << IEEE80211_RADIOTAP_EXT); 
     rt_header.it_present[1] = (1 << 5) |
                               (1 << IEEE80211_RADIOTAP_ANTENNA); 
                            //    (1 << IEEE80211_RADIOTAP_NS)|
                            //    (1 << IEEE80211_RADIOTAP_EXT);
    //  rt_header.it_present[2] = (1 << 5) |
    //                            (1 << IEEE80211_RADIOTAP_ANTENNA); 

}
// チャネル情報の設定関数
void set_channel_info(uint16_t freq, uint16_t flags) {
    rt_header.channel_freq = freq; // エンディアンを考慮
    rt_header.channel_flags = flags; // エンディアンを考慮
}
void set_timestamp(){
    struct timespec tm;
    clock_gettime(CLOCK_REALTIME, &tm);
    rt_header.tsft = (uint64_t)tm.tv_sec * 1000000 + tm.tv_nsec /1000;
}
void set_flags(uint8_t flags){
    rt_header.flags = flags;
}
void set_rate(uint8_t rate){
    rt_header.rate = rate;
}
// void set_antenna(uint8_t anntena){
//     rt_header.anntena = anntena;
// }  
void set_antsignal(uint8_t signal){
    rt_header.db_antsignal = signal;
}
void set_ts(){
    struct timespec tm;
    clock_gettime(CLOCK_REALTIME, &tm);
    rt_header.ts2 = (uint64_t)tm.tv_sec * 1000000 + tm.tv_nsec /1000;
}


uint8_t radiotap_header[] = {
    0x00, 0x00,
    0x0c, 0x00,
    0x00, 0x01, 0x00, 0x00,
    0x85, 0x09, 0xa0, 0x00
};

// 鍵の情報を保持しておく構造体
typedef struct 
{
    char QR_Key[81];
    uint8_t Ini_Proto_Key[64];
    uint8_t Ini_Boot_key[32];
    uint8_t Res_Proto_Key[64];
    uint8_t Res_Boot_Key[64];
    uint8_t Res_Boot_Key_Hash[32];
    uint8_t N_x[32];
    uint8_t M_x[32];
    uint8_t I_nonce[16];
    uint8_t R_nonce[16];
    uint8_t I_auth[32];
    uint8_t ke[32];
    uint8_t E_nonce[16];
    uint8_t test_hash[32];
}auth_t;

auth_t auth; 

// Data unwrapped with k2 の構造体
typedef struct 
{
    uint8_t Attr_ID1[2];
    uint8_t Attr_len1[2];
    uint8_t R_nonce[16];
    uint8_t Attr_ID2[2];
    uint8_t Attr_len2[2];
    uint8_t I_nonce[16];
    uint8_t Attr_ID3[2];
    uint8_t Attr_len3[2];
    uint8_t R_capability[1];
    uint8_t Attr_ID4[2];
    uint8_t Attr_len4[2];
    uint8_t Wrapped_data[52];
}data_unwrapped_with_k2;


// Response Frame の構造体 
typedef struct 
{
    uint8_t Attr_ID1[2];
    uint8_t Attr_len1[2];
    uint8_t DPP_Status[1];
    uint8_t Attr_ID2[2];
    uint8_t Attr_len2[2];
    uint8_t Res_Boot_Hash[32];
    uint8_t Attr_ID3[2];
    uint8_t Attr_len3[2];
    uint8_t Res_Proto_Key[64];
    uint8_t Attr_ID4[2];
    uint8_t Attr_len4[2];
    uint8_t Wrapped_data[117];
} dpp_auth_response_attributes_t;




// Confirm Frame の構造体
typedef struct 
{
    uint8_t Attr_ID1[2];
    uint8_t Attr_len1[2];
    uint8_t DPP_Status[1];
    uint8_t Attr_ID2[2];
    uint8_t Attr_len2[2];
    uint8_t Res_Boot_Hash[32];
    uint8_t Attr_ID3[2];
    uint8_t Attr_len3[2];
    uint8_t Wrapped_data[52];
} dpp_confirm_attributes_t;

// Configuration Response Frame の構造体
typedef struct 
{
    uint8_t Attr_ID1[2];
    uint8_t Attr_len1[2];
    uint8_t DPP_Status[1];
    uint8_t Attr_ID2[2];
    uint8_t Attr_len2[2];
    uint8_t Wrapped_data[140];
} dpp_configuration_response_t;



// DPP Attribute の構造体
typedef struct 
{
    uint8_t header1[4];
    uint8_t Res_boot_Hash[32];
    uint8_t header2[4];
    uint8_t Ini_boot_Hash[32];
    uint8_t header3[4];
    uint8_t Ini_P_Key[64];
    uint8_t header5[4];
    uint8_t Wrapped_data[41];

} dpp_attributes_t;
// DPPアクションフレームの構造体
typedef struct {
    uint8_t category;
    uint8_t action;
    uint8_t oui[3];
    uint8_t oui_type;
    uint8_t crypto_suite;
    uint8_t frame_type;
} dpp_action_frame_t;
// configuration response に使うアクションフレーム
typedef struct{
    uint8_t category;
    uint8_t action;
    uint8_t dialog;
    uint16_t status;
    uint16_t delay;
    uint8_t tag_num;
    uint8_t tag_len;
    uint8_t PAME_BI;
    uint8_t id;
    uint8_t vs_len;
    uint8_t oui[3];
    uint8_t oui_type;
    uint8_t frame_type;
    uint16_t Query_len;
} __attribute__((__packed__)) dpp_action_frame2_t;
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

// Attribute を表示させるための //debug 関数
void debug_print(char *msg, size_t size, u8 * attr){
    printf("%s = \n", msg);
    for (size_t i = 0; i < size; i++)
    {
        printf("%02x",attr[i]);
    }
    printf("\n");
}

void debug_dump(char *msg, size_t size, u8 * attr){
    printf("%s = \n", msg);
    for (size_t i = 0; i < size; i++)
    {
        printf("%02x ",attr[i]);
        if (i != 0 && ((i+1) % 8 == 0))
        {
            printf(" ");
       
            if (i != 0 && ((i+1) % 16 ) == 0)
            {
                printf("\n");
            }
        } 
        
    }
    printf("\n");
}
size_t read_file_to_byte_array(const char *filename, unsigned char *byte_array) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    // ファイルサイズを取得
    fseek(file, 0, SEEK_END);
    size_t length = ftell(file);
    fseek(file, 0, SEEK_SET);

    // バイト配列に読み込み
    fread(byte_array, 1, length, file);
    fclose(file);

    return length;
}
int compare_mac_addr(const uint8_t *packet){
                struct ieee80211_radiotap_header *rtheader = (struct ieee80211_radiotap_header *)packet;
                int rtap_len = rtheader->it_len;

                ieee80211_header_t *macheader = (ieee80211_header_t *)(packet + rtap_len);
            
                return memcmp(macheader-> addr2,TARGET_MAC,6);
}

bool parseMACAddress(const char *macStr, uint8_t *macArray) {
    int values[6];
    if (sscanf(macStr, "%x:%x:%x:%x:%x:%x", 
               &values[0], &values[1], &values[2], 
               &values[3], &values[4], &values[5]) != 6) {
        return false; // 解析エラー
    }
    
    for (int i = 0; i < 6; i++) {
        macArray[i] = (uint8_t) values[i];
    }
    
    return true;
}

int debug_compare_mac_addr(const uint8_t *packet){
                uint8_t macaddr[6];

                struct ieee80211_radiotap_header *rtheader = (struct ieee80211_radiotap_header *)packet;
                int rtap_len = rtheader->it_len;

                ieee80211_header_t *macheader = (ieee80211_header_t *)(packet + rtap_len);
                if (!parseMACAddress("48:27:e2:84:59:18",macaddr)) {
                    printf("Couldnt parse MacAddr\n");
                }
                return memcmp(macheader-> addr2,macaddr,6);
}
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_size) {
    size_t hex_len = strlen(hex);

    // 長さが偶数でなければ不正
    if (hex_len % 2 != 0) {
        return -1;
    }

    // bytes 配列のサイズチェック
    if (hex_len / 2 > bytes_size) {
        return -1;
    }

    for (size_t i = 0; i < hex_len; i += 2) {
        if (!isxdigit(hex[i]) || !isxdigit(hex[i + 1])) {
            return -1; // 不正な16進数文字列
        }
        // 2文字を1バイトに変換
        char byte_str[3] = {hex[i], hex[i + 1], '\0'};
        bytes[i / 2] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    return 0; // 成功
}

void parse_auth_response_attr(dpp_auth_response_attributes_t *response_attributes, const uint8_t *packet, int offset){
    memcpy(response_attributes->Attr_ID1, packet + offset, ATTR_ID_LEN);
    offset += ATTR_ID_LEN;
    memcpy(response_attributes->Attr_len1, packet + offset, ATTR_ID_LEN_LEN);
    offset += ATTR_ID_LEN_LEN;
    memcpy(response_attributes->DPP_Status, packet + offset, 1);
    offset += 1;
    memcpy(response_attributes->Attr_ID2, packet + offset, ATTR_ID_LEN);
    offset += ATTR_ID_LEN;
    memcpy(response_attributes->Attr_len2, packet + offset, ATTR_ID_LEN_LEN);
    offset += ATTR_ID_LEN;
    memcpy(response_attributes->Res_Boot_Hash, packet + offset, BOOT_KEY_LEN);
    offset += BOOT_KEY_LEN;
    memcpy(response_attributes->Attr_ID3, packet + offset, ATTR_ID_LEN);
    offset += ATTR_ID_LEN;
    memcpy(response_attributes->Attr_len3, packet + offset, ATTR_ID_LEN_LEN);
    offset += ATTR_ID_LEN_LEN;
    memcpy(response_attributes->Res_Proto_Key, packet + offset, PROT_KEY_LEN);
    offset += PROT_KEY_LEN;
    memcpy(response_attributes->Attr_ID4, packet + offset, ATTR_ID_LEN);
    offset += ATTR_ID_LEN;
    memcpy(response_attributes->Attr_len4, packet + offset, ATTR_ID_LEN_LEN);
    offset += ATTR_ID_LEN_LEN;
    memcpy(response_attributes->Wrapped_data, packet + offset, 117);
}


// 関数プロトタイプ
void create_dpp_auth_req_frame(uint8_t *frame, size_t *frame_len);
void generate_dpp_elements(uint8_t *public_key, uint8_t *nonce, uint8_t *auth_tag);
void unwraped(u8 *Res_prot_key_data, int key_len, u8 *wrapped_data, int wrapped_data_len, u8 *attr_start, int attr_len);
int gen_i_auth(u8 *i_auth);
void create_dpp_auth_conf_frame(uint8_t *frame, size_t *frame_len);
void create_dpp_conf_res_frame(uint8_t *frame, size_t *frame_len);

long long get_timestamp(){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (long long)ts.tv_sec * 1000000LL + (long long )ts.tv_nsec / 1000LL;
}

void init_timer(){
    start_time = (struct timespec){0};
    start_time.tv_sec = get_timestamp() /1000000LL;
    start_time.tv_nsec = (get_timestamp() % 10000000LL) * 1000LL;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
}



int main(int argc, char*argv[]) {
    init_timer();
    long long t_start, t_auth_req, t_auth_res, t_auth_conf, t_conf_req[6], t_conf_res;
    t_start = get_timestamp();

    if (argc != 5)
    {
        printf("Usage: %s <interface_name> <Pub_Boot_Key> <Enrollee-MAC_ADDR> <Configurator-MAC_ADDR>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *dev = argv[1];

    memcpy(auth.QR_Key, argv[2], 81);

    if (!parseMACAddress(argv[3], TARGET_MAC)) {
        printf("Invalid MAC address format.\n");
        return 1;
    }

    if (!parseMACAddress(argv[4], SRC_MAC)) {
        printf("Invalid MAC address format.\n");
        return 1;
    }

     // 使用するインターフェイス名
    // デバイスをオープン
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    const char *filename = "credential.json";
    config_length = read_file_to_byte_array(filename, configObj);


    // DPPアクションフレームを作成
    uint8_t frame[256];
    memset(frame, 0, 256);

    size_t frame_len;
    create_dpp_auth_req_frame(frame, &frame_len);
    //printf("start sending authentication request frame \n");
    // フレームを送信
    // flock をもちいて，ロック
    int lock_fd = open("./lockfile", O_CREAT | O_RDWR, 0666);
    if (lock_fd == -1)
    {
        printf("cant open file\n");
        return 1;
    }

    if(flock(lock_fd, LOCK_EX) == -1){
        perror("flock");
        close(lock_fd);
        return 1;
    }
    while (1) {
        for (size_t i = 0; i < 1; i++)
        {
            if (pcap_sendpacket(handle, frame, frame_len) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 2;
            }
            t_auth_req=get_timestamp();
            // 100ミリ秒待つ
            //usleep(100 * 1000);
        }

        // 返答フレームを待つ
        struct pcap_pkthdr *header0;
        const uint8_t *packet0;
        dpp_auth_response_attributes_t responce_attributes;

        int flag = 0;

        for (size_t i=0; i < 1000; i++)

        {
            int res = pcap_next_ex(handle, &header0, &packet0);
            int offset = 0;

            if (res == 1)
            {
                struct ieee80211_radiotap_header *auth_res_rtheader = (struct ieee80211_radiotap_header *)packet0;
                int rtap_len = auth_res_rtheader->it_len;
    
                // パケットを受信した場合、パケットの解析を行う
                if (compare_mac_addr(packet0) == 0 ){
                    t_auth_res=get_timestamp();
                    // パケットを構造体に格納

                    offset = rtap_len +IEEE80211_ACTION_FLAG_LEN +IEEE80211_ACTION_HEADER_LEN;

                    parse_auth_response_attr(&responce_attributes, packet0, offset);

                    memcpy(auth.Res_Proto_Key, responce_attributes.Res_Proto_Key, PROT_KEY_LEN);

                    // attr_start (Wrapped Data までのアトリビュート)
                    int attr_len = 3 * (ATTR_ID_LEN + ATTR_ID_LEN_LEN) + 1 + BOOT_KEY_LEN + PROT_KEY_LEN; 
                    u8 buf[attr_len];
                    memcpy(buf, packet0 + offset, attr_len);
                    unwraped(responce_attributes.Res_Proto_Key, PROT_KEY_LEN, responce_attributes.Wrapped_data, 117, buf, attr_len);


                    //printf("finish receving response frame\n");
                    goto confirm;

                }
            }
        }

        // 100ミリ秒待つ
        //usleep(100 * 1000);
    }
confirm:
    uint8_t frame2[256];
    size_t frame2_len;
    create_dpp_auth_conf_frame(frame2, &frame2_len);

    //printf("start sending Authentication confirm frame \n");

    if (pcap_sendpacket(handle, frame2, frame2_len) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }
    t_auth_conf = get_timestamp();

    struct pcap_pkthdr *header1;
    const uint8_t *packet1;
    uint8_t check[2];
    uint8_t len[2] = {0x6f, 0x00};
    uint8_t configreq[212];
    uint8_t wrapped_data[112];
    // configuration request frame が 4回届くため、4個目を指定するための flag
    int flag = 0;
    // // flock をもちいて，ロック
    // int lock_fd = open("./lockfile", O_CREAT | O_RDWR, 0666);
    // if (lock_fd == -1)
    // {
    //     printf("cant open file\n");
    //     return 1;
    // }

    // if(flock(lock_fd, LOCK_EX) == -1){
    //     perror("flock");
    //     close(lock_fd);
    //     return 1;
    // }
    

        for (size_t i=0; i < 1000; i++)
        {
            int res = pcap_next_ex(handle, &header1, &packet1);
            int offset = 0;
            if (res == 1)
            {
                struct ieee80211_radiotap_header *conf_req_rtheader = (struct ieee80211_radiotap_header *)packet1;
                int conf_req_rtap_len = conf_req_rtheader->it_len;

                // パケットを受信した場合、パケットの解析を行う
                if (compare_mac_addr(packet1)==0){
                    t_conf_req[flag] = get_timestamp();
                    offset = conf_req_rtap_len + IEEE80211_ACTION_FLAG_LEN + IEEE80211_GAS_HEADER_LEN + 4;
                    flag += 1;
                    // flag を1に変更
                    if (flag == 6)
                    {   
                        memcpy(check, packet1 + offset, 2);
                        if(memcmp(check, len, sizeof(check)) == 0){
                            memcpy(wrapped_data, packet1 + offset + 2, 111);
                            break;
                        }
                    }
                }
            }
        }
    
    // wrapped_data を ke で unwrap
    u8 * unwrapped_ke = NULL;
    size_t unwrapped_ke_len = 0;

    unwrapped_ke_len = 111 - AES_BLOCK_SIZE;
    unwrapped_ke = malloc(unwrapped_ke_len);
    if (aes_siv_decrypt(auth.ke, 32, wrapped_data, 111, 0, NULL, NULL, unwrapped_ke) < 0){
        printf("Decryption Failed");
    }

    //E-nonce と configRequest に切り分け
    u8 e_nonce[16];
    u8 configRequest[71];
    int offset = 4;
    memcpy(e_nonce, unwrapped_ke + offset, 16);
    offset += 16;
    memcpy(auth.E_nonce, e_nonce, 16);
    memcpy(configRequest, unwrapped_ke +offset + 4, 71);

    // configuration response frame を作成
    uint8_t frame3[250];
    size_t frame3_len;
    create_dpp_conf_res_frame(frame3, &frame3_len);
    
    // configuration response frame を送信
    //printf("start sending Configuration Response frame \n");

    if (pcap_sendpacket(handle, frame3, frame3_len) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }
    t_conf_res = get_timestamp();
    flock(lock_fd, LOCK_UN);
    pcap_close(handle);


    long long start_usec = (long long)start_time.tv_sec * 1000000LL + (long long)start_time.tv_nsec / 1000LL;

    printf("[TIME STAMP] Start dpp-configurator.c Time: %lld\n", t_start- start_usec);
    printf("[TIME STAMP] DPP_Authentication_Request Time: %lld\n", t_auth_req - start_usec);
    printf("[TIME STAMP] DPP_Authentication_Response Time: %lld\n", t_auth_res - start_usec);
    printf("[TIME STAMP] DPP_Authentication_Confirm Time: %lld\n", t_auth_conf - start_usec);
    printf("[TIME STAMP] DPP_Configuration_Request First Time: %lld\n", t_conf_req[0] - start_usec);
    printf("[TIME STAMP] DPP_Configuration_Request Last Time: %lld\n", t_conf_req[5] - start_usec);
    printf("[TIME STAMP] DPP_Configuration_Response Time: %lld\n", t_conf_res - start_usec);

    printf("[TIME STAMP] diff 1: %lld\n", t_auth_req- t_start);
    printf("[TIME STAMP] diff 2: %lld\n", t_auth_res - t_auth_req);
    printf("[TIME STAMP] diff 3: %lld\n", t_auth_conf - t_auth_res);
    printf("[TIME STAMP] diff 4: %lld\n", t_conf_req[0] - t_auth_conf);
    printf("[TIME STAMP] conf req diff: %lld\n", t_conf_req[5] - t_conf_req[0]);
    printf("[TIME STAMP] diff 5: %lld\n", t_conf_res - t_conf_req[5]);

    return 0;

}

void create_ieee80211_header(ieee80211_header_t *header, uint16_t sequence_ctrl) {
    header->frame_control[0] = 0xd0; // Management frame subtype (Action)
    header->frame_control[1] = 0x00;
    header->duration = 0x013a;
    uint8_t addr1[MAC_ADDR_LEN] = {0x34, 0x85, 0x18, 0x82, 0x4a, 0x28}; // Enrollee の MACアドレス 
    uint8_t addr2[MAC_ADDR_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}; // Configurator の MACアドレス
    uint8_t addr3[MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; 

    memcpy(header->addr1, TARGET_MAC, MAC_ADDR_LEN);
    memcpy(header->addr2, SRC_MAC, MAC_ADDR_LEN);
    memcpy(header->addr3, addr3, MAC_ADDR_LEN);
    header->sequence_control = sequence_ctrl;

}

void create_dpp_action_frame(dpp_action_frame_t *dpp_frame, uint8_t frame_type){
    dpp_frame -> category = 0x04; // Public Action frame
    dpp_frame -> action = 0x09;   // DPP
    dpp_frame -> oui[0] = 0x50;
    dpp_frame -> oui[1] = 0x6f;
    dpp_frame -> oui[2] = 0x9a;
    dpp_frame -> oui_type = 0x1a;
    dpp_frame -> crypto_suite = 0x01; // Crypto Suite (例: 0x01)
    dpp_frame -> frame_type = frame_type; 

}

void create_dpp_auth_req_frame(uint8_t *frame, size_t *frame_len) {
    // Radiotapヘッダの設定
    init_radiotap_header();
    set_channel_info(2437, 0x00a0);
    set_timestamp();
    set_flags(0x10);
    set_rate(0x02);
    //set_antenna(0x00);
    set_antsignal(0xe8);
    set_ts();
    rt_header.accuracy = 0x0016;
    rt_header.sp = 0x11;
    rt_header.af = 0x03;
    rt_header.as1 = 0xe8;
    rt_header.an1 = 0x00;
    
    // 802.11ヘッダの設定
    ieee80211_header_t ieee80211_header;

    create_ieee80211_header(&ieee80211_header, 0x0190);
    // DPPアクションフレームの設定
    dpp_action_frame_t dpp_frame;
    create_dpp_action_frame(&dpp_frame, 0x00);

    // Initiator Bootstrap Key
    const unsigned char Ini_Bootkey_data[] = {
        0x5d, 0x46, 0x7a, 0x09, 0x76, 0x02, 0x92, 0xfc,
        0x15, 0xd3, 0x17, 0x92, 0xb0, 0xa5, 0xb0, 0x50,
        0xdb, 0x8b, 0xf6, 0xad, 0x80, 0x7d, 0x71, 0xb2,
        0xd9, 0x3f, 0x4d, 0x1c, 0x2e, 0x65, 0xd8, 0x81

    };
    memcpy(auth.Ini_Boot_key, Ini_Bootkey_data, 32);

    // Initiator Protocol Key
    const unsigned char Ini_key_data[] = {
        0x00, 0xa8, 0x7d, 0xe9, 0xaf, 0xbb, 0x40, 0x6c, 0x96,
        0xe5, 0xf7, 0x9a, 0x3d, 0xf8, 0x95, 0xec, 0xac,
        0x3a, 0xd4, 0x06, 0xf9, 0x5d, 0xa6, 0x63, 0x14,
        0xc8, 0xcb, 0x31, 0x65, 0xe0, 0xc6, 0x17, 0x83
    };
    size_t Ini_key_len = sizeof(Ini_key_data);
    EC_KEY *Ini_key = NULL;
    Ini_key = create_ec_key_from_private_key_bytes(Ini_key_data, Ini_key_len);
    
    // 公開鍵のバイト列へのエンコード
     unsigned char *Ini_pub_key_bytes = NULL; // Initiator public key
     size_t pub_key_len = 0;
     if (!encode_ec_public_key(Ini_key, &Ini_pub_key_bytes, &pub_key_len)) {
         handleErrors();
     }
     memcpy(auth.Ini_Proto_Key, Ini_pub_key_bytes + 1, 64);

    // Responder Bootstrap key のハッシュを計算
    unsigned char Res_bootkey_hash[SHA256_DIGEST_LENGTH];
    size_t data_len;
    size_t key_len;
    //const char key[81] = "MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgACCcWFqRtN+f0loEUgGIXDnMXPrjl92u2pV97Ff6DjUD8="; // QRコードに書かれている文字列
    unsigned char *der_data;

    der_data = (unsigned char *)base64_gen_decode(auth.QR_Key, 81, &data_len, base64_table);

    if (sha256_vector(1, (const u8 **)&der_data, &data_len, Res_bootkey_hash))
    {
        printf("failed to ....\n");
    }
    memcpy(auth.Res_Boot_Key_Hash, Res_bootkey_hash, 32);

    // 非圧縮形式に変換
    u8 *pub_key  = create_ec_key_from_der(der_data, data_len, &key_len);

    memcpy(auth.Res_Boot_Key, pub_key + 1, 64);

    EC_KEY *Res_Boot_key = NULL;
    Res_Boot_key = convert_bytes_to_EC_KEY(pub_key, 65); //{64 + 1(非圧縮形式を示す 04)}

    // DPP Attribute の設定 
    dpp_attributes_t dpp_attribute;
    memcpy(dpp_attribute.header1 , "\x02\x10\x20\x00",4);
    memcpy(dpp_attribute.Res_boot_Hash ,auth.Res_Boot_Key_Hash,32);
    memcpy(dpp_attribute.header2, "\x01\x10\x20\x00",4);
    memcpy(dpp_attribute.Ini_boot_Hash, auth.Ini_Boot_key, 32);
    memcpy(dpp_attribute.header3, "\x03\x10\x40\x00",4);
    memcpy(dpp_attribute.Ini_P_Key , auth.Ini_Proto_Key, 64);
    memcpy(dpp_attribute.header5 , "\x04\x10\x29\x00",4);

    // Wrapped_data の準備

    // 共通秘密鍵Mxの計算
    unsigned char *secret = NULL;
    size_t secret_len = compute_ecdh_secret(Ini_key, Res_Boot_key, &secret);
    memcpy(auth.M_x, secret, secret_len);

    // HKDFで導出するキーの長さ（例：32バイト = 256ビット）
    size_t out_len = 32;
    unsigned char out_key[out_len];
    const char *info = "first intermediate key";

    // HKDFを使用してk1を導出
    derive_key_with_hkdf(secret, secret_len, out_key, out_len, info);

    // I-nonceの設定
    const unsigned char I_nonce[] = {0x13, 0xf4, 0x60, 0x2a, 0x16, 0xda, 0xeb, 0x69,
    0x71, 0x22, 0x63, 0xb9, 0xc4, 0x6c, 0xba, 0x31};
    size_t I_nonce_len = sizeof(I_nonce);
    memcpy(auth.I_nonce, I_nonce, I_nonce_len);

    // I-capabilitiesの設定
    const unsigned char I_capabilities[] = {0x02};
    size_t I_capabilities_len = sizeof(I_capabilities);

    unsigned char wrappeddata[4 + 16 + 4 + 1 + AES_BLOCK_SIZE];

    //OUI, OUI Type, Crypto Suite, DPP frame Type
    const u8 *addr[2];
    size_t len[2];
    u8 tmp[] = {0x50, 0x6f, 0x9a, 0x1a, 0x01, 0x00}; 
    addr[0] = tmp;
    len[0] = sizeof(tmp);

    // Data before wrapped data
    u8 before_wrapped_data[2 *(4 + 32) + 4 + 64  + sizeof(wrappeddata)];
    u8 *a;
    size_t offset = 0;

    memcpy(before_wrapped_data + offset, "\x02\x10\x20\x00",4);
    offset += 4;
    memcpy(before_wrapped_data + offset, auth.Res_Boot_Key_Hash,32);
    offset += 32;
    memcpy(before_wrapped_data + offset,  "\x01\x10\x20\x00",4);
    offset += 4;
    memcpy(before_wrapped_data + offset, auth.Ini_Boot_key, 32);
    offset += 32;
    memcpy(before_wrapped_data + offset,  "\x03\x10\x40\x00",4);
    offset += 4;
    memcpy(before_wrapped_data + offset, auth.Ini_Proto_Key, 64);
    offset += 64;
    addr[1] = before_wrapped_data;
    len[1] = offset;
    
    // テスト用の nonce や capabilities 
    u8 clear[4 + 16 + 4 + 1];
    u8 clear_data[4 + 16 + 4 + 1];
    size_t clear_data_len = 0;

    memcpy(clear_data + clear_data_len, "\x05\x10\x10\x00",4);
    clear_data_len += 4;
    memcpy(clear_data + clear_data_len, I_nonce, I_nonce_len);
    clear_data_len += I_nonce_len;
    memcpy(clear_data + clear_data_len, "\x06\x10\x01\x00",4);
    clear_data_len += 4;
    memcpy(clear_data + clear_data_len, I_capabilities, I_capabilities_len);
    clear_data_len += I_capabilities_len;
    // printf("Clear Data: ");
    // for (size_t i = 0; i < clear_data_len; i++) {
    //     printf("%02x", clear_data[i]);
    // }
    // printf("\n");
    
    // AES-SIV暗号化
    aes_siv_encrypt(out_key, out_len, clear_data,clear_data_len , 2, addr, len, wrappeddata);

    memcpy(dpp_attribute.Wrapped_data , wrappeddata, 41);

    // DPPアクションフレーム全体のサイズを計算
    uint8_t *ptr = frame;
    // Radiotapヘッダをコピー
    //memcpy(ptr, radiotap_header, sizeof(radiotap_header));
    //ptr += sizeof(radiotap_header);

    memcpy(ptr, &rt_header, sizeof(rt_header));
    ptr += sizeof(rt_header);
    // 802.11ヘッダをコピー
    memcpy(ptr, &ieee80211_header, sizeof(ieee80211_header_t));
    ptr += sizeof(ieee80211_header_t);
    // DPPアクションフレームをコピー
    memcpy(ptr, &dpp_frame, sizeof(dpp_action_frame_t));
    ptr += sizeof(dpp_action_frame_t);
    // DPP Attribute をコピー
    memcpy(ptr, &dpp_attribute, sizeof(dpp_attributes_t));
    ptr += sizeof(dpp_attributes_t);
    // FCS
    *ptr = 0x00;
    ptr += 1;
    *ptr = 0x00;
    ptr += 1;
    *ptr = 0x00;
    ptr += 1;
    *ptr = 0x00;
    ptr += 1;


    *frame_len = ptr - frame; // フレーム全体の長さを計算
    // メモリの解放
    OPENSSL_free(secret);
    EC_KEY_free(Ini_key);
    EC_KEY_free(Res_Boot_key);
}
void unwraped(u8 *Res_prot_key_data, int key_len, u8 *wrapped_data, int wrapped_data_len, u8 *attr_start, int attr_len){
    //printf("start unwrap\n\n\n");
    // Initiator Protocol Key
    const unsigned char Ini_key_data[] = {
        0x00, 0xa8, 0x7d, 0xe9, 0xaf, 0xbb, 0x40, 0x6c, 0x96,
        0xe5, 0xf7, 0x9a, 0x3d, 0xf8, 0x95, 0xec, 0xac,
        0x3a, 0xd4, 0x06, 0xf9, 0x5d, 0xa6, 0x63, 0x14,
        0xc8, 0xcb, 0x31, 0x65, 0xe0, 0xc6, 0x17, 0x83
    };
    size_t Ini_key_len = sizeof(Ini_key_data);
    EC_KEY *Ini_key = NULL;
    Ini_key = create_ec_key_from_private_key_bytes(Ini_key_data, Ini_key_len);

    if (EC_KEY_check_key(Ini_key) == 0){
        printf("Invalid Ini_key\n");
    }


    // 公開鍵のバイト列へのエンコード
     unsigned char *Ini_pub_key_bytes = NULL; // Initiator public key
     size_t pub_key_len = 0;
     if (!encode_ec_public_key(Ini_key, &Ini_pub_key_bytes, &pub_key_len)) {
         handleErrors();
     }

    // Responder Protocol Key
    EC_KEY *Res_Prot_Key = NULL;
    u8 *buf = (u8 *)malloc(key_len + 1);
    buf[0] = 0x04;
    memcpy(buf +1 , Res_prot_key_data, key_len);
    
    Res_Prot_Key = convert_bytes_to_EC_KEY(buf, key_len + 1);

     if (EC_KEY_check_key(Res_Prot_Key) == 0){
        printf("Res_Prot_Key\n");
    }


    // 共通秘密 Nx の計算
    u8 *secret = NULL;
    size_t secret_len = compute_ecdh_secret(Ini_key, Res_Prot_Key, &secret);
    memcpy(auth.N_x, secret, secret_len);

    // HKDFで導出するキーの長さ（例：32バイト = 256ビット）
    size_t out_len = 32;
    unsigned char out_key[out_len];
    u8 *info = "second intermediate key";

    // HKDFを使用してk2を導出
    derive_key_with_hkdf(secret, secret_len, out_key, out_len, info);

    //OUI, OUI Type, Crypto Suite, DPP frame Type
    const u8 *addr[2];
    size_t len[2];
    u8 tmp[] = {0x50, 0x6f, 0x9a, 0x1a, 0x01, 0x01}; 
    addr[0] = tmp;
    len[0] = sizeof(tmp);

    // Data before wrapped data
    addr[1] = attr_start;
    len[1] = attr_len;

    // decrypt
    u8 *unwrapped = NULL;
    size_t unwrapped_len = 0;

    unwrapped_len = wrapped_data_len - AES_BLOCK_SIZE;
    unwrapped = malloc(unwrapped_len);

    if(aes_siv_decrypt(out_key, out_len, wrapped_data, wrapped_data_len, 2, addr, len, unwrapped)< 0){
        printf("failed to decrypt\n");
    }
    
    // unwrap したデータを構造体に格納
    data_unwrapped_with_k2 unwraped_with_k2;
    size_t offset = 0;

    memcpy(unwraped_with_k2.Attr_ID1, unwrapped + offset, ATTR_ID_LEN);
    offset += 2;
    memcpy(unwraped_with_k2.Attr_len1, unwrapped + offset, ATTR_ID_LEN_LEN);
    offset += 2;
    memcpy(unwraped_with_k2.R_nonce, unwrapped + offset, 16);
    offset += 16;
    memcpy(unwraped_with_k2.Attr_ID2, unwrapped + offset, ATTR_ID_LEN);
    offset += ATTR_ID_LEN;
    memcpy(unwraped_with_k2.Attr_len2, unwrapped + offset, ATTR_ID_LEN_LEN);
    offset += ATTR_ID_LEN;
    memcpy(unwraped_with_k2.I_nonce, unwrapped + offset, 16);
    offset += 16;
    memcpy(unwraped_with_k2.Attr_ID3, unwrapped + offset, ATTR_ID_LEN);
    offset += ATTR_ID_LEN;
    memcpy(unwraped_with_k2.Attr_len3, unwrapped + offset, ATTR_ID_LEN_LEN);
    offset += ATTR_ID_LEN_LEN;
    memcpy(unwraped_with_k2.R_capability, unwrapped + offset, 1);
    offset += 1;
    memcpy(unwraped_with_k2.Attr_ID4, unwrapped + offset, ATTR_ID_LEN);
    offset += ATTR_ID_LEN;
    memcpy(unwraped_with_k2.Attr_len4, unwrapped + offset, ATTR_ID_LEN_LEN);
    offset += ATTR_ID_LEN_LEN;
    memcpy(unwraped_with_k2.Wrapped_data, unwrapped + offset, 52);
    offset += 52;
    memcpy(auth.R_nonce, unwraped_with_k2.R_nonce, 16);

    // ke を求める
    u8 ke[32];
    const char *info_ke = "DPP Key";
    u8 nonces[2 * 16];
    u8 prk[64];
    int res;
    const u8 *addr_2[3];
    size_t len_2[3];
    size_t num_elem = 0;

    // nonceの設定 <= 今回は取得したパケットから I-nonce を設定
    //               本来，自身で作成した I-nonce を設定
    memcpy(nonces, unwraped_with_k2.I_nonce, 16);
    memcpy(&nonces[16], unwraped_with_k2.R_nonce, 16);

    addr[num_elem] = auth.M_x;
    len[num_elem] = 32;
    num_elem ++;
    addr[num_elem] = auth.N_x;
    len[num_elem] = 32;
    num_elem ++;

    res = hmac_sha256_vector(nonces, 2* 16, num_elem, addr, len, prk);
    if (res < 0) printf("failed to make vector\n");
    //debug_print("DPP: PRK", 32, prk);

    res = hmac_sha256_kdf(prk, 32, NULL, (const u8 *) info_ke, strlen(info_ke), ke, 32);
    if (res < 0) printf("failed to Expand ke");
    memcpy(auth.ke, ke, 32);

    // ke で R-auth を decrypt
    u8 * unwrapped2 = NULL;
    size_t unwrapped2_len = 0;

    unwrapped2_len = 52 - AES_BLOCK_SIZE;
    unwrapped2 = malloc(unwrapped_len);

    if (aes_siv_decrypt(ke, 32, unwraped_with_k2.Wrapped_data, 52, 0, NULL, NULL, unwrapped2) < 0){
        printf("Decryption Failed");
    }
    
    // i_auth を生成
    int a;
    u8 i_auth[64];
    a = gen_i_auth(i_auth);
}
int gen_i_auth(u8 *i_auth){
    const u8 *addr[7];
    size_t len[7];
    size_t i, num_elem = 0;
    size_t nonce_len;
    u8 one = 1;
    int res = -1;

    nonce_len = 16;

    addr[num_elem] = auth.R_nonce;
    len[num_elem] = nonce_len;
    num_elem++;

    addr[num_elem] = auth.I_nonce;
    len[num_elem] = nonce_len;
    num_elem++;

    addr[num_elem] = auth.Res_Proto_Key;
    len[num_elem] = SHA256_MAC_LEN;
    num_elem++;

    addr[num_elem] = auth.Ini_Proto_Key;
    len[num_elem] = SHA256_MAC_LEN;
    num_elem++;

    addr[num_elem] = auth.Res_Boot_Key;
    len[num_elem] = SHA256_MAC_LEN;
    num_elem++;

    addr[num_elem] = &one;
    len[num_elem] = 1;
    num_elem++;

    res = sha256_vector(num_elem, addr, len, i_auth);
    if(res == 0){
        //debug_print("I-auth", 32, i_auth);
    }

    memcpy(auth.I_auth, i_auth, 32);

    return 0;
}
void create_dpp_auth_conf_frame(uint8_t *frame, size_t *frame_len){

    ieee80211_header_t ieee80211_header;
    create_ieee80211_header(&ieee80211_header, 0x0f40);
    // DPPアクションフレームの設定
    dpp_action_frame_t dpp_frame;
    create_dpp_action_frame(&dpp_frame, 0x02);

    // DPP Attribute の設定 
    dpp_confirm_attributes_t dpp_confirm_attributes;
    memcpy(dpp_confirm_attributes.Attr_ID1, "\x00\x10", 2);
    memcpy(dpp_confirm_attributes.Attr_len1, "\x01\x00", 2);
    memcpy(dpp_confirm_attributes.DPP_Status, "\x00", 1);
    memcpy(dpp_confirm_attributes.Attr_ID2, "\x02\x10", 2);
    memcpy(dpp_confirm_attributes.Attr_len2, "\x20\x00", 2);
    memcpy(dpp_confirm_attributes.Res_Boot_Hash, auth.Res_Boot_Key_Hash,32);
    //debug_print("Res_boot", 32, dpp_confirm_attributes.Res_Boot_Hash);

    // Data wrapped with ke の準備
    unsigned char wrappeddata[4 + 32 +  AES_BLOCK_SIZE];
    u8 before_wrapped_data[ 4 + 1 + 4 + 32 + sizeof(wrappeddata)];

    const u8 *addr[2];
    size_t len[2];

    u8 tmp[] = {0x50, 0x6f, 0x9a, 0x1a, 0x01, 0x02}; 
    addr[0] = tmp;
    len[0] = sizeof(tmp);

    size_t offset = 0;
    memcpy(before_wrapped_data + offset, dpp_confirm_attributes.Attr_ID1, 2);
    offset += 2;
    memcpy(before_wrapped_data + offset, dpp_confirm_attributes.Attr_len1, 2);
    offset += 2;
    memcpy(before_wrapped_data + offset, dpp_confirm_attributes.DPP_Status, 1);
    offset += 1;
    memcpy(before_wrapped_data + offset, dpp_confirm_attributes.Attr_ID2, 2);
    offset += 2;
    memcpy(before_wrapped_data + offset, dpp_confirm_attributes.Attr_len2, 2);
    offset += 2;
    memcpy(before_wrapped_data + offset, dpp_confirm_attributes.Res_Boot_Hash, 32);
    offset += 32;

    addr[1] = before_wrapped_data;
    len[1] = offset;

    u8 clear[36];
    memcpy(clear, "\x0a\x10", 2);
    memcpy(clear + 2, "\x20\x00", 2);
    memcpy(clear + 4, auth.I_auth, 32);

    if (aes_siv_encrypt(auth.ke, 32, clear, 36, 2, addr, len, wrappeddata) < 0)
    {
        printf("failed to encrypt");
    }
    
    //debug_print("Data wrapped with ke", 52, wrappeddata);

    memcpy(dpp_confirm_attributes.Attr_ID3, "\x04\x10", 2);
    memcpy(dpp_confirm_attributes.Attr_len3, "\x34\x00", 2);
    memcpy(dpp_confirm_attributes.Wrapped_data, wrappeddata, 52);


    // DPPアクションフレーム全体のサイズを計算
    uint8_t *ptr = frame;
    // Radiotapヘッダをコピー
    // memcpy(ptr, radiotap_header, sizeof(radiotap_header));
    // ptr += sizeof(radiotap_header);
    memcpy(ptr, &rt_header, sizeof(rt_header));
    ptr += sizeof(rt_header);
    // 802.11ヘッダをコピー
    memcpy(ptr, &ieee80211_header, sizeof(ieee80211_header_t));
    ptr += sizeof(ieee80211_header_t);
    // DPPアクションフレームをコピー
    memcpy(ptr, &dpp_frame, sizeof(dpp_action_frame_t));
    ptr += sizeof(dpp_action_frame_t);
    // DPP Attribute をコピー
    memcpy(ptr, &dpp_confirm_attributes, sizeof(dpp_confirm_attributes_t));
    ptr += sizeof(dpp_confirm_attributes_t);

    // FCS
    *ptr = 0x00;
    ptr += 1;
    *ptr = 0x00;
    ptr += 1;
    *ptr = 0x00;
    ptr += 1;
    *ptr = 0x00;
    ptr += 1;

    *frame_len = ptr - frame; // フレーム全体の長さを計算
}
void create_dpp_conf_res_frame(uint8_t *frame, size_t *frame_len){
    ieee80211_header_t ieee80211_header;
    create_ieee80211_header(&ieee80211_header, 0x03f0);
    dpp_action_frame2_t dpp_frame;
    // TODO 関数化しておく
    dpp_frame.category = 0x04; // Public Action frame
    dpp_frame.action = 0x0b;  
    dpp_frame.dialog = 0x00;
    dpp_frame.status = 0x0000;
    dpp_frame.delay = 0x0000;
    dpp_frame.tag_num = 0x6c;
    dpp_frame.tag_len = 0x08;
    dpp_frame.PAME_BI = 0x7f;
    dpp_frame.id = 0xdd;
    dpp_frame.vs_len = 0x05;
    dpp_frame.oui[0] = 0x50;
    dpp_frame.oui[1] = 0x6f;
    dpp_frame.oui[2] = 0x9a;
    dpp_frame.oui_type = 0x1a;
    dpp_frame.frame_type = 0x01;
    dpp_frame.Query_len =0x0095;

    // DPP Attribute の設定 
    dpp_configuration_response_t dpp_response;
    memcpy(dpp_response.Attr_ID1, "\x00\x10", 2);
    memcpy(dpp_response.Attr_len1, "\x01\x00", 2);
    memcpy(dpp_response.DPP_Status, "\x00",1);
    memcpy(dpp_response.Attr_ID2, "\x04\x10", 2);
    memcpy(dpp_response.Attr_len2, "\x8c\x00", 2);

    // configObject の用意
    // u8 configObj[Confsize];
    // size_t size = 0;

    // const char *filename = "credential.json";
    // size_t length = read_file_to_byte_array(filename, configObj);

    u8 clear_data[124];
    int offset = 0;
    memcpy(clear_data, "\x14\x10", 2);
    offset += 2;
    memcpy(clear_data + offset, "\x10\x00", 2);
    offset += 2;
    memcpy(clear_data + offset, auth.E_nonce, 16);
    offset += 16;
    memcpy(clear_data + offset, "\x0c\x10", 2);
    offset += 2;
    memcpy(clear_data + offset, "\x64\x00", 2);
    offset += 2;
    memcpy(clear_data + offset, configObj, 100);

    // Data wrapped with ke の準備
    u8 wrappeddata[124 + AES_BLOCK_SIZE];

    u8 tmp[] = {0x00, 0x10, 0x01, 0x00, 0x00};

    const u8 *addr[1];
    size_t len[1];

    addr[0] = tmp;
    len[0] = sizeof(tmp);


    if(aes_siv_encrypt(auth.ke, 32, clear_data, 124, 1, addr, len, wrappeddata) < 0){
        printf("failed to encrypt \n");
    }

    memcpy(dpp_response.Wrapped_data, wrappeddata, 140);

    // DPPアクションフレーム全体のサイズを計算
    uint8_t *ptr = frame;
    // Radiotapヘッダをコピー
    memcpy(ptr, &rt_header, sizeof(rt_header));
    ptr += sizeof(rt_header);
    // 802.11ヘッダをコピー
    memcpy(ptr, &ieee80211_header, sizeof(ieee80211_header_t));
    ptr += sizeof(ieee80211_header_t);
    // DPPアクションフレームをコピー
    memcpy(ptr, &dpp_frame, sizeof(dpp_action_frame2_t));
    ptr += sizeof(dpp_action_frame2_t);
    // アトリビュートをコピー
    memcpy(ptr, &dpp_response, sizeof(dpp_configuration_response_t));
    ptr += sizeof(dpp_configuration_response_t);
    
    *ptr = 0x00;
    ptr += 1;
    *ptr = 0x00;
    ptr += 1;
    *ptr = 0x00;
    ptr += 1;
    *ptr = 0x00;
    ptr += 1;

    *frame_len = ptr - frame; // フレーム全体の長さを計算
    
}
