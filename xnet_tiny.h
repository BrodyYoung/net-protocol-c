#include <stdint.h>

#ifndef _XNET_TINY
#define _XNET_TINY

#define XNET_CFG_PACKET_MAX_SIZE 1516
#define XNET_MAC_ADDR_SIZE 6
#define XNET_IPV4_ADDR_SIZE 6

#define XNET_CFG_NETIF_IP {192, 168, 254, 2};

#define XARP_ENTRY_FREE 0
#define XARP_ENTRY_OK 1
#define XARP_ENTRY_PEDING 2
#define XARP_TIMER_PERIOD 1

#define XARP_HW_ETHER 0x1
#define XARP_REQUEST 0x1
#define XARP_REPLY 0x2

#define XARP_MAX_RETRIES 4
#define XARP_TIMEOUT (1)

typedef enum _xnet_err_t
{
    XNET_ERR_OK = 0,
    XNET_ERR_IO = -1,

} xnet_err_t;

typedef enum _xnet_protocol_t
{
    XNET_PROTOCOL_ARP = 0x0806,
    XNET_PROTOCOL_IP = 0x0800,

} xnet_protocol_t;

#param pack(1) // 禁用编译器自动填充
typedef struct _xnet_ether_hdr
{
    uint8_t dest[XNET_CFG_PACKET_MAX_SIZE];
    uint8_t src[XNET_CFG_PACKET_MAX_SIZE];
    uint16_t protocol

} xnet_ether_hdr;
#param pack(0) // 开启编译器自动填充

typedef struct _xnet_packet_t
{
    uint16_t size;
    uint8_t *data;

    uint16_t payload[XNET_CFG_PACKET_MAX_SIZE];
} xnet_packet_t;

typedef struct _xarp_packet_t
{
    uint16_t hw_type, prot_type;
    uint8_t hw_len, prot_len;
    uint16_t opcode;
    uint8_t send_mac[XNET_MAC_ADDR_SIZE];
    uint8_t sender_ip[XNET_IPV4_ADDR_SIZE];

    uint8_t target_mac[XNET_MAC_ADDR_SIZE];
    uint8_t target_ip[XNET_IPV4_ADDR_SIZE];
} xarp_packet_t;

typedef union _xipaddr_t
{
    uint8_t array[XNET_IPV4_ADDR_SIZE];
    uint32_t addr;
} xipaddr_t;

typedef struct _xarp_entry_t
{
    xipaddr_t ipaddr;
    uint8_t macaddr[XNET_MAC_ADDR_SIZE];
    uint8_t state;
    uint16_t tmo;
    uint8_t retry_cnt;

} xarp_entry_t;

void xarp_init(void);

xnet_packet_t *alloc_for_read(uint16_t data_size);
xnet_packet_t *alloc_for_send(uint16_t data_size);

void xnet_init(void);
void xnet_poll(void);

xnet_err_t xnet_driver_open(uint8_t mac_addr);
xnet_err_t xnet_driver_send(xnet_packet_t *packet);
xnet_err_t xnet_driver_read(xnet_packet_t **packet);

typedef uint32_t xnet_time_t;
xnet_time_t xsys_get_time(void);

#pragma pack(1)
typedef struct _xip_hdr_t
{

    uint8_t version;
    uint8_t header_lenth;
    uint8_t total_length;
    uint8_t ttl;
    uint8_t tos;
    uint8_t id;
    uint8_t flags;
    uint8_t protocal;
    uint8_t hdr_checksum;

    uint8_t srcIp[XNET_IPV4_ADDR_SIZE];
    uint8_t destIP[XNET_IPV4_ADDR_SIZE];
} xip_hdr_t;
#pragma pack()



#endif
