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

#define XTCP_CFG_MAX_TCP 40

typedef enum _xnet_err_t
{
    XNET_ERR_OK = 0,
    XNET_ERR_IO = -1,
    XNET_ERR_BINDED = -4,

} xnet_err_t;

typedef enum _xnet_protocol_t
{
    XNET_PROTOCOL_ARP = 0x0806,
    XNET_PROTOCOL_IP = 0x0800,
    XNET_PROTOCOL_ICMP = 1,
    XNET_PROTOCOL_IP = 17,
    XNET_PROTOCOL_TCP = 6,

} xnet_protocol_t;

#pragma pack(1) // 禁用编译器自动填充
typedef struct _xnet_ether_hdr
{
    uint8_t dest[XNET_CFG_PACKET_MAX_SIZE];
    uint8_t src[XNET_CFG_PACKET_MAX_SIZE];
    uint16_t protocol

} xnet_ether_hdr;
#pragma pack(0) // 开启编译器自动填充

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

xnet_err_t xnet_driver_open(uint8_t *mac_addr);
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

    uint8_t srcIP[XNET_IPV4_ADDR_SIZE];
    uint8_t destIP[XNET_IPV4_ADDR_SIZE];
} xip_hdr_t;
#pragma pack()

xnet_err_t xip_out(xnet_protocol_t *protocol, xipaddr_t *dest_ip, xnet_packet_t *packet);

typedef struct _xtcp_t xtcp_t;

typedef xnet_err_t (*xtcp_handler_t)(xtcp_t *tcp, xtcp_conn_state_t event);

typedef enum _xtcp_conn_state_t
{
    XTCP_CONN_CONNECTED,
    XTCP_CONN_DATA_RECV,
    XTCP_CONN_CLOSED,
} xtcp_conn_state_t;

typedef enum _xtcp_state_t
{
    XTCP_STATE_FREE,
    XTCP_STATE_CLOSED,
    XTCP_STATE_LISTEN,
} xtcp_state_t;

typedef struct _xtcp_t
{
    xtcp_state_t state;
    uint16_t local_port, remote_port;
    xipaddr_t remote_ip;
    xtcp_handler_t handler;
} xtcp_t;

#pragma pack(1)
typedef struct _xtcp_hdr_t
{
    uint16_t src_port, dest_port;
    uint32_t seq, ack;
#define XTCP_FLAG_FIN (1 << 0)
#define XTCP_FLAG_SYN (1 << 1)
#define XTCP_FLAG_RST (1 << 2)
#define XTCP_FLAG_ACK (1 << 4)
    union
    {
        struct
        {
            uint16_t flags : 6;
            uint16_t reserved : 6;
            uint16_t hdr_len : 4;
        };
        uint16_t all;
    } hdr_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;

} xtcp_hdr_t;
#pragma pack(0)

void xtcp_init(void);
void xtcp_in(xipaddr_t *remote_ip, xnet_packet_t *packet);

xtcp_t *xtcp_open(xtcp_handler_t *handler);
xnet_err_t xtcp_close(xtcp_t *tcp);
xnet_err_t xtcp_bind(xtcp_t *tcp, uint16_t local_port);
xnet_err_t xtcp_listen(xtcp_t *tcp);
#define XUDP_CFG_MAX_UDP 10
struct _xudp_t
{
    enum
    {
        XUDP_STATE_FREE,
        XUDP_STATE_USED
    } state;

    uint16_t local_port;
    xudp_handler handler;
}xudp_t;

void xudp_init(void);
xudp_t *xudp_open(xudp_handler_t handler);
void xudp_close(uint16_t *udp);
xudp_t *xudp_find(uint16_t port);
xnet_err_t xudp_bind(xudp_t *udp, uint8_t port);

#define XNET_IP_DEFAULT_TTL = 60
#endif
