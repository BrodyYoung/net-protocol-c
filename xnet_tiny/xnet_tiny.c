#include "xnet_tiny.h"
#include <stdint.h>
#include <time.h>

/* ------------------通用------------------*/

#define min(a, b) ((a) > (b) ? (b) : (a));

// 交换大小端
#define swap_order16(v) ((v & 0xFF) << 8 | (v >> 8) & 0xFF)

uint32_t swap_order32(uint32_t v)
{
    uint8_t *v_array = (uint8_t *)&v;
    uint8_t temp;

    temp = v_array[0];
    v_array[0] = v_array[3];
    v_array[3] = temp;

    temp = v_array[1];
    v_array[1] = v_array[2];
    v_array[2] = temp;
    return v;
}

// 获取系统时间，单位秒
xnet_time_t xsys_get_time()
{
    return clock() / CLOCKS_PER_SEC;
}

// 发送使用tx_packet，接收使用rx_packet
static xnet_packet_t tx_packet, rx_packet;

static const xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP;
static const uint8_t mac_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t ether_broadcast;

// 分配接收数据包
xnet_packet_t *xnet_alloc_for_read(uint16_t data_size)
{
    rx_packet.data = rx_packet.payload;
    rx_packet.size = data_size;
    // 返回包的起始地址
    return &rx_packet;
}

// 分配发送数据包
xnet_packet_t *xnet_alloc_for_send(uint16_t data_size)
{
    tx_packet.data = tx_packet.payload + XNET_CFG_PACKET_MAX_SIZE - data_size;
    tx_packet.size = data_size;
    // 返回包的起始地址
    return &tx_packet;
}

// 添加包头
static void add_header(xnet_packet_t *packet, uint16_t header_size)
{
    packet->data -= header_size;
    packet->size += header_size;
}

// 删除包头
static void remove_header(xnet_packet_t *packet, uint16_t header_size)
{
    packet->data += header_size;
    packet->size -= header_size;
}

// 截断包头
static void truncate_packet(xnet_packet_t *packet, uint16_t size)
{
    packet->size = min(packet->size, size);
}

void xnet_init()
{
    ethernet_init();
    xarp_init();
    xip_init();
    xicmp_init();
    xudp_init();
}
/* ------------------以太网协议------------------*/
// 初始化以太网协议
static xnet_err_t ethernet_init(void)
{
    xnet_err_t err = xnet_driver_open(netif_mac);
    if (err < 0)
    {
        return err;
    }

    return xarp_make_request(&netif_ipaddr);
}

static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];
// 以太网协议输出
static xnet_err_t ethernet_out_to(uint8_t protocol, uint8_t mac_addr, xnet_packet_t *packet)
{
    xnet_ether_hdr *ether_hdr;
    add_header(packet, sizeof(xnet_ether_hdr));

    ether_hdr = (xnet_ether_hdr *)packet->data;
    memcpy(ether_hdr->dest, mac_addr, XNET_MAC_ADDR_SIZE);
    memcpy(ether_hdr->src, netif_mac, XNET_MAC_ADDR_SIZE);
    ether_hdr->protocol = protocol;
    return xnet_driver_send(packet);
}

// 以太网协议输入
static void ethernet_in(xnet_packet_t *packet)
{
    xnet_ether_hdr *ether_hdr;
    uint16_t protocol;
    if (packet->size <= sizeof(xnet_ether_hdr))
    {
        return;
    }

    ether_hdr = (xnet_ether_hdr *)packet->data;
    protocol = swap_order16(ether_hdr->protocol);
    switch (protocol)
    {
    case XNET_PROTOCOL_ARP:
        break;

    case XNET_PROTOCOL_IP:
        break;
    }
}

// 以太网协议轮询
static void ethernet_poll()
{
    xnet_packet_t *packet;
    if (xnet_driver_read(&packet) == XNET_ERR_OK)
    {
        ethernet_in(packet);
    }
}

void xnet_poll()
{
    ethernet_poll();
}

/* ------------------ARP协议------------------*/

static xarp_entry_t arp_entry;

// 初始化ARP协议
void xarp_init(void)
{
    arp_entry.state = XARP_ENTRY_FREE;
}

// ARP协议输入
void xarp_in(){

};

// 创建ARP协议请求
int xarp_make_request(const xipaddr_t *ipaddr)
{
    xnet_packet_t *packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t *arp_packet = (xarp_packet_t *)packet->data;

    arp_packet->hw_type = XARP_HW_ETHER;
    arp_packet->prot_type = swap_order16(XNET_PROTOCOL_IP);
    arp_packet->hw_len = XNET_MAC_ADDR_SIZE;
    arp_packet->prot_len = XNET_IPV4_ADDR_SIZE;
    arp_packet->opcode = swap_order16(XARP_REQUEST);

    memcpy(arp_packet->send_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memcpy(arp_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->target_ip, ipaddr->array, XNET_IPV4_ADDR_SIZE);

    return ethernet_out_to(XNET_PROTOCOL_ARP, ether_broadcast, packet);
}

// 创建ARP协议响应
int xarp_make_response(const xipaddr_t *ipaddr)
{
    xnet_packet_t *packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t *response_packet = (xarp_packet_t *)packet->data;

    response_packet->hw_type = XARP_HW_ETHER;
    response_packet->prot_type = swap_order16(XNET_PROTOCOL_IP);
    response_packet->hw_len = XNET_MAC_ADDR_SIZE;
    response_packet->prot_len = XNET_IPV4_ADDR_SIZE;
    response_packet->opcode = swap_order16(XARP_REQUEST);

    memcpy(response_packet->send_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memcpy(response_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->target_ip, ipaddr->array, XNET_IPV4_ADDR_SIZE);

    return ethernet_out_to(XNET_PROTOCOL_ARP, response_packet->send_mac, packet);
}

// xnet_err_t xarp_resolve(const xipaddr_t * )

const xarp_entry_t arp_entry;

// ARP协议轮询
void xarp_poll(void)
{
    if (xnet_check_tmo())
    {
        switch (arp_entry.state)
        {
        case XARP_ENTRY_OK:
            if (--arp_entry.tmo == 0)
            {
                xarp_make_request(&arp_entry.ipaddr);
                arp_entry.state = XARP_ENTRY_PEDING;
                arp_entry.tmo = XARP_TIMEOUT;
            }
            break;
        case XARP_ENTRY_PEDING:
            if (--arp_entry.tmo == 0)
            {
                if (arp_entry.retry_cnt-- == 0)
                {
                    arp_entry.state = XARP_ENTRY_FREE;
                }
                else
                {
                    make_request(&arp_entry.ipaddr);
                    arp_entry.state = XARP_ENTRY_PEDING;
                    arp_entry.tmo = XARP_TIMEOUT;
                }
            }
            break;
        }
    }
}

/* ------------------IP协议------------------*/

// 初始化IP协议
void xip_init()
{
}

// IP协议输入
void xip_in()
{
}

// IP协议输出
xnet_err_t xip_out(xnet_protocol_t *protocol, xipaddr_t *dest_ip, xnet_packet_t *packet)
{
    xip_hdr_t *iphdr;
    add_header(packet, sizeof(xip_hdr_t));
    iphdr = (xip_hdr_t *)packet->data;

    iphdr->hdr_checksum = 0;
    iphdr->header_lenth = sizeof(packet);
    iphdr->id = swap_order16(ip_packet_id);
    iphdr->header_lenth = sizeof(xip_hdr_t) / 4;
    iphdr->total_length = swaporder16(packet->size);
    iphdr->protocal = XNET_PROTOCOL_IP;
    iphdr->tos = 0;
    iphdr->ttl = XNET_IP_DEFAULT_TTL;

    iphdr->flags_fragment = 0;
    iphdr->version - XNET_VERSION_IPV4;
    memcpy(iphdr->srcIP, &netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memcpy(iphdr->destIP, dest_ip.array, XNET_IPV4_ADDR_SIZE);
    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = check_sum16((uint16_t *)iphdr, saizeof(xip_hdr_t), 0, 1);
    ip_packet_id++;
}

static xnet_err_t ethernet_out(xipaddr_t *dest_ip, xnet_packet_t *packet)
{
    xnet_err_t err;
    uint8_t *mac_addr;
}

/* ------------------UDP协议------------------*/

void xudp_init(void)
{
    memset(udp_socket, 0, sizeof(udp_socket));
}

xudp_t *xudp_open(xudp_handler_t handler)
{
    xudp_t *udp, *end;
    for (udp = udp_socket, end = &udp_socket[XUDP_CFG_MAX_UDP]; udp < end; udp++)
    {
        if (udp->state == XUDP_STATE_FREE)
        {
            udp->state = XUDP_STATE_USED;
            udp->local_port = 0;
            udp->handler = handler;
            return udp;
        }
    }
    return (xudp_t *)0;
}

void xudp_close(uint16_t *udp)
{
    udp->state = XUDP_STATE_FREE;
}

xudp_t *xudp_find(uint16_t port)
{
    xudp_t *curr, *end;
    for (curr = udp_socket, end = &udp_socket[XUDP_CFG_MAX_UDP], curr < end; curr++)
    {
        if (curr->state == XUDP_STATE_USED && curr->local_port == port)
        {
            return curr;
        }
    }
    return (xudp_t *)0;
}

static xnet_err_t tcp_send_reset(uint32_t remote_ack, uint16_t local_port, xipaddr_t *remote_ip, uint16_t remote_port)
{
    xnet_packet_t *packet = xnwet_alloc_for_send(siozeof(xnet_hdr_t));

    xtcp_hdr_t *tcp_hdr = (xtcp_hdr_t *)packet->data;

    tcp_hdr->src_port = swap_order16(local_port);
    tcp_hdr->dest_port = swap_order16(remote_port);
    tcp_hdr->seq = swap(order16(local_port));

    tcp_hdr->ack = swap_order32(remote_ack);
    tcp_hdr->hdr_flags.all = 0;

    tcp_hdr->hdr_flags.hdr_len = sizeof(xtcp_hdr_t) / 4; // 4个字节为一单位
    tcp_hdr->hdr_flags.flags = XTCP_FLAG_RST | XTCP_FLAG_ACK;
    tcp_hdr->hdr_flags.all = swap_order16(tcp_hdr->hdr_flags.all);

    tcp_hdr->window = 0;
    tcp_hdr->checksum = 0;
    tcp_hdr->urgent_ptr = 0;
    tcp_hdr->checksum = checksum_peso(&netif_ipaddr, remote_ip, XNET_PROTOCOL_TCP, (uint16_t *)packet->data, packet->size);

    tcp_hdr->checksum = tcp_hdr->checksum ? tcp_hdr->checksum : 0xFFFF;
    return xip_out(XNET_PROTOCOL_TCP, remote_ip, packet);
}

xnet_err_t xudp_bind(xudp_t *udp, uint8_t local_port)
{
    xudp_t *curr, *end;
    for (curr = udp_socket, end = &udp_socket[XUDP_CFG_MAX_UDP], curr < end; curr++)
    {
        if ((curr != udp) && (curr->local_port == local_port))
        {
            return XNET_ERR_BINDED;
        }
    }
    curr->local_port = local_port;
    return XNET_ERR_IO;
}

/* ------------------TCP协议------------------*/
void xtcp_init(void)
{
    memset(tcp_socket, 0, size(tcp_socket));
}

static xtcp_t *xtcp_alloc(void)
{
    xtcp_t *tcp, *end;

    for (tcp = tcp_socket, end = tcp_socket + XTCP_CFG_MAX_TCP; tcp < end; tcp++)
    {
        if (tcp->state == XTCP_STATE_FREE)
        {
            tcp->local_port = 0;
            tcp->remote_port = 0;
            tcp->remote_port = 0;
            tcp->handler = (xtcp_handler_t)0;

            return tcp;
        }
    }
    return (xtcp_t *)0;
}

xtcp_t *xtcp_open(xtcp_handler_t *handler)
{
    xtcp_t *tcp = xtcp_alloc();
    if (!tcp)
    {
        return (xtcp_t *)0;
    }

    tcp->state = XTCP_STATE_CLOSED;
    tcp->handler = handler;
    return tcp;
}

/* ------------------HTTP协议------------------*/
