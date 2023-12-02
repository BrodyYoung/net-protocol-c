#include "xnet_tiny.h"
#include <stdint.h>
#include <time.h>

#define min(a, b) ((a) > (b) ? (b) : (a));

// 交换大小端
#define swap_order(v) ((v & 0xFF) << 8 | (v >> 8) & 0xFF)

// 发送使用tx_packet，接收使用rx_packet

static xnet_packet_t tx_packet, rx_packet;
static xarp_entry_t arp_entry;
static const xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP;
static const uint8_t mac_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t ether_broadcast;

// 分配读数据包
xnet_packet_t *alloc_for_read(uint16_t data_size)
{
    rx_packet.data = rx_packet.payload;
    rx_packet.size = data_size;

    return &rx_packet;
}

// 分配写数据包
xnet_packet_t *alloc_for_send(uint16_t data_size)
{
    rx_packet.data = rx_packet.payload;
    rx_packet.size = data_size;
    return &rx_packet;
}

// 添加协议头
static void add_header(xnet_packet_t *packet, uint32_t header_size)
{
    packet->data -= header_size;
    packet->size += header_size;
}

// 删除协议头
static void remove_header(xnet_packet_t *packet, uint32_t header_size)
{
    packet->data += header_size;
    packet->size -= header_size;
}

// 截断数据包
static void truncate_packet(xnet_packet_t *packet, uint16_t size)
{
    packet->size = min(packet->size, size);
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

int ethernet_out_to(uint8_t protocol, uint8_t mac_addr, xnet_packet_t *packet)
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
void ethernet_in(xnet_packet_t *packet)
{
    xnet_ether_hdr *ether_hdr;
    uint16_t protocol;
    if (packet->size <= sizeof(xnet_ether_hdr))
    {
        return;
    }

    ether_hdr = (xnet_ether_hdr *)packet->data;
    protocol = swap_order(ether_hdr->protocol);
    switch (protocol)
    {
    case XNET_PROTOCOL_ARP:
        break;

    case XNET_PROTOCOL_IP:
        break;
    }
}

// 以太网协议轮询
void ethernet_poll()
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

    xnet_packet_t *packet = alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t *arp_packet = (xarp_packet_t *)packet->data;

    arp_packet->hw_type = XARP_HW_ETHER;
    arp_packet->prot_type = swap_order(XNET_PROTOCOL_IP);
    arp_packet->hw_len = XNET_MAC_ADDR_SIZE;
    arp_packet->prot_len = XNET_IPV4_ADDR_SIZE;
    arp_packet->opcode = swap_order(XARP_REQUEST);

    memcpy(arp_packet->send_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memcpy(arp_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->target_ip, ipaddr->array, XNET_IPV4_ADDR_SIZE);

    return ethernet_out_to(XNET_PROTOCOL_ARP, ether_broadcast, packet);
}

// 创建ARP协议响应
int xarp_make_response(const xipaddr_t *ipaddr)
{
    xnet_packet_t *packet = alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t *response_packet = (xarp_packet_t *)packet->data;

    response_packet->hw_type = XARP_HW_ETHER;
    response_packet->prot_type = swap_order(XNET_PROTOCOL_IP);
    response_packet->hw_len = XNET_MAC_ADDR_SIZE;
    response_packet->prot_len = XNET_IPV4_ADDR_SIZE;
    response_packet->opcode = swap_order(XARP_REQUEST);

    memcpy(response_packet->send_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memcpy(response_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->target_ip, ipaddr->array, XNET_IPV4_ADDR_SIZE);

    return ethernet_out_to(XNET_PROTOCOL_ARP, response_packet->send_mac, packet);
}

// xnet_err_t xarp_resolve(const xipaddr_t * ) 

// 获取系统时间，单位秒
xnet_time_t xsys_get_time()
{

    return clock() / CLOCKS_PER_SEC;
}

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
    iphdr->id = ip_packet_id++;
    iphdr->header_lenth = sizeof(xip_hdr_t) / 4;
    iphdr->total_length = swaporder16(packet->size);
    iphdr->protocal = XNET_PROTOCOL_IP;
    iphdr->tos = 0;
    iphdr->ttl = 10;
    iphdr->flags;
    iphdr->version - XNET_VERSION_IPV4;
    memcpy(iphdr->srcIP, &netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memcpy(iphdr->destIP, dest_ip.array, XNET_IPV4_ADDR_SIZE);
    iphdr->hdr_checksum = 0;
}

static xnet_err_t ethernet_out(xipaddr_t *dest_ip, xnet_packet_t *packet)
{
    xnet_err_t err;
    uint8_t *mac_addr;
    

}

