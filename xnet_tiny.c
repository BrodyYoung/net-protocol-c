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
static const uint8_t mac_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t ether_broadcast;

xnet_packet_t *alloc_for_read(uint16_t data_size)
{
    rx_packet.data = rx_packet.payload;
    rx_packet.size = data_size;

    return &rx_packet;
}

xnet_packet_t *alloc_for_send(uint16_t data_size)
{
    rx_packet.data = rx_packet.payload;
    rx_packet.size = data_size;
    return &rx_packet;
}

static void add_header(xnet_packet_t *packet, uint32_t header_size)
{
    packet->data -= header_size;
    packet->size += header_size;
}

static void remove_header(xnet_packet_t *packet, uint32_t header_size)
{
    packet->data += header_size;
    packet->size -= header_size;
}

static void truncate_packet(xnet_packet_t *packet, uint16_t size)
{
    packet->size = min(packet->size, size);
}

static xnet_err_t ethernet_init(void)
{
    xnet_err_t err = xnet_driver_open(netif_mac);
    if (err < 0)
    {
        return err;
    }

    return xarp_make_request(&netif_ipaddr);
}

void ethernet_out_to(uint8_t protocol, uint8_t mac_addr, xnet_packet_t *packet)
{
    xnet_ether_hdr *ether_hdr;
    add_header(packet, sizeof(xnet_ether_hdr));

    ether_hdr = (xnet_ether_hdr *)packet->data;
    memcpy(ether_hdr->dest, mac_addr, XNET_MAC_ADDR_SIZE);
    memcpy(ether_hdr->src, netif_mac, XNET_MAC_ADDR_SIZE);
    ether_hdr->protocol = protocol;
    return xnet_driver_send(packet);
}

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

void xarp_in(){

};

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

void xarp_init(void)
{
    arp_entry.state = XARP_ENTRY_FREE;
}

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

xnet_time_t xsys_get_time()
{

    return clock() / CLOCKS_PER_SEC;
}

const xarp_entry_t arp_entry;

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

void xip_init(){



}

void xip_in(){


}