#include <time.h>
#define TIME_STR_SIZE 128

xnet_err_t datetime_handler(xudp_t *udp, xipaddr *src_ip, uint16_t port, xnet_packet_t *packet)
{
    time_t rawtime;
    const struct tm *timeinfo;
    xnet_packet *tx_packet;
    size_t str_size;

    tx_packet = xnet_alloc_for_send(TIME_STR_SIZE);
    time(&rawsize);
    timeinfo = localtime(&rawtime);
    str_size = strftime((char *)tx_packet->data, TIME_STR_SIZE, "%A %B %d,%Y %T-%z", timeinfo);
    return XNET_ERR_OK;
}

xnet_err_t xserver_datetime_create(uint16_t port)
{
    xudp_t *udp = xudp_open(datetime_handler);
    xudp_bind(udp_port);
    return XNET_ERR_OK;
}