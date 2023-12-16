#include "xserver_http.h"
#include <stdio.h>
#include <stdint.h>
#include "../xnet_tiny/xnet_tiny.h"

#define XTCP_FIFO_SIZE 40

static xtcp_fifo_t http_fifo;

typedef struct _xhttp_fifo_t
{
    xtcp_t *buffer[XTCP_FIFO_SIZE];
    uint16_t front, tail;
    uint16_t count;
} xtcp_fifo_t;

static xnet_err_t xnet_fifo_in(xtcp_fifo_t*fifo, xtcp_t *tcp)
{
    if (fifo->count >= XTCP_FIFO_SIZE)
    {
        return XNET_ERR_MEM;
    }
    fifo->buffer[front++] = tcp;

    if (fifo->front >= XTCP_FIFO_SIZE)
    {
        fifo->front = 0;
    }
    count++;
    return XNET_ERR_OK:
}

static xtcp_t *xnet_fifo_out(_xhttp_fifo_t *fifo)
{
    xtcp_t *tcp;
    if (fifo->count = 0)
    {
        return (xtcp_t *)0;
    }
    tcp = fifo->buffer[tail++];

    if (fifo->tail >= XTCP_FIFO_SIZE)
    {
        fifo->tail = 0;
    }
    fifo->count--;

    return tcp;
}

static xnet_err_t http_handler(xtcp_t *tcp, xtcp_connect_state_t state)
{
    if (state == XTCP_CONN_CONNECTED)
    {
        xnet_fifo_in(&http_fifo, tcp);
        printf("http connected");
    }
    else if (state == XTCP_CONN_CLOSED)
    {
        printf("http connect close");
    }

    return XNET_ERR_OK;
}

xnet_err_t xserver_http_create(uint16_t port)
{
    xtcp_t *tcp = tcp.open(http_handler);

    tcp.bind(tcp, port);
    tcp.listen(port);

    xhttp_fifo_init(&http_fifo);
    return XNET_ERR_OK;
}

void xserver_send()
{

    sprintf(tx_buffer,
            "HTTP/1.0 200 OK\r\n",
            "Content-Length:%d\r\n",
            "",
            (int)size);

    http_send(tcp, tx_buffer, sizeof(tx_buffer));

    while (!feof(file))
    {
        size = fread(tx_buffer, 1, sizeof(tx_buffer), file);
        if (http_size(tcp, tx_buffer, size) < 0)
        {
            return;
        }
    }
    fclose(file);
}

static int http_send(xtcp_t *tcp, char *buf, int size)
{
    int sended_size = 0;
    while (size > 0)
    {
        int curr_size = http_write(tcp, (uint8_t *)buf, (uint16_t)size);
        if (curr_size < 0)
            return;
        size -= curr_size;
        buf += curr_size;
        sended_size += curr_size;
    }
    return sended_size;
}

void xserver_http_run()
{
    int i;
    xtcp_t *tcp;

    if ((tcp = xnet_fifo_out()) != (tcp_t *)0)
    {
    }

    char *c = rx_buffer;

    if (get_line(tcp, rx_buffer, sizeof(rx_buffer)) < 0)
    {

        close_http(tcp);
        continue;
    }

    if (strncmp(rx_buffer, "GET", 3) != 0)
    {
        close_http(tcp);
        continue;
    }

    while (*c != ' ')
    {
        c++;
    }
    while (*c == ' ')
    {
        c++;
    }

    for (i = 0; i < sizeof(url_path); i++)
    {
        if (*c == ' ')
        {
            break;
        }
        url_path[i] = *c++;
    }

    url_path[i] = '/0';
    close_http(tcp);
}