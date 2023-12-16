#include <stdio.h>
#include "xnet_tiny.h"

int main(void)
{
    xnet_init();

    xserver_datatime_create(13);
    xserver_http_create(80);

    printf("xnet running\n");

    while (1)
    {
        xnet_poll();
        xserver_http_run();
    }
    return 0;
}