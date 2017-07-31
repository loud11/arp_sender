#include "my_mac.h"

char * my_ip()

{
    struct ifreq *ifr;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    struct ifconf ifcfg;
    int fd;
    int n;
    int numreqs = 30;
    char * ip;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifcfg, 0, sizeof(ifcfg));

    ifcfg.ifc_buf = NULL;
    ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
    ifcfg.ifc_buf = (char *)malloc(ifcfg.ifc_len);

    for(;;)

    {
        ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
        ifcfg.ifc_buf = (char *)realloc(ifcfg.ifc_buf, ifcfg.ifc_len);
        if (ioctl(fd, SIOCGIFCONF, (char *)&ifcfg) < 0)
        {
            perror("SIOCGIFCONF ");
            exit(0);
        }
        break;
    }

    ifr = ifcfg.ifc_req;

    for (n = 0; n < ifcfg.ifc_len; n+= sizeof(struct ifreq))
    {
        sin = (struct sockaddr_in *)&ifr->ifr_addr;
        printf("IP    %s\n", ip= inet_ntoa(sin->sin_addr));
        printf("IP    %s\n", ip);

        if ( ntohl(sin->sin_addr.s_addr) == INADDR_LOOPBACK)
        {
            printf("Loop Back\n");
        }
        else
        {
            return ip;

        }

        printf("\n");

        ifr++;

    }
    exit(0);
}
