#include "my_mac.h"
#include <netinet/ether.h>

char * my_mac()

{
    struct ifreq *ifr;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    struct ifconf ifcfg;
    int fd;
    int n;
    int numreqs = 30;

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
        printf("[%s]\n", ifr->ifr_name);
        sin = (struct sockaddr_in *)&ifr->ifr_addr;
        printf("IP    %s\n", inet_ntoa(sin->sin_addr));

        if ( ntohl(sin->sin_addr.s_addr) == INADDR_LOOPBACK)
        {
            printf("Loop Back\n");
        }
        else
        {
            ioctl(fd, SIOCGIFHWADDR, (char *)ifr);
            sa = &ifr->ifr_hwaddr;
            printf("MAC	%s \n", ether_ntoa((struct ether_addr *)sa->sa_data));

        }

        printf("\n");

        ifr++;

    }

    return ether_ntoa((struct ether_addr *)sa->sa_data);

}
