/*
 * mac_addr_sys.c
 *
 * Return the MAC (ie, ethernet hardware) address by using system specific
 * calls.
 *
 * compile with: gcc -c -D "OS" mac_addr_sys.c
 * with "OS" is one of Linux, AIX, HPUX 
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef Linux
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#endif

#ifdef HPUX
#include <netio.h>
#endif

#ifdef AIX
#include <sys/ndd_var.h>
#include <sys/kinfo.h>
#endif

#ifdef WIN32
#include <pcap.h>
#endif

int mac_addr_sys ( char *dev, u_char *addr)
{
/* implementation for Linux */
#ifdef Linux
   struct ifreq ifr;

   int sd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        return -1; // error: can't create socket.
    }

    /* set interface name (lo, eth0, eth1,..) */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_ifrn.ifrn_name, dev, IFNAMSIZ);

    /* get a Get Interface Hardware Address */
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) != 0) {
        return -1;
    }

    bcopy((u_char *)ifr.ifr_ifru.ifru_hwaddr.sa_data, addr, 6);

    close(sd);
    return 0;

#endif

/* implementation for HP-UX */
#ifdef HPUX

#define LAN_DEV0 "/dev/lan0"

    int             fd;
    struct fis      iocnt_block;
    int             i;
    char    net_buf[sizeof(LAN_DEV0)+1];
    char    *p;

    (void)sprintf(net_buf, "%s", LAN_DEV0);
    p = net_buf + strlen(net_buf) - 1;

    /* 
     * Get 802.3 address from card by opening the driver and interrogating it.
     */
    for (i = 0; i < 10; i++, (*p)++) {
        if ((fd = open (net_buf, O_RDONLY)) != -1) {
                        iocnt_block.reqtype = LOCAL_ADDRESS;
                        ioctl (fd, NETSTAT, &iocnt_block);
                        close (fd);

            if (iocnt_block.vtype == 6)
                break;
        }
    }

    if (fd == -1 || iocnt_block.vtype != 6) {
        return -1;
    }

        bcopy( &iocnt_block.value.s[0], addr, 6);
        return 0;

#endif /* HPUX */
        

/* implementation for AIX */
#ifdef AIX

    int size;
    struct kinfo_ndd *nddp;

    size = getkerninfo(KINFO_NDD, 0, 0, 0);
    if (size <= 0) {
        return -1;
    }
    nddp = (struct kinfo_ndd *)malloc(size);
          
    if (!nddp) {
        return -1;
    }
    if (getkerninfo(KINFO_NDD, nddp, &size, 0) < 0) {
        free(nddp);
        return -1;
    }
    bcopy(nddp->ndd_addr, addr, 6);
    free(nddp);
    return 0;
#endif

/* implementation for darwin/MacOS */
#ifdef DARWIN
	struct ifaddrs *ifa = NULL;
	struct sockaddr_dl* dl;

	getifaddrs(&ifa);

	while (ifa != NULL) {
		dl = (struct sockaddr_dl*)ifa->ifa_addr;
		if (dl->sdl_nlen > 0 && strncmp(dev, dl->sdl_data, dl->sdl_nlen) == 0) {
			bcopy((u_char *)LLADDR(dl), addr, 6);
			return 0;
		} else {
			ifa = ifa->ifa_next;
		}
	}

#endif
	
/* implementation for NetBSD, FreeBSD, OpenBSD */
#if defined(FREE_BSD) || defined(NET_BSD) || defined(OPEN_BSD)
     int                     mib[6], len;
     char                    *buf;
     struct if_msghdr        *ifm;
     struct sockaddr_dl      *sdl;

     mib[0] = CTL_NET;
     mib[1] = AF_ROUTE;
     mib[2] = 0;
     mib[3] = AF_LINK;
     mib[4] = NET_RT_IFLIST;
     if ((mib[5] = if_nametoindex(dev)) == 0) {
             perror("if_nametoindex error");
             return -1;
     }

     if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
             perror("sysctl 1 error");
             return -1;
     }

     if ((buf = malloc(len)) == NULL) {
             perror("malloc error");
             return -1;
     }

     if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
             perror("sysctl 2 error");
             return -1;
     }

     ifm = (struct if_msghdr *)buf;
     sdl = (struct sockaddr_dl *)(ifm + 1);

     bcopy((u_char *)LLADDR(sdl), addr, 6);
     return 0;

#endif

/* Not implemented platforms */
        return -1;
}
