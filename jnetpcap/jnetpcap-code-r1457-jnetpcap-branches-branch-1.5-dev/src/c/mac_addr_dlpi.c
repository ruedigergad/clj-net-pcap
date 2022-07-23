/*
 * mac_addr_dlpi.c
 *
 * Return the MAC (ie, ethernet hardware) address by using the dlpi api.
 *
 * compile with: gcc -c -D "OS" mac_addr_dlpi.c
 * with "OS" is one of AIX, SunOS, HPUX 
 */

#if defined(SUNOS) || defined(HPUX) || defined(AIX)

/***********************************************************************/
/* 
 * implementation 
 */

#define INSAP 22 

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <sys/stropts.h>
#include <sys/poll.h>
#include <sys/dlpi.h>

#define bcopy(source, destination, length) memcpy(destination, source, length)

#define AREA_SZ 5000 /* buffer length in byes */ 
static u_long ctl_area[AREA_SZ];
static u_long dat_area[AREA_SZ];
static struct strbuf ctl = {AREA_SZ, 0, (char *)ctl_area};
static struct strbuf dat = {AREA_SZ, 0, (char *)dat_area};
#define GOT_CTRL 1 
#define GOT_DATA 2 
#define GOT_BOTH 3 
#define GOT_INTR 4 
#define GOT_ERR 128 

/* get a message from a stream; return type of message */
static int get_msg(int fd)
{
    int flags = 0;
    int res, ret;
    ctl_area[0] = 0;
    dat_area[0] = 0;
    ret = 0;
    res = getmsg(fd, &ctl, &dat, &flags);
    if(res < 0) {
        if(errno == EINTR) {
            return(GOT_INTR);
        } else {
            return(GOT_ERR);
        }
    }
    if(ctl.len > 0) {
        ret |= GOT_CTRL;
    }
    if(dat.len > 0) {
        ret |= GOT_DATA;
    }
    return(ret);
}

/* verify that dl_primitive in ctl_area = prim */
static int check_ctrl(int prim)
{
    dl_error_ack_t *err_ack = (dl_error_ack_t *)ctl_area;
    if(err_ack->dl_primitive != prim) {
        return GOT_ERR;
    }
    return 0;
}

/* put a control message on a stream  */
static int put_ctrl(int fd, int len, int pri)
{
    ctl.len = len;
    if(putmsg(fd, &ctl, 0, pri) < 0) {
        return GOT_ERR;
    }
    return  0;
}

/* put a control + data message on a stream */
static int put_both(int fd, int clen, int dlen, int pri)
{
    ctl.len = clen;
    dat.len = dlen;
    if(putmsg(fd, &ctl, &dat, pri) < 0) {
        return GOT_ERR;
    }
    return  0;
}

/* open file descriptor and attach */
static int dl_open(const char *dev, int *fd)
{
    dl_attach_req_t *attach_req = (dl_attach_req_t *)ctl_area;
    if((*fd = open(dev, O_RDWR)) == -1) {
        return GOT_ERR;
    } 

    return 0;
}

/* send DL_BIND_REQ */
static int dl_bind(int fd, int sap, u_char *addr)
{
    dl_bind_req_t *bind_req = (dl_bind_req_t *)ctl_area;
    dl_bind_ack_t *bind_ack = (dl_bind_ack_t *)ctl_area;
    bind_req->dl_primitive = DL_BIND_REQ;
    bind_req->dl_sap = sap;
    bind_req->dl_max_conind = 1;
    bind_req->dl_service_mode = DL_CLDLS;
    bind_req->dl_conn_mgmt = 0;
    bind_req->dl_xidtest_flg = 0;
    put_ctrl(fd, sizeof(dl_bind_req_t), 0);
    get_msg(fd);
    if (GOT_ERR == check_ctrl(DL_BIND_ACK)) {
        return GOT_ERR;
    }
    bcopy((u_char *)bind_ack + bind_ack->dl_addr_offset, addr,
        bind_ack->dl_addr_length);
    return 0;
}

/***********************************************************************/
/*
 * interface:
 * function mac_addr_dlpi - get the mac address of the "first" interface
 *
 * parameter: addr: an array of six bytes, has to be allocated by the caller
 *
 * return: 0 if OK, -1 if the address could not be determined
 *
 */

int mac_addr_dlpi ( char *dev, u_char  *addr)
{
    int fd;
    int ppa;
    u_char mac_addr[25];
    int i;

    if (GOT_ERR != dl_open(dev, &fd)) {
        if (GOT_ERR != dl_bind(fd, 0, mac_addr)) {
            bcopy( mac_addr, addr, 6);

            return 0;
        } 
    }

    close(fd);
    return -1;
}

#endif
