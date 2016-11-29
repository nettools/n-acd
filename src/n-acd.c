#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <unistd.h>
#include "n-acd.h"

#define _cleanup_(_x) __attribute__((__cleanup__(_x)))
#define _public_ __attribute__((__visibility__("default")))

struct NAcd {
        unsigned long n_refs;
        unsigned int seed;
        int fd_epoll;
        int ifindex;
        struct ether_addr mac;
        struct in_addr address;

        NAcdFn fn;
        void *userdata;
};

_public_ int n_acd_new(NAcd **acdp) {
        _cleanup_(n_acd_unrefp) NAcd *acd = NULL;
        void *p;

        acd = calloc(1, sizeof(*acd));
        if (!acd)
                return -ENOMEM;

        acd->n_refs = 1;
        acd->fd_epoll = -1;
        acd->ifindex = -1;

        /*
         * We need random jitter for all timeouts when handling ARP probes. Use
         * AT_RANDOM to get a seed for rand_r(3p), if available (should always
         * be available on linux). See the time-out scheduler for details.
         */
        p = (void *)getauxval(AT_RANDOM);
        if (p)
                acd->seed = *(unsigned int *)p;

        acd->fd_epoll = epoll_create1(EPOLL_CLOEXEC);
        if (acd->fd_epoll < 0)
                return -errno;

        *acdp = acd;
        acd = NULL;
        return 0;
}

_public_ NAcd *n_acd_ref(NAcd *acd) {
        if (acd)
                ++acd->n_refs;
        return acd;
}

_public_ NAcd *n_acd_unref(NAcd *acd) {
        if (!acd || --acd->n_refs)
                return NULL;

        n_acd_stop(acd);
        if (acd->fd_epoll >= 0)
                close(acd->fd_epoll);
        free(acd);

        return NULL;
}

_public_ bool n_acd_is_running(NAcd *acd) {
        return !!acd->fn;
}

_public_ void n_acd_get_fd(NAcd *acd, int *fdp) {
        *fdp = acd->fd_epoll;
}

_public_ void n_acd_get_ifindex(NAcd *acd, int *ifindexp) {
        *ifindexp = acd->ifindex;
}

_public_ void n_acd_get_mac(NAcd *acd, struct ether_addr *macp) {
        memcpy(macp, &acd->mac, sizeof(acd->mac));
}

_public_ void n_acd_get_address(NAcd *acd, struct in_addr *addressp) {
        memcpy(addressp, &acd->address, sizeof(acd->address));
}

_public_ int n_acd_set_ifindex(NAcd *acd, int ifindex) {
        if (ifindex < 0)
                return -EINVAL;
        if (n_acd_is_running(acd))
                return -EBUSY;

        acd->ifindex = ifindex;
        return 0;
}

_public_ int n_acd_set_mac(NAcd *acd, const struct ether_addr *mac) {
        if (!memcmp(mac->ether_addr_octet, (uint8_t[ETH_ALEN]){ }, ETH_ALEN))
                return -EINVAL;
        if (n_acd_is_running(acd))
                return -EBUSY;

        memcpy(&acd->mac, mac, sizeof(acd->mac));
        return 0;
}

_public_ int n_acd_set_address(NAcd *acd, const struct in_addr *address) {
        if (!address->s_addr)
                return -EINVAL;
        if (n_acd_is_running(acd))
                return -EBUSY;

        memcpy(&acd->address, address, sizeof(acd->address));
        return 0;
}

_public_ int n_acd_dispatch(NAcd *acd) {
        return 0;
}

_public_ int n_acd_start(NAcd *acd, NAcdFn fn, void *userdata) {
        if (!fn)
                return -EINVAL;
        if (n_acd_is_running(acd))
                return -EBUSY;
        if (acd->ifindex < 0 ||
            !memcmp(acd->mac.ether_addr_octet, (uint8_t[ETH_ALEN]){ }, ETH_ALEN) ||
            !acd->address.s_addr)
                return -EBADRQC;

        acd->fn = fn;
        acd->userdata = userdata;
        return 0;
}

_public_ void n_acd_stop(NAcd *acd) {
        acd->fn = NULL;
        acd->userdata = NULL;
}
