#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include "n-acd.h"

#define _cleanup_(_x) __attribute__((__cleanup__(_x)))
#define _public_ __attribute__((__visibility__("default")))

enum {
        N_ACD_EPOLL_TIMER,
};

struct NAcd {
        /* context */
        unsigned long n_refs;
        unsigned int seed;
        int fd_epoll;
        int fd_timer;

        /* configuration */
        int ifindex;
        struct ether_addr mac;
        struct in_addr address;

        /* runtime */
        NAcdFn fn;
        void *userdata;
};

_public_ int n_acd_new(NAcd **acdp) {
        _cleanup_(n_acd_unrefp) NAcd *acd = NULL;
        void *p;
        int r;

        acd = calloc(1, sizeof(*acd));
        if (!acd)
                return -ENOMEM;

        acd->n_refs = 1;
        acd->fd_epoll = -1;
        acd->fd_timer = -1;
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

        acd->fd_timer = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (acd->fd_timer < 0)
                return -errno;

        r = epoll_ctl(acd->fd_epoll, EPOLL_CTL_ADD, acd->fd_timer,
                      &(struct epoll_event){
                              .events = EPOLLIN,
                              .data.u32 = N_ACD_EPOLL_TIMER,
                      });
        if (r < 0)
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
        if (acd->fd_timer >= 0)
                close(acd->fd_timer);
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

static int n_acd_schedule(NAcd *acd, uint64_t u_timeout, unsigned int u_jitter) {
        uint64_t u_next = u_timeout;
        int r;

        /*
         * ACD specifies jitter values to reduce packet storms on the local
         * link. This call accepts the maximum relative jitter value in
         * microseconds as @u_jitter. We then use rand_r(3p) to get a
         * pseudo-random jitter on top of the real timeout given as @u_timeout.
         * Note that rand_r() is fine for this. Before you try to improve the
         * RNG, you better spend some time securing ARP.
         */
        if (u_jitter)
                u_next += rand_r(&acd->seed) % u_jitter;

        /*
         * Setting .it_value to 0 in timerfd_settime() disarms the timer. Avoid
         * this and always schedule at least 1us. Otherwise, we'd have to
         * recursively call into the time-out handler, which we really want to
         * avoid. No reason to optimize performance here.
         */
        if (!u_next)
                u_next = 1;

        r = timerfd_settime(acd->fd_timer, 0,
                            &(struct itimerspec){ .it_value = {
                                    .tv_sec = u_next / UINT64_C(1000000),
                                    .tv_nsec = u_next % UINT64_C(1000000) * UINT64_C(1000),
                            } }, NULL);
        if (r < 0)
                return -errno;

        return 0;
}

static int n_acd_handle_timeout(NAcd *acd, uint64_t v) {
        return 0;
}

static int n_acd_dispatch_timer(NAcd *acd, struct epoll_event *event) {
        uint64_t v;
        int r;

        if (event->events & EPOLLIN) {
                r = read(acd->fd_timer, &v, sizeof(v));
                if (r == sizeof(v)) {
                        /*
                         * We successfully read a timer-value. Handle it and
                         * return. We do NOT fall-through to EPOLLHUP handling,
                         * as we always must drain buffers first.
                         */
                        return n_acd_handle_timeout(acd, v);
                } else if (r >= 0) {
                        /*
                         * Kernel guarantees 8-byte reads; fail hard if it
                         * suddenly starts doing weird shit. No clue what to do
                         * with those values, anyway.
                         */
                        return -EIO;
                } else if (errno != EAGAIN) {
                        /*
                         * Something failed. We use CLOCK_BOOTTIME, so
                         * ECANCELED cannot happen. Hence, there is no error
                         * that we could gracefully handle. Fail hard and let
                         * the caller deal with it.
                         */
                        return -errno;
                }
        }

        if (event->events & (EPOLLHUP | EPOLLERR)) {
                /*
                 * There is no way to handle either gracefully. If we ignored
                 * them, we would busy-loop, so lets rather forward the error
                 * to the caller.
                 */
                return -EIO;
        }

        return 0;
}

_public_ int n_acd_dispatch(NAcd *acd) {
        struct epoll_event events[2];
        int r, n, i;

        n = epoll_wait(acd->fd_epoll, events, sizeof(events) / sizeof(*events), 0);
        if (n < 0)
                return -errno;

        for (i = 0; i < n; ++i) {
                switch (events[i].data.u32) {
                case N_ACD_EPOLL_TIMER:
                        r = n_acd_dispatch_timer(acd, events + i);
                        break;
                default:
                        r = 0;
                        break;
                }

                if (r < 0)
                        return r;
        }

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
        timerfd_settime(acd->fd_timer, 0, &(struct itimerspec){}, NULL);
}
