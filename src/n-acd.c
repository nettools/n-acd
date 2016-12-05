#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>
#include "n-acd.h"

#define _public_ __attribute__((__visibility__("default")))

/*
 * These parameters and timing intervals are taken directly from the RFC-5227.
 * See there for details why they were selected like this.
 */
#define N_ACD_RFC_PROBE_NUM                     (3)
#define N_ACD_RFC_PROBE_WAIT_USEC               (UINT64_C(1000000)) /* 1s */
#define N_ACD_RFC_PROBE_MIN_USEC                (UINT64_C(1000000)) /* 1s */
#define N_ACD_RFC_PROBE_MAX_USEC                (UINT64_C(3000000)) /* 3s */
#define N_ACD_RFC_ANNOUNCE_NUM                  (3)
#define N_ACD_RFC_ANNOUNCE_WAIT_USEC            (UINT64_C(2000000)) /* 2s */
#define N_ACD_RFC_ANNOUNCE_INTERVAL_USEC        (UINT64_C(2000000)) /* 2s */
#define N_ACD_RFC_MAX_CONFLICTS                 (10)
#define N_ACD_RFC_RATE_LIMIT_INTERVAL_USEC      (UINT64_C(60000000)) /* 60s */
#define N_ACD_RFC_DEFEND_INTERVAL_USEC          (UINT64_C(10000000)) /* 10s */

enum {
        N_ACD_EPOLL_TIMER,
        N_ACD_EPOLL_SOCKET,
};

enum {
        N_ACD_STATE_INIT,
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
        struct in_addr ip;

        /* runtime */
        NAcdFn fn;
        void *userdata;
        int fd_socket;
        unsigned int state;
};

_public_ int n_acd_new(NAcd **acdp) {
        NAcd *acd;
        void *p;
        int r;

        acd = calloc(1, sizeof(*acd));
        if (!acd)
                return -ENOMEM;

        acd->n_refs = 1;
        acd->fd_epoll = -1;
        acd->fd_timer = -1;
        acd->ifindex = -1;
        acd->fd_socket = -1;
        acd->state = N_ACD_STATE_INIT;

        /*
         * We need random jitter for all timeouts when handling ARP probes. Use
         * AT_RANDOM to get a seed for rand_r(3p), if available (should always
         * be available on linux). See the time-out scheduler for details.
         */
        p = (void *)getauxval(AT_RANDOM);
        if (p)
                acd->seed = *(unsigned int *)p;

        acd->fd_epoll = epoll_create1(EPOLL_CLOEXEC);
        if (acd->fd_epoll < 0) {
                r = -errno;
                goto error;
        }

        acd->fd_timer = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (acd->fd_timer < 0) {
                r = -errno;
                goto error;
        }

        r = epoll_ctl(acd->fd_epoll, EPOLL_CTL_ADD, acd->fd_timer,
                      &(struct epoll_event){
                              .events = EPOLLIN,
                              .data.u32 = N_ACD_EPOLL_TIMER,
                      });
        if (r < 0) {
                r = -errno;
                goto error;
        }

        *acdp = acd;
        return 0;

error:
        n_acd_unref(acd);
        return r;
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

        assert(acd->fd_socket < 0);

        if (acd->fd_timer >= 0) {
                assert(acd->fd_epoll >= 0);
                epoll_ctl(acd->fd_epoll, EPOLL_CTL_DEL, acd->fd_timer, NULL);
                close(acd->fd_timer);
                acd->fd_timer = -1;
        }

        if (acd->fd_epoll >= 0) {
                close(acd->fd_epoll);
                acd->fd_epoll = -1;
        }

        free(acd);

        return NULL;
}

_public_ bool n_acd_is_running(NAcd *acd) {
        return acd->state != N_ACD_STATE_INIT;
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

_public_ void n_acd_get_ip(NAcd *acd, struct in_addr *ipp) {
        memcpy(ipp, &acd->ip, sizeof(acd->ip));
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

_public_ int n_acd_set_ip(NAcd *acd, const struct in_addr *ip) {
        if (!ip->s_addr)
                return -EINVAL;
        if (n_acd_is_running(acd))
                return -EBUSY;

        memcpy(&acd->ip, ip, sizeof(acd->ip));
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

static int n_acd_bind_socket(NAcd *acd, int s) {
        /*
         * Due to strict aliasing, we cannot get uint32_t/uint16_t pointers to
         * acd->mac, so provide a union accessor.
         */
        const union {
                uint8_t u8[6];
                uint16_t u16[3];
                uint32_t u32[1];
        } mac = {
                .u8 = {
                        acd->mac.ether_addr_octet[0],
                        acd->mac.ether_addr_octet[1],
                        acd->mac.ether_addr_octet[2],
                        acd->mac.ether_addr_octet[3],
                        acd->mac.ether_addr_octet[4],
                        acd->mac.ether_addr_octet[5],
                }
        };
        struct sock_filter filter[] = {
                /*
                 * Basic ARP header validation. Make sure the packet-length,
                 * wire type, protocol type, and address lengths are correct.
                 */
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                                          /* A <- packet length */
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(struct ether_arp), 1, 0),                            /* packet >= arp packet ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_hrd)),                  /* A <- header */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPHRD_ETHER, 1, 0),                                        /* header == ethernet ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_pro)),                  /* A <- protocol */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 1, 0),                                        /* protocol == IP ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_hln)),                  /* A <- hardware address length */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, sizeof(struct ether_addr), 1, 0),                           /* length == sizeof(ether_addr)? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_pln)),                  /* A <- protocol address length */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, sizeof(struct in_addr), 1, 0),                              /* length == sizeof(in_addr) ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_op)),                   /* A <- operation */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 2, 0),                                       /* protocol == request ? */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 1, 0),                                         /* protocol == reply ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                /*
                 * Sender hardware address must be different from ours. Note
                 * that BPF runs in big-endian mode, but assumes immediates are
                 * given in native-endian. This might look weird on 6-byte mac
                 * addresses, but is needed to revert the BPF magic.
                 */
                BPF_STMT(BPF_LD + BPF_IMM, be32toh(mac.u32[0])),                                                /* A <- 4 bytes of client's MAC */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ether_arp, arp_sha)),                        /* A <- 4 bytes of SHA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                         /* A xor X */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 6),                                                   /* A == 0 ? */
                BPF_STMT(BPF_LD + BPF_IMM, be16toh(mac.u16[2])),                                                /* A <- remainder of client's MAC */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, arp_sha) + 4),                    /* A <- remainder of SHA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                         /* A xor X */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),                                                   /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                /*
                 * Sender protocol address or target protocol address must be
                 * equal to the one we care about. Again, immediates must be
                 * given in native-endian.
                 */
                BPF_STMT(BPF_LD + BPF_IMM, be32toh(acd->ip.s_addr)),                                            /* A <- clients IP */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ether_arp, arp_spa)),                        /* A <- SPA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                         /* X xor A */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),                                                   /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 65535),                                                               /* return all */
                BPF_STMT(BPF_LD + BPF_IMM, be32toh(acd->ip.s_addr)),                                            /* A <- clients IP */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ether_arp, arp_tpa)),                        /* A <- TPA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                         /* X xor A */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),                                                   /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 65535),                                                               /* return all */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */
        };
        const struct sock_fprog fprog = {
                .len = sizeof(filter) / sizeof(*filter),
                .filter = filter,
        };
        const struct sockaddr_ll address = {
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_ARP),
                .sll_ifindex = acd->ifindex,
                .sll_halen = ETH_ALEN,
                .sll_addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };
        int r;

        /*
         * Install a packet filter that matches on the ARP header and
         * addresses, to reduce the number of wake-ups to a minimum.
         */
        r = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        /*
         * Bind the packet-socket to ETH_P_ARP and the specified network
         * interface.
         */
        r = bind(s, (struct sockaddr *)&address, sizeof(address));
        if (r < 0)
                return -errno;

        return 0;
}

static int n_acd_setup_socket(NAcd *acd) {
        int r, s;

        s = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        r = n_acd_bind_socket(acd, s);
        if (r < 0)
                goto error;

        r = epoll_ctl(acd->fd_epoll, EPOLL_CTL_ADD, s,
                      &(struct epoll_event){
                              .events = EPOLLIN,
                              .data.u32 = N_ACD_EPOLL_SOCKET,
                      });
        if (r < 0) {
                r = -errno;
                goto error;
        }

        acd->fd_socket = s;
        return 0;

error:
        close(s);
        return r;
}

_public_ int n_acd_start(NAcd *acd, NAcdFn fn, void *userdata) {
        int r;

        if (!fn)
                return -EINVAL;
        if (n_acd_is_running(acd))
                return -EBUSY;
        if (acd->ifindex < 0 ||
            !memcmp(acd->mac.ether_addr_octet, (uint8_t[ETH_ALEN]){ }, ETH_ALEN) ||
            !acd->ip.s_addr)
                return -EBADRQC;

        r = n_acd_setup_socket(acd);
        if (r < 0)
                goto error;

        r = n_acd_schedule(acd, 0, 0);
        if (r < 0)
                goto error;

        acd->fn = fn;
        acd->userdata = userdata;
        return 0;

error:
        n_acd_stop(acd);
        return r;
}

_public_ void n_acd_stop(NAcd *acd) {
        acd->fn = NULL;
        acd->userdata = NULL;
        acd->state = N_ACD_STATE_INIT;
        timerfd_settime(acd->fd_timer, 0, &(struct itimerspec){}, NULL);

        if (acd->fd_socket >= 0) {
                assert(acd->fd_epoll >= 0);
                epoll_ctl(acd->fd_epoll, EPOLL_CTL_DEL, acd->fd_socket, NULL);
                close(acd->fd_socket);
                acd->fd_socket = -1;
        }
}
