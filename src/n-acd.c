/*
 * IPv4 Address Conflict Detection
 *
 * This implements the main n-acd API. It is built around an epoll-fd to
 * encapsulate a timerfd+socket. The n-acd context has quite straightforward
 * lifetime rules. The parameters must be set when the engine is started, and
 * they can only be changed by stopping and restartding the engine. The engine
 * is started on demand and stopped when no longer needed.
 * During the entire lifetime the context can be dispatched. That is, the
 * dispatcher does not have to be aware of the context state. After each call
 * to dispatch(), the caller must pop all pending events until -EAGAIN is
 * returned.
 *
 * If a conflict is detected, the ACD engine reports to the caller and stops
 * the engine. The caller can now modify parameters and restart the engine, if
 * required.
 */

#include <assert.h>
#include <c-list.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
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
 * These parameters and timing intervals specified in RFC-5227. The original
 * values are:
 *
 *     PROBE_NUM                                3
 *     PROBE_WAIT                               1s
 *     PROBE_MIN                                1s
 *     PROBE_MAX                                3s
 *     ANNOUNCE_NUM                             3
 *     ANNOUNCE_WAIT                            2s
 *     ANNOUNCE_INTERVAL                        2s
 *     MAX_CONFLICTS                            10
 *     RATE_LIMIT_INTERVAL                      60s
 *     DEFEND_INTERVAL                          10s
 *
 * If we assume a best-case and worst-case scenario for non-conflicted runs, we
 * end up with a runtime between 4s and 9s to finish the probe. Then it still
 * takes a fixed 4s to finish the announcements.
 *
 * RFC 5227 section 1.1:
 *     [...] (Note that the values listed here are fixed constants; they are
 *     not intended to be modifiable by implementers, operators, or end users.
 *     These constants are given symbolic names here to facilitate the writing
 *     of future standards that may want to reference this document with
 *     different values for these named constants; however, at the present time
 *     no such future standards exist.) [...]
 *
 * Unfortunately, no-one ever stepped up to write a "future standard" to revise
 * the timings. A 9s timeout for successful link setups is not acceptable in
 * today. Hence, we will just go forward and ignore the proposed values. On both
 * wired and wireless local links round-trip latencies of below 3ms are common,
 * while latencies above 10ms are rarely seen. We just go ahead and use an
 * interval of 50ms to 10ms for the probes, plus a 200ms wait interval. This
 * should properly honor slower networks, as well as recognize the need of the
 * other peers to schedule the needed processes to handle the requests.
 * If this annoys the hell out of you, file a bug report and we can make the
 * speedup a configurable option of the context object.
 */
#define N_ACD_RFC_PROBE_NUM                     (3)
#define N_ACD_RFC_PROBE_WAIT_USEC               (UINT64_C(50000)) /* 50ms */
#define N_ACD_RFC_PROBE_MIN_USEC                (UINT64_C(50000)) /* 50ms */
#define N_ACD_RFC_PROBE_MAX_USEC                (UINT64_C(100000)) /* 100ms */
#define N_ACD_RFC_ANNOUNCE_NUM                  (3)
#define N_ACD_RFC_ANNOUNCE_WAIT_USEC            (UINT64_C(200000)) /* 200ms */
#define N_ACD_RFC_ANNOUNCE_INTERVAL_USEC        (UINT64_C(500000)) /* 500ms */
#define N_ACD_RFC_MAX_CONFLICTS                 (10)
#define N_ACD_RFC_RATE_LIMIT_INTERVAL_USEC      (UINT64_C(60000000)) /* 60s */
#define N_ACD_RFC_DEFEND_INTERVAL_USEC          (UINT64_C(10000000)) /* 10s */

/*
 * Fake ENETDOWN error-code. We use this as replacement for known EFOOBAR error
 * codes. It is explicitly chosen to be outside the known error-code range.
 * Whenever we are deep down in a call-stack and notice a ENETDOWN error, we
 * return this instead. It is caught by the top-level dispatcher and then
 * properly handled.
 * This avoids gracefully handling ENETDOWN in call-stacks, but then continuing
 * with some work in the callers without noticing the soft failure.
 */
#define N_ACD_E_DOWN (INT_MAX)

enum {
        N_ACD_EPOLL_TIMER,
        N_ACD_EPOLL_SOCKET,
};

enum {
        N_ACD_STATE_INIT,
        N_ACD_STATE_PROBING,
        N_ACD_STATE_ANNOUNCING,
};

typedef struct NAcdEventNode {
        NAcdEvent event;
        CList link;
} NAcdEventNode;

struct NAcd {
        /* context */
        unsigned int seed;
        int fd_epoll;
        int fd_timer;

        /* configuration */
        NAcdConfig config;

        /* runtime */
        int fd_socket;
        unsigned int state;
        unsigned int n_iteration;
        unsigned int n_conflicts;
        unsigned int defend;
        uint64_t last_defend;
        uint64_t last_conflict;

        /* pending events */
        CList events;
        NAcdEventNode *current;
};

static int n_acd_errno(void) {
        /*
         * Compilers continuously warn about uninitialized variables since they
         * cannot deduce that `return -errno;` will always be negative. This
         * small wrapper makes sure compilers figure that out. Use it as
         * replacement for `errno` read access. Yes, it generates worse code,
         * but only marginally and only affects slow-paths.
         */
        return abs(errno) ? : EIO;
}

static int n_acd_event_node_new(NAcdEventNode **nodep, unsigned int event) {
        NAcdEventNode *node;

        node = calloc(1, sizeof(*node));
        if (!node)
                return -ENOMEM;

        node->event.event = event;
        node->link = (CList)C_LIST_INIT(node->link);

        *nodep = node;

        return 0;
}

static NAcdEventNode *n_acd_event_node_free(NAcdEventNode *node) {
        if (!node)
                return NULL;

        c_list_unlink(&node->link);
        free(node);

        return NULL;
}

_public_ int n_acd_new(NAcd **acdp) {
        struct timespec ts;
        NAcd *acd;
        void *p;
        int r;

        acd = calloc(1, sizeof(*acd));
        if (!acd)
                return -ENOMEM;

        acd->fd_epoll = -1;
        acd->fd_timer = -1;
        acd->fd_socket = -1;
        acd->state = N_ACD_STATE_INIT;
        acd->defend = N_ACD_DEFEND_NEVER;
        acd->events = (CList)C_LIST_INIT(acd->events);

        /*
         * We need random jitter for all timeouts when handling ARP probes. Use
         * AT_RANDOM to get a seed for rand_r(3p), if available (should always
         * be available on linux). See the time-out scheduler for details.
         * Additionally, we include the current time in the seed. This avoids
         * using the same jitter in case you run multiple ACD engines in the
         * same process.
         */
        p = (void *)getauxval(AT_RANDOM);
        if (p)
                acd->seed = *(unsigned int *)p;

        r = clock_gettime(CLOCK_BOOTTIME, &ts);
        if (r < 0) {
                r = -n_acd_errno();
                goto error;
        }

        acd->seed ^= ts.tv_nsec ^ ts.tv_sec;

        acd->fd_epoll = epoll_create1(EPOLL_CLOEXEC);
        if (acd->fd_epoll < 0) {
                r = -n_acd_errno();
                goto error;
        }

        acd->fd_timer = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (acd->fd_timer < 0) {
                r = -n_acd_errno();
                goto error;
        }

        r = epoll_ctl(acd->fd_epoll, EPOLL_CTL_ADD, acd->fd_timer,
                      &(struct epoll_event){
                              .events = EPOLLIN,
                              .data.u32 = N_ACD_EPOLL_TIMER,
                      });
        if (r < 0) {
                r = -n_acd_errno();
                goto error;
        }

        *acdp = acd;
        return 0;

error:
        n_acd_free(acd);
        return r;
}

_public_ NAcd *n_acd_free(NAcd *acd) {
        if (!acd)
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

_public_ void n_acd_get_fd(NAcd *acd, int *fdp) {
        *fdp = acd->fd_epoll;
}

static int n_acd_push_event(NAcd *acd, unsigned int event, uint16_t *operation, uint8_t (*sender)[6], uint8_t (*target)[4]) {
        NAcdEventNode *node;
        int r;

        r = n_acd_event_node_new(&node, event);
        if (r < 0)
                return r;

        switch (event) {
        case N_ACD_EVENT_USED:
                node->event.used.operation = be16toh(*operation);
                memcpy(&node->event.used.sender, sender, sizeof(node->event.used.sender));
                memcpy(&node->event.used.target, target, sizeof(node->event.used.target));
                break;
        case N_ACD_EVENT_CONFLICT:
                node->event.conflict.operation = be16toh(*operation);
                memcpy(&node->event.conflict.sender, sender, sizeof(node->event.conflict.sender));
                memcpy(&node->event.conflict.target, target, sizeof(node->event.conflict.target));
                break;
        case N_ACD_EVENT_DEFENDED:
                node->event.defended.operation = be16toh(*operation);
                memcpy(&node->event.defended.sender, sender, sizeof(node->event.defended.sender));
                memcpy(&node->event.defended.target, target, sizeof(node->event.defended.target));
                break;
        case N_ACD_EVENT_READY:
        case N_ACD_EVENT_DOWN:
                break;
        default:
                assert(0);
        }

        c_list_link_tail(&acd->events, &node->link);

        return 0;
}

static void n_acd_flush_events(NAcd *acd) {
        NAcdEventNode *node;

        while ((node = c_list_first_entry(&acd->events, NAcdEventNode, link)))
                n_acd_event_node_free(node);
}

static int n_acd_now(uint64_t *nowp) {
        struct timespec ts;
        int r;

        r = clock_gettime(CLOCK_BOOTTIME, &ts);
        if (r < 0)
                return -n_acd_errno();

        *nowp = ts.tv_sec * UINT64_C(1000000) + ts.tv_nsec / UINT64_C(1000);
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
                return -n_acd_errno();

        return 0;
}

static int n_acd_send(NAcd *acd, const struct in_addr *spa) {
        struct sockaddr_ll address = {
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_ARP),
                .sll_ifindex = acd->config.ifindex,
                .sll_halen = ETH_ALEN,
                .sll_addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };
        struct ether_arp arp = {
                .ea_hdr.ar_hrd = htobe16(ARPHRD_ETHER),
                .ea_hdr.ar_pro = htobe16(ETHERTYPE_IP),
                .ea_hdr.ar_hln = ETH_ALEN,
                .ea_hdr.ar_pln = sizeof(uint32_t),
                .ea_hdr.ar_op = htobe16(ARPOP_REQUEST),
        };
        ssize_t l;

        memcpy(arp.arp_sha, acd->config.mac.ether_addr_octet, ETH_ALEN);
        memcpy(arp.arp_tpa, &acd->config.ip.s_addr, sizeof(uint32_t));

        if (spa)
                memcpy(arp.arp_spa, &spa->s_addr, sizeof(spa->s_addr));

        l = sendto(acd->fd_socket, &arp, sizeof(arp), MSG_NOSIGNAL, (struct sockaddr *)&address, sizeof(address));
        if (l == (ssize_t)sizeof(arp)) {
                /* Packet was properly sent. */
                return 0;
        } else if (l >= 0) {
                /*
                 * Ugh. The packet was truncated. This should not happen, but
                 * lets just pretend the packet was dropped.
                 */
                return 0;
        } else if (errno == EAGAIN || errno == ENOBUFS) {
                /*
                 * In case the output buffer is full, the packet is silently
                 * dropped. This is just as if the physical layer happened to
                 * drop the packet. We are not on a reliable medium, so no
                 * reason to pretend we are.
                 */
                return 0;
        } else if (errno == ENETDOWN || errno == ENXIO) {
                /*
                 * We get ENETDOWN if the network-device goes down or is
                 * removed. ENXIO might happen on async send-operations if the
                 * network-device was unplugged and thus the kernel is no
                 * longer aware of it.
                 * In any case, we do not allow proceeding with this socket. We
                 * stop the engine and notify the user gracefully.
                 */
                return -N_ACD_E_DOWN;
        }

        return -n_acd_errno();
}

static void n_acd_remember_conflict(NAcd *acd, uint64_t now) {
        if (++acd->n_conflicts >= N_ACD_RFC_MAX_CONFLICTS) {
                acd->n_conflicts = N_ACD_RFC_MAX_CONFLICTS;
                acd->last_conflict = now;
        }
}

static int n_acd_handle_timeout(NAcd *acd, uint64_t v) {
        int r;

        switch (acd->state) {
        case N_ACD_STATE_PROBING:
                /*
                 * We are still PROBING. We send 3 probes with a random timeout
                 * scheduled between each. If, after a fixed timeout, we did
                 * not receive any conflict we consider the probing successful.
                 */
                if (acd->n_iteration >= N_ACD_RFC_PROBE_NUM) {
                        /*
                         * All 3 probes succeeded and we waited enough to
                         * consider this address usable by now. Do not announce
                         * the address, yet. We must first give the caller a
                         * chance to configure the address (so they can answer
                         * ARP requests), before announcing it. But our
                         * callbacks are not necessarily synchronous (we want
                         * to allow IPC there), so just notify the caller and
                         * wait for further instructions, thus effectively
                         * increasing the probe-wait.
                         */
                        r = n_acd_push_event(acd, N_ACD_EVENT_READY, NULL, NULL, NULL);
                        if (r)
                                return r;
                } else {
                        /*
                         * We have not sent all 3 probes, yet. A timer fired,
                         * so we are ready to send the next probe. If this is
                         * the third probe, schedule a timer for ANNOUNCE_WAIT
                         * to give other peers a chance to answer. If this is
                         * not the third probe, wait between PROBE_MIN and
                         * PROBE_MAX for the next probe.
                         */

                        r = n_acd_send(acd, NULL);
                        if (r < 0)
                                return r;

                        if (++acd->n_iteration >= N_ACD_RFC_PROBE_NUM)
                                r = n_acd_schedule(acd, N_ACD_RFC_ANNOUNCE_WAIT_USEC, 0);
                        else
                                r = n_acd_schedule(acd, N_ACD_RFC_PROBE_MIN_USEC,
                                                   N_ACD_RFC_PROBE_MAX_USEC - N_ACD_RFC_PROBE_MIN_USEC);
                        if (r < 0)
                                return r;
                }

                break;

        case N_ACD_STATE_ANNOUNCING:
                /*
                 * We are ANNOUNCING, meaning the caller configured the address
                 * on the interface and is actively using it. We send 3
                 * announcements out, in a short interval, and then just
                 * perform passive conflict detection.
                 * Note that once all 3 announcements are sent, we no longer
                 * schedule a timer, so this part should not trigger, anymore.
                 */

                r = n_acd_send(acd, &acd->config.ip);
                if (r < 0)
                        return r;

                if (++acd->n_iteration < N_ACD_RFC_ANNOUNCE_NUM) {
                        r = n_acd_schedule(acd, N_ACD_RFC_ANNOUNCE_WAIT_USEC, 0);
                        if (r < 0)
                                return r;
                }

                break;

        case N_ACD_STATE_INIT:
        default:
                /*
                 * There are no timeouts in these states. If we trigger one,
                 * something is fishy. Let the caller deal with this.
                 */
                return -EIO;
        }

        return 0;
}

static int n_acd_handle_packet(NAcd *acd, struct ether_arp *packet) {
        bool hard_conflict;
        uint64_t now;
        int r;

        /*
         * Via BPF we discard any non-conflict packets. There are only 2 types
         * that can pass: A conflict on the Sender Protocol Address, or a
         * conflict on the Target Protocol Address.
         *
         * The former we call a hard-conflict. It implies that the sender uses
         * the address already. We must always catch this and in some way react
         * to it. Any kind, REQUEST or REPLY must be caught (though it is
         * unlikely that we ever catch REPLIES since they tend to be unicasts).
         *
         * However, in case the Target Protocol Address matches, we just know
         * that somebody is looking for the address. Hence, we must also check
         * that the packet is an ARP-Probe (Sender Protocol Address is 0). If
         * it is, it means someone else does ACD on our address. We call this a
         * soft conflict.
         */
        if (!memcmp(packet->arp_spa, (uint8_t[4]){ }, sizeof(packet->arp_spa)) &&
            !memcmp(packet->arp_tpa, &acd->config.ip.s_addr, sizeof(packet->arp_tpa)) &&
            packet->ea_hdr.ar_op == htobe16(ARPOP_REQUEST)) {
                hard_conflict = false;
        } else if (!memcmp(packet->arp_spa, &acd->config.ip.s_addr, sizeof(packet->arp_spa))) {
                hard_conflict = true;
        } else {
                /*
                 * Ignore anything that is specific enough to match the BPF
                 * filter, but is none of the conflicts described above.
                 */
                return 0;
        }

        r = n_acd_now(&now);
        if (r < 0)
                return r;

        switch (acd->state) {
        case N_ACD_STATE_PROBING:
                /*
                 * Regardless whether this is a hard or soft conflict, we must
                 * treat this as a probe failure. That is, notify the caller of
                 * the conflict and wait for further instructions. We do not
                 * react to this, until the caller tells us what to do. But we
                 * immediately disable the timer, since there is no point in
                 * continuing the probing.
                 */
                n_acd_remember_conflict(acd, now);
                timerfd_settime(acd->fd_timer, 0, &(struct itimerspec){}, NULL);
                r = n_acd_push_event(acd, N_ACD_EVENT_USED, &packet->ea_hdr.ar_op, &packet->arp_sha, &packet->arp_tpa);
                if (r)
                        return r;

                break;

        case N_ACD_STATE_ANNOUNCING:
                /*
                 * We were already instructed to announce the address, which
                 * means the address is configured and in use. Hence, the
                 * caller is responsible to serve regular ARP queries. Meaning,
                 * we can ignore any soft conflicts (other peers doing ACD).
                 *
                 * But if we see a hard-conflict, we either defend the address
                 * according to the caller's instructions, or we report the
                 * conflict and bail out.
                 */

                if (!hard_conflict)
                        break;

                if (acd->defend == N_ACD_DEFEND_NEVER) {
                        n_acd_remember_conflict(acd, now);
                        timerfd_settime(acd->fd_timer, 0, &(struct itimerspec){}, NULL);
                        r = n_acd_push_event(acd, N_ACD_EVENT_CONFLICT, &packet->ea_hdr.ar_op, &packet->arp_sha, &packet->arp_tpa);
                        if (r)
                                return r;
                } else {
                        if (now > acd->last_defend + N_ACD_RFC_DEFEND_INTERVAL_USEC) {
                                r = n_acd_send(acd, &acd->config.ip);
                                if (r < 0)
                                        return r;

                                acd->last_defend = now;
                                r = n_acd_push_event(acd, N_ACD_EVENT_DEFENDED, &packet->ea_hdr.ar_op, &packet->arp_sha, &packet->arp_tpa);
                                if (r)
                                        return r;
                        } else if (acd->defend == N_ACD_DEFEND_ONCE) {
                                n_acd_remember_conflict(acd, now);
                                timerfd_settime(acd->fd_timer, 0, &(struct itimerspec){}, NULL);
                                r = n_acd_push_event(acd, N_ACD_EVENT_CONFLICT, &packet->ea_hdr.ar_op, &packet->arp_sha, &packet->arp_tpa);
                                if (r)
                                        return r;
                        } else {
                                r = n_acd_push_event(acd, N_ACD_EVENT_DEFENDED, &packet->ea_hdr.ar_op, &packet->arp_sha, &packet->arp_tpa);
                                if (r)
                                        return r;
                        }
                }

                break;

        case N_ACD_STATE_INIT:
        default:
                /*
                 * The socket should not be dispatched in those states, since
                 * it is neither allocated nor added to epoll. Fail hard if we
                 * trigger this somehow.
                 */
                return -EIO;
        }

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
                        return -n_acd_errno();
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

static int n_acd_dispatch_socket(NAcd *acd, struct epoll_event *event) {
        struct ether_arp packet;
        ssize_t l;

        /*
         * Regardless whether EPOLLIN is set in @event->events, we always
         * invoke recv(2). This is a safety-net for sockets, which always fetch
         * queued errors on all syscalls. That means, if anything failed on the
         * socket, we will be notified via recv(2). This simplifies the code
         * and avoid magic EPOLLIN/ERR/HUP juggling.
         *
         * Note that we must use recv(2) over read(2), since the latter cannot
         * deal with empty packets properly.
         */
        l = recv(acd->fd_socket, &packet, sizeof(packet), MSG_TRUNC);
        if (l == (ssize_t)sizeof(packet)) {
                /*
                 * We read a full ARP packet. We never fall-through to EPOLLHUP
                 * handling, as we always must drain buffers first.
                 */
                return n_acd_handle_packet(acd, &packet);
        } else if (l >= 0) {
                /*
                 * The BPF filter discards wrong packets, so error out
                 * if something slips through for any reason. Don't silently
                 * ignore it, since we explicitly want to know if something
                 * went fishy.
                 */
                return -EIO;
        } else if (errno == ENETDOWN || errno == ENXIO) {
                /*
                 * We get ENETDOWN if the network-device goes down or is
                 * removed. ENXIO might happen on async send-operations if the
                 * network-device was unplugged and thus the kernel is no
                 * longer aware of it.
                 * In any case, we do not allow proceeding with this socket. We
                 * stop the engine and notify the user gracefully.
                 */
                return -N_ACD_E_DOWN;
        } else if (errno != EAGAIN) {
                /*
                 * Cannot dispatch the packet. This might be due to OOM, HUP,
                 * or something else. We cannot handle it gracefully so forward
                 * to the caller.
                 */
                return -n_acd_errno();
        }

        /*
         * We cannot read data from the socket (we got EAGAIN). As a safety net
         * check for EPOLLHUP/ERR. Those cannot be disabled with epoll, so we
         * must make sure to not busy-loop by ignoring them. Note that we know
         * recv(2) on sockets to return an error if either of these epoll-flags
         * is set. Hence, if we did not handle it above, we have no other way
         * but treating those flags as fatal errors and returning them to the
         * caller.
         */
        if (event->events & (EPOLLHUP | EPOLLERR))
                return -EIO;

        return 0;
}

_public_ int n_acd_dispatch(NAcd *acd) {
        struct epoll_event events[2];
        int n, i, r = 0;

        n = epoll_wait(acd->fd_epoll, events, sizeof(events) / sizeof(*events), 0);
        if (n < 0) {
                return -n_acd_errno();
        }

        for (i = 0; i < n; ++i) {
                switch (events[i].data.u32) {
                case N_ACD_EPOLL_TIMER:
                        r = n_acd_dispatch_timer(acd, events + i);
                        break;
                case N_ACD_EPOLL_SOCKET:
                        r = n_acd_dispatch_socket(acd, events + i);
                        break;
                default:
                        r = 0;
                        break;
                }

                if (r != 0)
                        break;
        }

        if (r == -N_ACD_E_DOWN) {
                /*
                 * N_ACD_E_DOWN is synthesized whenever we notice
                 * ENETDOWN-related errors on the network interface. This
                 * allows bailing out of deep call-paths and then handling the
                 * error gracefully here.
                 */
                n_acd_stop(acd);
                r = n_acd_push_event(acd, N_ACD_EVENT_DOWN, NULL, NULL, NULL);
                if (r)
                        return r;

                return 0;
        }

        return r;
}

_public_ int n_acd_pop_event(NAcd *acd, NAcdEvent **eventp) {
        acd->current = n_acd_event_node_free(acd->current);

        if (c_list_is_empty(&acd->events))
                return N_ACD_E_AGAIN;

        acd->current = c_list_first_entry(&acd->events, NAcdEventNode, link);
        c_list_unlink_init(&acd->current->link);

        if (eventp)
                *eventp = &acd->current->event;

        return 0;
}

static int n_acd_bind_socket(NAcd *acd, int s) {
        /*
         * Due to strict aliasing, we cannot get uint32_t/uint16_t pointers to
         * acd->config.mac, so provide a union accessor.
         */
        const union {
                uint8_t u8[6];
                uint16_t u16[3];
                uint32_t u32[1];
        } mac = {
                .u8 = {
                        acd->config.mac.ether_addr_octet[0],
                        acd->config.mac.ether_addr_octet[1],
                        acd->config.mac.ether_addr_octet[2],
                        acd->config.mac.ether_addr_octet[3],
                        acd->config.mac.ether_addr_octet[4],
                        acd->config.mac.ether_addr_octet[5],
                }
        };
        struct sock_filter filter[] = {
                /*
                 * Basic ARP header validation. Make sure the packet-length,
                 * wire type, protocol type, and address lengths are correct.
                 */
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                                          /* A <- packet length */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, sizeof(struct ether_arp), 1, 0),                            /* packet == arp packet ? */
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
                BPF_STMT(BPF_LD + BPF_IMM, be32toh(acd->config.ip.s_addr)),                                     /* A <- clients IP */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ether_arp, arp_spa)),                        /* A <- SPA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                         /* X xor A */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),                                                   /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 65535),                                                               /* return all */
                BPF_STMT(BPF_LD + BPF_IMM, be32toh(acd->config.ip.s_addr)),                                     /* A <- clients IP */
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
                .sll_ifindex = acd->config.ifindex,
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
                return -n_acd_errno();

        /*
         * Bind the packet-socket to ETH_P_ARP and the specified network
         * interface.
         */
        r = bind(s, (struct sockaddr *)&address, sizeof(address));
        if (r < 0)
                return -n_acd_errno();

        return 0;
}

static int n_acd_setup_socket(NAcd *acd) {
        int r, s;

        s = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -n_acd_errno();

        r = n_acd_bind_socket(acd, s);
        if (r < 0)
                goto error;

        r = epoll_ctl(acd->fd_epoll, EPOLL_CTL_ADD, s,
                      &(struct epoll_event){
                              .events = EPOLLIN,
                              .data.u32 = N_ACD_EPOLL_SOCKET,
                      });
        if (r < 0) {
                r = -n_acd_errno();
                goto error;
        }

        acd->fd_socket = s;
        return 0;

error:
        close(s);
        return r;
}

static bool n_acd_is_running(NAcd *acd) {
        return acd->state != N_ACD_STATE_INIT;
}

_public_ int n_acd_start(NAcd *acd, NAcdConfig *config) {
        uint64_t now, delay;
        int r;

        if (!config->ifindex ||
            !memcmp(config->mac.ether_addr_octet, (uint8_t[ETH_ALEN]){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, ETH_ALEN) ||
            !config->ip.s_addr)
                return N_ACD_E_INVALID_ARGUMENT;

        if (n_acd_is_running(acd))
                return N_ACD_E_STARTED;

        acd->config = *config;

        r = n_acd_setup_socket(acd);
        if (r < 0)
                goto error;

        r = n_acd_now(&now);
        if (r < 0)
                goto error;

        if (now < acd->last_conflict + N_ACD_RFC_RATE_LIMIT_INTERVAL_USEC)
                delay = acd->last_conflict + N_ACD_RFC_RATE_LIMIT_INTERVAL_USEC - now;
        else
                delay = 0;

        r = n_acd_schedule(acd, delay, N_ACD_RFC_PROBE_WAIT_USEC);
        if (r < 0)
                goto error;

        acd->state = N_ACD_STATE_PROBING;
        acd->defend = N_ACD_DEFEND_NEVER;
        acd->n_iteration = 0;
        acd->last_defend = 0;
        return 0;

error:
        n_acd_stop(acd);
        return r;
}

_public_ void n_acd_stop(NAcd *acd) {
        acd->state = N_ACD_STATE_INIT;
        acd->defend = N_ACD_DEFEND_NEVER;
        acd->n_iteration = 0;
        acd->last_defend = 0;
        timerfd_settime(acd->fd_timer, 0, &(struct itimerspec){}, NULL);
        n_acd_flush_events(acd);

        assert(c_list_is_empty(&acd->events));

        if (acd->fd_socket >= 0) {
                assert(acd->fd_epoll >= 0);
                epoll_ctl(acd->fd_epoll, EPOLL_CTL_DEL, acd->fd_socket, NULL);
                close(acd->fd_socket);
                acd->fd_socket = -1;
        }
}

_public_ int n_acd_announce(NAcd *acd, unsigned int defend) {
        uint64_t now;
        int r;

        if (defend >= _N_ACD_DEFEND_N)
                return N_ACD_E_INVALID_ARGUMENT;
        if (!n_acd_is_running(acd))
                return N_ACD_E_STOPPED;

        /*
         * Sending announcements means we finished probing and use the address
         * now. We therefore reset the conflict counter in case we adhered to
         * the rate-limit. Since probing is properly delayed, a well-behaving
         * client will always reset the conflict counter here. However, if you
         * force-use an address regardless of conflicts, then this will not
         * trigger and the conflict counter stays untouched.
         */
        r = n_acd_now(&now);
        if (r < 0)
                return r;

        if (now >= acd->last_conflict + N_ACD_RFC_RATE_LIMIT_INTERVAL_USEC)
                acd->n_conflicts = 0;

        /*
         * Instead of sending the first announcement here, we schedule an idle
         * timer. This avoids possibly recursing into the user callback. We
         * should never trigger callbacks from arbitrary stacks, but always
         * restrict them to the dispatcher.
         */
        r = n_acd_schedule(acd, 0, 0);
        if (r < 0)
                return r;

        acd->state = N_ACD_STATE_ANNOUNCING;
        acd->defend = defend;
        acd->n_iteration = 0;
        return 0;
}
