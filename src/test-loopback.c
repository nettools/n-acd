/*
 * Test on loopback device
 * This runs the ACD engine on the loopback device, effectively testing the BPF
 * filter of ACD to discard its own packets. This might happen on
 * non-spanning-tree networks, or on networks that echo packets.
 */

#include <stdlib.h>
#include "test.h"

static void test_loopback(int ifindex, const struct ether_addr *mac) {
        NAcdConfig config = {
                .ifindex = ifindex,
                .mac = *mac,
                .ip = { htobe32((192 << 24) | (168 << 16) | (1 << 0)) },
        };
        struct pollfd pfds;
        NAcd *acd;
        int r, fd;

        r = n_acd_new(&acd);
        assert(!r);

        n_acd_get_fd(acd, &fd);
        r = n_acd_start(acd, &config);
        assert(!r);

        for (;;) {
                NAcdEvent *event;
                pfds = (struct pollfd){ .fd = fd, .events = POLLIN };
                r = poll(&pfds, 1, -1);
                assert(r >= 0);

                r = n_acd_dispatch(acd);
                assert(!r);

                r = n_acd_pop_event(acd, &event);
                if (!r) {
                        assert(event->event == N_ACD_EVENT_READY);
                        break;
                } else {
                        assert(r == N_ACD_E_DONE);
                }
        }

        n_acd_free(acd);
}

int main(int argc, char **argv) {
        struct ether_addr mac;
        int r, ifindex;

        r = test_setup();
        if (r)
                return r;

        r = system("ip link set lo up");
        assert(r == 0);
        test_if_query("lo", &ifindex, &mac);
        test_loopback(ifindex, &mac);

        return 0;
}
