/*
 * Test on loopback device
 * This runs the ACD engine on the loopback device, effectively testing the BPF
 * filter of ACD to discard its own packets. This might happen on
 * non-spanning-tree networks, or on networks that echo packets.
 */

#include <stdlib.h>
#include "test.h"

static void test_loopback_fn(NAcd *acd, void *userdata, unsigned int event, const struct ether_arp *conflict) {
        bool *running = userdata;

        assert(event == N_ACD_EVENT_READY);
        *running = false;
}

static void test_loopback(int ifindex, const struct ether_addr *mac) {
        struct pollfd pfds;
        bool running;
        NAcd *acd;
        int r, fd;

        r = n_acd_new(&acd);
        assert(r >= 0);

        r = n_acd_set_ifindex(acd, ifindex);
        assert(r >= 0);
        r = n_acd_set_mac(acd, mac);
        assert(r >= 0);
        r = n_acd_set_ip(acd, &(struct in_addr){ htobe32((192 << 24) | (168 << 16) | (1 << 0)) });
        assert(r >= 0);

        n_acd_get_fd(acd, &fd);
        r = n_acd_start(acd, test_loopback_fn, &running);
        assert(r >= 0);

        for (running = true; running; ) {
                pfds = (struct pollfd){ .fd = fd, .events = POLLIN };
                r = poll(&pfds, 1, -1);
                assert(r >= 0);

                r = n_acd_dispatch(acd);
                assert(r >= 0);
        }

        n_acd_unref(acd);
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
