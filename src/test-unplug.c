/*
 * Unplug device during test run
 * Run the ACD engine with an address that is not used by anyone else on the
 * link, but DOWN or UNPLUG the device while running.
 */

#include <stdlib.h>
#include "test.h"

static void test_unplug_down_fn(NAcd *acd, void *userdata, unsigned int event, const struct ether_arp *conflict) {
        int ifindex, *state = userdata;

        if (event == N_ACD_EVENT_DOWN) {
                *state = 0;
        } else {
                assert(event == N_ACD_EVENT_READY);
                *state = 1;
                n_acd_get_ifindex(acd, &ifindex);
                test_veth_cmd(ifindex, "down");
        }
}

static void test_unplug_down(int ifindex, const struct ether_addr *mac, unsigned int run) {
        struct pollfd pfds;
        int state;
        NAcd *acd;
        int r, fd;

        if (!run--)
                test_veth_cmd(ifindex, "down");

        r = n_acd_new(&acd);
        assert(r >= 0);

        r = n_acd_set_ifindex(acd, ifindex);
        assert(r >= 0);
        r = n_acd_set_mac(acd, mac);
        assert(r >= 0);
        r = n_acd_set_ip(acd, &(struct in_addr){ htobe32((192 << 24) | (168 << 16) | (1 << 0)) });
        assert(r >= 0);

        if (!run--)
                test_veth_cmd(ifindex, "down");

        n_acd_get_fd(acd, &fd);
        r = n_acd_start(acd, test_unplug_down_fn, &state);
        assert(r >= 0);

        if (!run--)
                test_veth_cmd(ifindex, "down");

        for (state = -1; state; ) {
                pfds = (struct pollfd){ .fd = fd, .events = POLLIN };
                r = poll(&pfds, 1, -1);
                assert(r >= 0);

                if (!run--)
                        test_veth_cmd(ifindex, "down");

                r = n_acd_dispatch(acd);
                assert(r >= 0);
        }

        n_acd_unref(acd);
}

int main(int argc, char **argv) {
        struct ether_addr mac;
        unsigned int i;
        int r, ifindex;

        r = test_setup();
        if (r)
                return r;

        test_veth_new(&ifindex, &mac, NULL, NULL);

        for (i = 0; i < 5; ++i) {
                test_unplug_down(ifindex, &mac, i);
                test_veth_cmd(ifindex, "up");
        }

        return 0;
}
