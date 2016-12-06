/*
 * Test with unused address twice in parallel
 * This runs the ACD engine with an unused address on a veth pair, but it runs
 * it on both ends. We expect the PROBE to fail on at least one of the devices.
 */

#include <stdlib.h>
#include "test.h"

static void test_unused_fn(NAcd *acd, void *userdata, unsigned int event, const struct ether_arp *conflict) {
        int *state = userdata;

        assert(event == N_ACD_EVENT_READY || event == N_ACD_EVENT_USED);
        *state = !!(event == N_ACD_EVENT_READY);
}

static void test_unused(int ifindex1, const struct ether_addr *mac1, int ifindex2, const struct ether_addr *mac2) {
        struct pollfd pfds[2];
        NAcd *acd1, *acd2;
        int r, fd1, fd2, state1, state2;

        r = n_acd_new(&acd1);
        assert(r >= 0);
        r = n_acd_new(&acd2);
        assert(r >= 0);

        r = n_acd_set_ifindex(acd1, ifindex1);
        assert(r >= 0);
        r = n_acd_set_mac(acd1, mac1);
        assert(r >= 0);
        r = n_acd_set_ip(acd1, &(struct in_addr){ htobe32((192 << 24) | (168 << 16) | (1 << 0)) });
        assert(r >= 0);

        r = n_acd_set_ifindex(acd2, ifindex2);
        assert(r >= 0);
        r = n_acd_set_mac(acd2, mac2);
        assert(r >= 0);
        r = n_acd_set_ip(acd2, &(struct in_addr){ htobe32((192 << 24) | (168 << 16) | (1 << 0)) });
        assert(r >= 0);

        n_acd_get_fd(acd1, &fd1);
        n_acd_get_fd(acd2, &fd2);

        r = n_acd_start(acd1, test_unused_fn, &state1);
        assert(r >= 0);
        r = n_acd_start(acd2, test_unused_fn, &state2);
        assert(r >= 0);

        for (state1 = state2 = -1; state1 == -1 || state2 == -1; ) {
                pfds[0] = (struct pollfd){ .fd = fd1, .events = (state1 == -1) ? POLLIN : 0 };
                pfds[1] = (struct pollfd){ .fd = fd2, .events = (state2 == -1) ? POLLIN : 0 };
                r = poll(pfds, sizeof(pfds) / sizeof(*pfds), -1);
                assert(r >= 0);

                if (state1 == -1) {
                        r = n_acd_dispatch(acd1);
                        assert(r >= 0);
                }

                if (state2 == -1) {
                        r = n_acd_dispatch(acd2);
                        assert(r >= 0);
                }
        }

        n_acd_unref(acd1);
        n_acd_unref(acd2);

        assert(!state1 || !state2);
}

int main(int argc, char **argv) {
        struct ether_addr mac1, mac2;
        int r, ifindex1, ifindex2;

        r = test_setup();
        if (r)
                return r;

        test_veth_new(&ifindex1, &mac1, &ifindex2, &mac2);
        test_unused(ifindex1, &mac1, ifindex2, &mac2);

        return 0;
}
