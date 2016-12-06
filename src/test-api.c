/*
 * Tests for n-acd API
 * This verifies the visibility and availability of the public API of the
 * n-acd library.
 */

#include <stdlib.h>
#include "test.h"

static void test_api_constants(void) {
        assert(N_ACD_DEFEND_NEVER != _N_ACD_DEFEND_N);
        assert(N_ACD_DEFEND_ONCE != _N_ACD_DEFEND_N);
        assert(N_ACD_DEFEND_ALWAYS != _N_ACD_DEFEND_N);

        assert(N_ACD_EVENT_READY != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_USED != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_DEFENDED != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_CONFLICT != _N_ACD_EVENT_N);
        assert(N_ACD_EVENT_DOWN != _N_ACD_EVENT_N);
}

static void test_api_management(void) {
        NAcd *acd = NULL;
        int r;

        /* new/ref/unref/unrefp */

        n_acd_unrefp(&acd);

        r = n_acd_new(&acd);
        assert(r >= 0);
        n_acd_ref(acd);
        n_acd_unref(acd);


        n_acd_unref(acd);
}

static void test_api_configuration(void) {
        struct ether_addr mac;
        struct in_addr ip;
        NAcd *acd;
        int r, ifindex;

        /* {get,set}_{ifindex,mac,ip} */

        r = n_acd_new(&acd);
        assert(r >= 0);

        r = n_acd_set_ifindex(acd, 1);
        assert(r >= 0);
        r = n_acd_set_mac(acd, &(struct ether_addr){ { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54 } });
        assert(r >= 0);
        r = n_acd_set_ip(acd, &(struct in_addr){ htobe32((127 << 24) | (1 << 0)) });
        assert(r >= 0);

        n_acd_get_ifindex(acd, &ifindex);
        assert(ifindex == 1);
        n_acd_get_mac(acd, &mac);
        assert(!memcmp(mac.ether_addr_octet, (uint8_t[ETH_ALEN]){ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54 }, ETH_ALEN));
        n_acd_get_ip(acd, &ip);
        assert(ip.s_addr == htobe32((127 << 24) | (1 << 0)));

        n_acd_unref(acd);
}

static void test_api_runtime(void) {
        NAcdFn fn = NULL;
        NAcd *acd;
        int r;

        /* get_fd/is_running/dispatch/start/stop/announce */

        r = n_acd_new(&acd);
        assert(r >= 0);

        n_acd_get_fd(acd, &r);
        assert(r >= 0);
        r = n_acd_is_running(acd);
        assert(!r);
        r = n_acd_dispatch(acd);
        assert(r >= 0);
        r = n_acd_start(acd, fn, NULL);
        assert(r < 0);
        n_acd_stop(acd);
        r = n_acd_announce(acd, N_ACD_DEFEND_NEVER);
        assert(r < 0);

        n_acd_unref(acd);
}

int main(int argc, char **argv) {
        test_api_constants();
        test_api_management();
        test_api_configuration();
        test_api_runtime();
        return 0;
}
