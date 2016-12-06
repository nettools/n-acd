#pragma once

/*
 * Test Helpers
 * Bunch of helpers to setup the environment for networking tests. This
 * includes net-namespace setups, veth setups, and more.
 */

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "n-acd.h"

static inline void test_veth_new(int *parent_indexp,
                                 struct ether_addr *parent_macp,
                                 int *child_indexp,
                                 struct ether_addr *child_macp) {
        struct ifreq ifr;
        int r, s;

        /* Eww... but it works. */
        r = system("ip link add type veth");
        assert(r == 0);
        r = system("ip link set veth0 up");
        assert(r == 0);
        r = system("ip link set veth1 up");
        assert(r == 0);

        s = socket(AF_INET, SOCK_DGRAM, 0);
        assert(s >= 0);

        if (parent_indexp) {
                *parent_indexp = if_nametoindex("veth0");
                assert(*parent_indexp > 0);
        }

        if (child_indexp) {
                *child_indexp = if_nametoindex("veth1");
                assert(*child_indexp > 0);
        }

        if (parent_macp) {
                memset(&ifr, 0, sizeof(ifr));
                strcpy(ifr.ifr_name, "veth0");
                r = ioctl(s, SIOCGIFHWADDR, &ifr);
                assert(r >= 0);
                memcpy(parent_macp->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        if (child_macp) {
                memset(&ifr, 0, sizeof(ifr));
                strcpy(ifr.ifr_name, "veth1");
                r = ioctl(s, SIOCGIFHWADDR, &ifr);
                assert(r >= 0);
                memcpy(child_macp->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        close(s);
}

static inline int test_setup(void) {
        int r;

        r = unshare(CLONE_NEWNET);
        if (r < 0) {
                assert(errno == EPERM);
                return 77;
        }

        return 0;
}
