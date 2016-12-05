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
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "n-acd.h"
