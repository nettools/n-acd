/*
 * Tests for n-acd API
 * This verifies the visibility and availability of the public API of the
 * n-acd library.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "n-acd.h"

static void test_api(void) {
        NAcd *acd = NULL;
        int r;

        n_acd_unrefp(&acd);

        r = n_acd_new(&acd);
        assert(r >= 0);
        n_acd_ref(acd);
        n_acd_unref(acd);

        n_acd_unref(acd);
}

int main(int argc, char **argv) {
        test_api();
        return 0;
}
