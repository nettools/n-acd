/*
 * Tests for timer utility library
 */

#include <stdio.h>
#include <errno.h>

#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include "timer.h"

#define N_TIMEOUTS (10000)

static void test_api(void) {
        Timer timer = TIMER_NULL(timer);
        Timeout t1 = TIMEOUT_INIT(t1), t2 = TIMEOUT_INIT(t2), *t;
        int r;

        r = timer_init(&timer);
        assert(!r);

        timeout_schedule(&t1, &timer, 1);
        timeout_schedule(&t2, &timer, 2);

        r = timer_pop(&timer, 10, &t);
        assert(!r);
        assert(t == &t1);

        timeout_unschedule(&t2);

        r = timer_pop(&timer, 10, &t);
        assert(!r);
        assert(!t);

        timer_deinit(&timer);
}

static void test_pop(void) {
        Timer timer = TIMER_NULL(timer);
        Timeout timeouts[N_TIMEOUTS] = {};
        uint64_t times[N_TIMEOUTS] = {};
        size_t n_timeouts = 0;
        bool armed;
        Timeout *t;
        int r;

        r = timer_init(&timer);
        assert(!r);

        for(size_t i = 0; i < N_TIMEOUTS; ++i) {
                timeouts[i] = (Timeout)TIMEOUT_INIT(timeouts[i]);
                times[i] = rand() % 128 + 1;
                timeout_schedule(&timeouts[i], &timer, times[i]);
        }

        armed = true;

        for(size_t i = 0; i <= 128; ++i) {
                if (armed) {
                        struct pollfd pfd = {
                                .fd = timer.fd,
                                .events = POLLIN,
                        };
                        uint64_t count;

                        r = poll(&pfd, 1, -1);
                        assert(r == 1);

                        r = read(timer.fd, &count, sizeof(count));
                        assert(r == sizeof(count));
                        assert(count == 1);
                        armed = false;
                }

                for (;;) {
                        uint64_t current_time;

                        r = timer_pop(&timer, i, &t);
                        assert(!r);
                        if (!t)
                                break;

                        current_time = times[t - timeouts];
                        assert(current_time == i);
                        ++n_timeouts;
                        armed = true;
                }
        }

        assert(n_timeouts == N_TIMEOUTS);

        r = timer_pop(&timer, (uint64_t)-1, &t);
        assert(!r);
        assert(!t);

        timer_deinit(&timer);
}

int main(int argc, char **argv) {
        test_api();
        test_pop();
        return 0;
}
