/*
 * Timer Utility Library
 */

#include <stdio.h>

#include <assert.h>
#include <c-rbtree.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include "timer.h"

int timer_init(Timer *timer) {
        int r;

        r = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (r < 0)
                return -errno;

        *timer = (Timer)TIMER_NULL(*timer);
        timer->fd = r;

        return 0;
}

void timer_deinit(Timer *timer) {
        assert(c_rbtree_is_empty(&timer->tree));

        if (timer->fd >= 0) {
                close(timer->fd);
                timer->fd = -1;
        }
}

void timer_now(Timer *timer, uint64_t *nowp) {
        struct timespec ts;
        int r;

        r = clock_gettime(CLOCK_BOOTTIME, &ts);
        assert(r >= 0);

        *nowp = ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

void timer_rearm(Timer *timer) {
        uint64_t time;
        Timeout *timeout;
        int r;

        /*
         * A timeout value of 0 clears the timer, we sholud only set that if
         * no timout exists in the tree.
         */

        timeout = c_rbnode_entry(c_rbtree_first(&timer->tree), Timeout, node);
        assert(!timeout || timeout->timeout);

        time = timeout ? timeout->timeout : 0;

        if (time != timer->scheduled_timeout) {
                r = timerfd_settime(timer->fd,
                                    TFD_TIMER_ABSTIME,
                                    &(struct itimerspec){
                                            .it_value = {
                                                    .tv_sec = time / UINT64_C(1000000000),
                                                    .tv_nsec = time % UINT64_C(1000000000),
                                            },
                                    },
                                    NULL);
                assert(r >= 0);

                timer->scheduled_timeout = time;
        }
}

int timer_pop(Timer *timer, uint64_t until, Timeout **timeoutp) {
        Timeout *timeout;

        /*
         * If the first timeout is scheduled before @until, then unlink
         * it and return it. Otherwise, return NULL.
         */
        timeout = c_rbnode_entry(c_rbtree_first(&timer->tree), Timeout, node);
        if (timeout && timeout->timeout <= until) {
                c_rbnode_unlink(&timeout->node);
                timeout->timeout = 0;
                *timeoutp = timeout;
        } else {
                *timeoutp = NULL;
        }

        return 0;
}

void timeout_schedule(Timeout *timeout, Timer *timer, uint64_t time) {

        assert(time);

        /*
         * In case @timeout was already scheduled, remove it from the
         * tree. If we are moving it to a new timer, rearm the old one.
         */
        if (timeout->timer) {
                c_rbnode_unlink(&timeout->node);
                if (timeout->timer != timer)
                        timer_rearm(timeout->timer);
        }
        timeout->timer = timer;
        timeout->timeout = time;

        /*
         * Now insert it back into the tree in the correct new position.
         * We allow duplicates in the tree, so this insertion is open-coded.
         */
        {
                Timeout *other;
                CRBNode **slot, *parent;

                slot = &timer->tree.root;
                parent = NULL;
                while (*slot) {
                        other = c_rbnode_entry(*slot, Timeout, node);
                        parent = *slot;
                        if (timeout->timeout < other->timeout)
                                slot = &(*slot)->left;
                        else
                                slot = &(*slot)->right;
                }

                c_rbtree_add(&timer->tree, parent, slot, &timeout->node);
        }

        /*
         * Rearm the timer as we updated the timeout tree.
         */
        timer_rearm(timer);
}

void timeout_unschedule(Timeout *timeout) {
        Timer *timer = timeout->timer;

        if (!timer)
                return;

        c_rbnode_unlink(&timeout->node);
        timeout->timeout = 0;
        timeout->timer = NULL;

        timer_rearm(timer);
}
