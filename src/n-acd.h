#pragma once

/*
 * IPv4 Address Conflict Detection
 *
 * This is the public header of the n-acd library, implementing IPv4 Address
 * Conflict Detection as described in RFC-5227. This header defines the public
 * API and all entry points of n-acd.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdbool.h>

enum {
        _N_ACD_E_SUCCESS,

        N_ACD_E_AGAIN,

        N_ACD_E_INVALID_ARGUMENT,
        N_ACD_E_STARTED,
        N_ACD_E_STOPPED,
};

typedef struct NAcd NAcd;

typedef struct NAcdConfig {
        unsigned int ifindex;
        struct ether_addr mac;
        struct in_addr ip;
} NAcdConfig;

typedef struct NAcdEvent {
        unsigned int event;
        union {
                struct {
                } ready, down;
                struct {
                        uint16_t operation;
                        struct ether_addr sender;
                        struct in_addr target;
                } used, defended, conflict;
        };
} NAcdEvent;

enum {
        N_ACD_EVENT_READY,
        N_ACD_EVENT_USED,
        N_ACD_EVENT_DEFENDED,
        N_ACD_EVENT_CONFLICT,
        N_ACD_EVENT_DOWN,
        _N_ACD_EVENT_N,
        _N_ACD_EVENT_INVALID,
};

enum {
        N_ACD_DEFEND_NEVER,
        N_ACD_DEFEND_ONCE,
        N_ACD_DEFEND_ALWAYS,
        _N_ACD_DEFEND_N,
};

int n_acd_new(NAcd **acdp);
NAcd *n_acd_free(NAcd *acd);

void n_acd_get_fd(NAcd *acd, int *fdp);

int n_acd_dispatch(NAcd *acd);
int n_acd_pop_event(NAcd *acd, NAcdEvent *eventp);
int n_acd_announce(NAcd *acd, unsigned int defend);

int n_acd_start(NAcd *acd, NAcdConfig *config);
void n_acd_stop(NAcd *acd);

static inline void n_acd_freep(NAcd **acd) {
        if (*acd)
                n_acd_free(*acd);
}

#ifdef __cplusplus
}
#endif
