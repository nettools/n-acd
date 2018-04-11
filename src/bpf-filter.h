#pragma once

struct ether_addr;
struct in_addr;

int n_acd_bpf_map_create(int *mapfdp, size_t max_elements);
int n_acd_bpf_map_add(int mapfd, struct in_addr *addr);
int n_acd_bpf_map_remove(int mapfd, struct in_addr *addr);

int n_acd_bpf_compile(int *progfdp, int mapfd, struct ether_addr *mac);
