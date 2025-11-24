#ifndef ARPSPOOF_H
#define ARPSPOOF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <libnet.h> 
#include <stdint.h>

// --- Constants ---
#define ARPOP_REPLY 2
#define TARGET_COUNT 20
#define HARDWARE_ADDR_SIZE 6
#define PROTOCOL_ADDR_SIZE 4

// --- Devices Struct
typedef struct {
    char *readable_ip;
    uint32_t ip_addr;
    uint8_t mac_addr[6];
} device;


// Global variables 
extern libnet_t *l; // Libnet context
extern device *victim; 
extern device *router;
extern uint8_t *attacker_mac_addr;

// --- Function Prototypes ---

/**
 * @brief Constructs and sends a spoofed ARP reply packet using Libnet.
 * @param fake_source The device you are impersonating (the Router or the Victim).
 * @param destination Target device to send the packet to (the Victim or the Router).
 * @param attacker_mac_addr Your machine's MAC address.
 * @param iface Interface name (e.g., "eth0").
 * @return void
 */
void arp_spoof(device *fake_source, device *destination, const char *iface);


/**
 * @brief Restores the target device's ARP cache by sending multiple genuine ARP replies.
 * @param fake_source The device whose true IP-MAC association is restored (the Router or the Victim).
 * @param destination The device whose cache needs cleaning (the Victim or the Router).
 * @param attacker_mac_addr Your machine's MAC address.
 * @return void
 */
void arp_restore(device *source, device *destination);


/**
 * @brief Signal handler for SIGINT (CTRL+C) to restore tables and exit.
 */
void cleanup_and_exit(int signum);


/**
 * @brief Converts a MAC string (e.g., "AA:BB:CC:DD:EE:FF") into a 6-byte array.
 * @param mac_str The MAC address string (e.g., argv[2]).
 * @param mac_array A pointer to the 6-byte array where the results will be saved.
 * @return 0 upon success, -1 upon failure.
 */
int parse_mac(const char *mac_str, uint8_t *mac_array);

#endif
