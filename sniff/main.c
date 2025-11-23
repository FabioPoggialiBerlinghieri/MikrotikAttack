#include "sniff.h"

int main(int argc, char *argv[]) {

    // Require exactly one argument: the network interface to capture from
    if (argc != 2) {
        fprintf(stderr, "Use: %s <Web_Interface>\n", argv[0]);
        return 1;
    }

    // Store the interface name provided by the user
    char *iface_name = argv[1];

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    // Capture only HTTP traffic (TCP port 80) on the interface
    char filter_exp[] = "tcp port 80";
    bpf_u_int32 net = 0;

    // Open a live packet capture session in promiscuous mode
    handle = pcap_open_live(iface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    // Compile the BPF filter expression into a program usable by the kernel
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Apply the compiled filter to the current capture session
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Start the main packet-capture loop.
    // pcap_loop() blocks and continuously reads packets from the interface.
    // For each captured packet, it invokes the callback function 'handle_http_packet'.
    // The second argument (-1) means "capture indefinitely" until an error occurs
    // or the program is externally interrupted.
    pcap_loop(handle, -1, handle_http_packet, NULL);

    // Clean up the capture handle before exiting
    pcap_close(handle);
    return 0;
}
