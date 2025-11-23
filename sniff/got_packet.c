#include "sniff.h"

void handle_http_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Cast headers
    ethheader *eth = (ethheader *)packet;
    ipheader *ip = (ipheader *)(packet + sizeof(ethheader));

    // Calculate IP header length in bytes
    // The iph_ihl field gives the length in 32-bit words (4 bytes each), 
    // so we multiply by 4 to get the length in bytes.
    int ip_header_len = ip->iph_ihl * 4;
    tcpheader *tcp = (tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = tcp->tcp_off * 4;

    // Compute pointer to TCP payload and its length
    const u_char *data = (u_char *)tcp + tcp_header_len;
    int data_len = pkthdr->len - (sizeof(ethheader) + ip_header_len + tcp_header_len);

    if (data_len <= 0) {
        return; // No payload to process
    }

    // Print raw HTTP payload (replace non-printable chars with '.')
    printf("HTTP Data (%d bytes): ", data_len);
    for (int i = 0; i < data_len; i++) {
        printf("%c", isprint(data[i]) ? data[i] : '.');
    }
    printf("\n");

    // Convert payload to string for searching
    char *data_str = (char *)data;

    // Detect HTTP GET requests
    if (strstr(data_str, "GET") != NULL) {
        printf("HTTP GET Request Detected\n");

        // Attempt to extract 'username' parameter from URL
        char *username_pos = strstr(data_str, "username=");
        if (username_pos != NULL) {
            username_pos += 9; // Skip "username="

            char username[100];
            int i = 0;
            while (username_pos[i] != '&' && username_pos[i] != ' ' && username_pos[i] != '\0' && i < sizeof(username) - 1) {
                username[i] = username_pos[i];
                i++;
            }
            username[i] = '\0'; // Null-terminate safely
            printf("Extracted Username: %s\n", username);
        }
    }
}
