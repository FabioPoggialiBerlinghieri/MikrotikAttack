#define _DEFAULT_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <ctype.h>
#include <string.h>

#define MAX_BODY_LENGTH 1000

// Definizione delle strutture per header IP, TCP, Ethernet
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short iph_len;
    unsigned short iph_ident;
    unsigned short iph_flag:3, iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

struct tcpheader {
    unsigned short tcp_sport;
    unsigned short tcp_dport;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned char tcp_res:4, tcp_off:4;
    unsigned char tcp_flags;
    unsigned short tcp_win;
    unsigned short tcp_sum;
    unsigned short tcp_urp;
};

struct ethheader {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

void got_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

    // Get the IP header length and TCP header length
    int ip_header_len = ip->iph_ihl * 4;
    int tcp_header_len = tcp->tcp_off * 4;

    // Get the start of the data section (HTTP request)
    const u_char *data = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int data_len = pkthdr->len - (sizeof(struct ethheader) + ip_header_len + tcp_header_len);

    // Check if the packet is a TCP packet destined to port 80 (HTTP)
    if (ntohs(tcp->tcp_dport) == 80) {
        // Print the HTTP data (for debugging purposes)
        printf("HTTP Data: ");
        for (int i = 0; i < data_len; i++) {
            printf("%c", data[i]);
        }
        printf("\n");

        // Now check for HTTP GET method and extract the username if available
        char *data_str = (char *)data;
        if (strstr(data_str, "GET") != NULL) {
            // Check if the packet contains "GET" and parse the HTTP request
            printf("HTTP GET Request Detected\n");

            // Look for common HTTP request fields, such as the 'Host', 'User-Agent', or parameters
            char *username_pos = strstr(data_str, "username=");
            if (username_pos != NULL) {
                // Extract the username (this is a simple example, might need more parsing)
                username_pos += 9; // Move past the "username=" part
                char username[100];
                int i = 0;
                // Extract the username (up to the next "&" or space)
                while (username_pos[i] != '&' && username_pos[i] != ' ' && username_pos[i] != '\0') {
                    username[i] = username_pos[i];
                    i++;
                }
                username[i] = '\0'; // Null-terminate the string
                printf("Extracted Username: %s\n", username);
            }
        }
    }
}


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // Filtro per catturare tutto il traffico TCP

    bpf_u_int32 net = 0;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}

