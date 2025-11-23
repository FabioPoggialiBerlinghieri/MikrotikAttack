#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <ctype.h>
#include <string.h>

// ---------
// Definition of IP, TCP, Ethernet header structures
// ---------

typedef struct {
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
} ipheader;

typedef struct {
    unsigned short tcp_sport;
    unsigned short tcp_dport;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned char tcp_res:4, tcp_off:4;
    unsigned char tcp_flags;
    unsigned short tcp_win;
    unsigned short tcp_sum;
    unsigned short tcp_urp;
} tcpheader;

typedef struct {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
} ethheader;

/**
 * @brief Callback invoked by pcap_loop() for each captured HTTP packet.
 *
 * This function parses Ethernet, IP, and TCP headers to locate the TCP payload.
 * Since the capture is already filtered for HTTP (TCP port 80), all packets
 * here are assumed to be HTTP requests. The function prints the payload content
 * and attempts a simple extraction of URL parameters, such as "username=" if present.
 *
 * @param args Optional user-defined argument passed by pcap_loop() (unused).
 * @param pkthdr Metadata describing the captured packet (length, timestamp, etc.).
 * @param packet Pointer to the raw packet bytes starting at the Ethernet header.
 * @return void
 */
void handle_http_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
