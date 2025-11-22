#define _DEFAULT_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <ctype.h>
#include <string.h>

#define MAX_BODY_LENGTH 1000

// Definizione della struttura dell'header IP
struct ipheader {
    unsigned char iph_ihl:4,    // Lunghezza dell'header IP (in parole da 4 byte)
                  iph_ver:4;    // Versione IP (IPv4 = 4)
    unsigned char iph_tos;       // Type of Service
    unsigned short iph_len;      // Lunghezza totale del pacchetto IP (header + dati)
    unsigned short iph_ident;    // Identification
    unsigned short iph_flag:3,   // Flag di frammentazione
                   iph_offset:13; // Offset del frammento
    unsigned char iph_ttl;       // Time To Live
    unsigned char iph_protocol;  // Tipo di protocollo (TCP = 6, UDP = 17, ICMP = 1, ...)
    unsigned short iph_chksum;   // Checksum dell'header IP
    struct in_addr iph_sourceip; // Indirizzo IP sorgente
    struct in_addr iph_destip;   // Indirizzo IP destinazione
};

struct tcpheader {
    unsigned short tcp_sport;   // Porta Sorgente (Source Port)
    unsigned short tcp_dport;   // Porta Destinazione (Destination Port)
    unsigned int   tcp_seq;     // Numero di sequenza
    unsigned int   tcp_ack;     // Numero di riscontro (Acknowledgment)

    // Attenzione ai bitfields per l'Endianness (qui per Little Endian / x86)
    unsigned char  tcp_res:4,   // Reserved (4 bit meno significativi)
                   tcp_off:4;   // Data Offset (4 bit più significativi)

    unsigned char  tcp_flags;   // Flag (SYN, ACK, FIN, PSH, ecc.)
    unsigned short tcp_win;     // Window Size
    unsigned short tcp_sum;     // Checksum
    unsigned short tcp_urp;     // Urgent Pointer
};

struct ethheader {
    u_char ether_dhost[6]; // MAC destinazione
    u_char ether_shost[6]; // MAC sorgente
    u_short ether_type;    // Tipo (IP = 0x0800, ARP = 0x0806, ecc.)
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // Controlla se il pacchetto è di tipo IP
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // Calcolo ip header
        int ip_header_len = ip->iph_ihl * 4;

        // Salta ip per arrivare a TCP
        struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);

        // Calcola lunghezza header TCP (anche questo variabile)
        int tcp_header_len = tcp->tcp_off * 4;

        char *payload = (u_char *)tcp + tcp_header_len;

        // Lunghezza payload = Lunghezza totale IP - header IP - header TCP
        int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;


        if (payload_len > 0) {
            char *body_delimiter = "\r\n\r\n";
            int delimiter_len = 4;
            char *body_start = NULL;
            int body_len = 0;
            
            // Cerchiamo il separatore \r\n\r\n
            for (int i = 0; i < payload_len - delimiter_len; i++) {

                // Confronta i 4 byte correnti con il separatore
                if (memcmp(payload + i, body_delimiter, delimiter_len) == 0) {
                    
                    // Trovato! Imposta il puntatore all'inizio del body
                    body_start = payload + i + delimiter_len;
                    
                    // Calcola la lunghezza effettiva dei dati utili rimanenti
                    body_len = payload_len - (i + delimiter_len);
                    break; 
                }
            }

            // Se abbiamo trovato un body e si tratta di una POST, stampiamo
            if (body_start != NULL) {

                // Stampa IP sorgente e destinazione
                printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
                printf("To:   %s\n", inet_ntoa(ip->iph_destip));
                    
                printf("\n--- BODY DEL PACCHETTO (%d bytes) ---\n", body_len);
                    
                // Stampiamo il body (limitando la stampa per sicurezza)
                for (int i = 0; i < body_len && i < MAX_BODY_LENGTH; i++) {
                    if (isprint((unsigned char)body_start[i]))
                        printf("%c", body_start[i]);
                    else
                        printf(".");
                }
                printf("\n---------------------------------------\n\n");
                }
            }
        }
    }


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; // struttura per contenere il filtro compilato
    char filter_exp[] = "tcp port 80"; // filtro: icmp o tcp o udp

    bpf_u_int32 net = 0; // ignoriamo netmask

    // step 1: apri live pcap session sulla NIC con nome corretto
    handle = pcap_open_live("wlo1", BUFSIZ, 1, 1000, errbuf); // primo parametro dice l'interfaccia di rete
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    // step 2: compila la stringa del filtro in un programma BPF che il kernel può usare    
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // step 3: ciclo infinito che cattura pacchetti
    // -1 = cattura indefinitamente
    // got_packet = callback per ogni pacchetto
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
