#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int link_header_length = 0; // Length of the link layer header

// Callback function for pcap_loop()
// Executed for each captured packet
void call_me_pls(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet_ptr) {
    // Basic Ethernet header definition
    struct ether_header {
        u_char ether_dhost[6];
        u_char ether_shost[6];
        u_short ether_type;
    };

    // Check if the packet is IPv4
    const struct ether_header *eth_hdr = (const struct ether_header *)packet_ptr;
    if (ntohs(eth_hdr->ether_type) != 0x0800) {
        // Not IPv4, skip
        return;
    }
    // Adjust the pointer to skip the link layer header
    packet_ptr += link_header_length;

    // Cast the pointer to interpret the data as an IP header
    struct ip *ip_hdr = (struct ip*) packet_ptr;

    // Buffers to store source and destination IP addresses
    char packet_srcip[INET_ADDRSTRLEN]; // Source IP address
    char packet_dstip[INET_ADDRSTRLEN]; // Destination IP address

    // Copy the IP addresses to buffers to avoid overwriting by inet_ntoa()
    strcpy(packet_srcip, inet_ntoa(ip_hdr->ip_src));
    strcpy(packet_dstip, inet_ntoa(ip_hdr->ip_dst));

    // Extract other IP header fields
    int packet_id = ntohs(ip_hdr->ip_id);           // Packet identification
    int packet_ttl = ip_hdr->ip_ttl;                // Time To Live
    int packet_tos = ip_hdr->ip_tos;                // Type Of Service
    int packet_len = ntohs(ip_hdr->ip_len);         // Total length (header + data)
    int packet_hlen = ip_hdr->ip_hl;                // Header length

    // Print packet timestamp
    char timestamp[32];
    struct tm *ltime;
    time_t local_tv_sec;
    local_tv_sec = pkthdr->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", ltime);

    // Calculate packet size in a more readable format
    char size_str[10];
    if (pkthdr->len >= 1024) {
        snprintf(size_str, sizeof(size_str), "%.1f KB", pkthdr->len / 1024.0);
    } else {
        snprintf(size_str, sizeof(size_str), "%d B", pkthdr->len);
    }

    printf("\n[%s.%06d] Packet %s\n", timestamp, (int)pkthdr->ts.tv_usec, size_str);
    printf("----------------------------------------\n");
    printf("IP Header:\n");
    printf("  ID: %u | TTL: %d | TOS: 0x%x\n", ntohs(ip_hdr->ip_id), packet_ttl, packet_tos);
    printf("  Source: %s\n", packet_srcip);
    printf("  Destination: %s\n", packet_dstip);

    packet_ptr += (4 * packet_hlen);
    int transport_protocol = ip_hdr->ip_p;

    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    struct icmp *icmp_hdr;
    int src_port, dst_port;
    
    printf("Transport Layer:\n");
    switch (transport_protocol) {
        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr *)packet_ptr;
            src_port = ntohs(tcp_hdr->th_sport);
            dst_port = ntohs(tcp_hdr->th_dport);
            printf("  Protocol: TCP\n");
            printf("  Source Port: %d\n", src_port);
            printf("  Destination Port: %d\n", dst_port);
            printf("  Flags: %s%s%s%s%s%s\n",
                (tcp_hdr->th_flags & TH_FIN ? "FIN " : ""),
                (tcp_hdr->th_flags & TH_SYN ? "SYN " : ""),
                (tcp_hdr->th_flags & TH_RST ? "RST " : ""),
                (tcp_hdr->th_flags & TH_PUSH ? "PSH " : ""),
                (tcp_hdr->th_flags & TH_ACK ? "ACK " : ""),
                (tcp_hdr->th_flags & TH_URG ? "URG " : ""));
            printf("  Window Size: %u\n", ntohs(tcp_hdr->th_win));
            printf("  Sequence Number: %u\n", ntohl(tcp_hdr->th_seq));
            break;
        case IPPROTO_UDP:
            udp_hdr = (struct udphdr *)packet_ptr;
            src_port = ntohs(udp_hdr->uh_sport);
            dst_port = ntohs(udp_hdr->uh_dport);
            printf("  Protocol: UDP\n");
            printf("  Source Port: %d\n", src_port);
            printf("  Destination Port: %d\n", dst_port);
            printf("  Length: %d bytes\n", ntohs(udp_hdr->uh_ulen));
            break;
        case IPPROTO_ICMP:
            icmp_hdr = (struct icmp *)packet_ptr;
            printf("  Protocol: ICMP\n");
            printf("  Type: %d\n", icmp_hdr->icmp_type);
            printf("  Code: %d\n", icmp_hdr->icmp_code);
            break;
        default:
            printf("  Unknown protocol: %d\n", transport_protocol);
    }
    printf("----------------------------------------\n");
}

void print_usage(const char *program_name) {
    printf("Usage: %s <interface> <packet_count>\n", program_name);
    printf("  interface    : Network interface to capture packets from (e.g., en0)\n");
    printf("  packet_count : Number of packets to capture (-1 for infinite)\n");
    printf("\nExample: %s en0 10\n", program_name);
}

int main(int argc, char *argv[]) {
    // Check command-line arguments
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    // Network interface to capture packets from
    char *device = argv[1];
    char errBuf[PCAP_ERRBUF_SIZE];

    // Convert packet count to integer
    int packet_count = atoi(argv[2]);
    if (packet_count < -1) {
        printf("ERROR: Invalid packet count. Use -1 for infinite capture or a positive number.\n");
        return 1;
    }

    // Open the network device for packet capture
    pcap_t *capture_device = pcap_open_live(device, BUFSIZ, 0, 0, errBuf);
    
    // Exit if device couldn't be opened
    if (!capture_device) {
        printf("ERROR: pcap_open_live() %s\n", errBuf);
        return 1;
    }

    // Set link header length BEFORE starting pcap_loop
    int link_hdr_type = pcap_datalink(capture_device);

    if (link_hdr_type == DLT_EN10MB) {
        link_header_length = 14; // Ethernet header length
    } else if (link_hdr_type == DLT_NULL) {
        link_header_length = 4; // Null header length
    } else {
        link_header_length = 0; // Unknown header type
    }

    printf("Starting packet capture on interface %s...\n", device);
    printf("Press Ctrl+C to stop capture\n\n");

    // Start packet capture loop
    if (pcap_loop(capture_device, packet_count, call_me_pls, (u_char*)NULL)) {
        printf("ERROR: pcap_loop() failed!\n");
        return 1;
    }

    return 0;
}