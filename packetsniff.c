#include <arpa/inet.h>
#include <netdb.h>
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

// Cache for hostname lookups to avoid repeated DNS queries
#define MAX_HOSTNAME_CACHE 100
struct hostname_cache_entry {
    char ip[INET_ADDRSTRLEN];
    char hostname[NI_MAXHOST];
    int is_valid;
};

struct hostname_cache_entry hostname_cache[MAX_HOSTNAME_CACHE];
int hostname_cache_index = 0;
int enable_dns_resolution = 1;  // Set to 0 to disable DNS lookups

// Initialize hostname cache
void init_hostname_cache() {
    for (int i = 0; i < MAX_HOSTNAME_CACHE; i++) {
        hostname_cache[i].is_valid = 0;
    }
}

// Get hostname for IP address (with caching)
const char* get_hostname(const char* ip_str) {
    if (!enable_dns_resolution) {
        return NULL;
    }
    
    // Check cache first
    for (int i = 0; i < MAX_HOSTNAME_CACHE; i++) {
        if (hostname_cache[i].is_valid && strcmp(hostname_cache[i].ip, ip_str) == 0) {
            return hostname_cache[i].hostname;
        }
    }
    
    // Not in cache, do lookup
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &(sa.sin_addr));
    
    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) != 0) {
        // Failed to resolve
        return NULL;
    }
    
    // Cache the result
    strcpy(hostname_cache[hostname_cache_index].ip, ip_str);
    strncpy(hostname_cache[hostname_cache_index].hostname, host, NI_MAXHOST);
    hostname_cache[hostname_cache_index].is_valid = 1;
    
    hostname_cache_index = (hostname_cache_index + 1) % MAX_HOSTNAME_CACHE;
    
    // Return the cached entry
    for (int i = 0; i < MAX_HOSTNAME_CACHE; i++) {
        if (hostname_cache[i].is_valid && strcmp(hostname_cache[i].ip, ip_str) == 0) {
            return hostname_cache[i].hostname;
        }
    }
    
    return NULL;  // Should not reach here
}

// Get service name for common ports
const char* get_service_name(int port) {
    switch(port) {
        case 20: return "FTP-Data";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: return "DHCP-Server";
        case 68: return "DHCP-Client";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5222: return "XMPP";
        case 5432: return "PostgreSQL";
        case 8080: return "HTTP-Alt";
        default: return NULL;
    }
}

// Format string to include service name if available
void format_port_service(char *buffer, size_t buffer_size, int port) {
    const char *service = get_service_name(port);
    if (service) {
        snprintf(buffer, buffer_size, "%d (%s)", port, service);
    } else {
        snprintf(buffer, buffer_size, "%d", port);
    }
}

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

    // Get hostnames if available
    const char* src_hostname = get_hostname(packet_srcip);
    const char* dst_hostname = get_hostname(packet_dstip);

    printf("\n[%s.%06d] Packet %s\n", timestamp, (int)pkthdr->ts.tv_usec, size_str);
    printf("----------------------------------------\n");
    printf("IP Header:\n");
    if (ntohs(ip_hdr->ip_id) == 0) {
        printf("  ID: Not Set | TTL: %d | TOS: 0x%x\n", packet_ttl, packet_tos);
    } else {
        printf("  ID: %u | TTL: %d | TOS: 0x%x\n", ntohs(ip_hdr->ip_id), packet_ttl, packet_tos);
    }
    printf("  Source: %s", packet_srcip);
    if (src_hostname) {
        printf(" (%s)", src_hostname);
    }
    printf("\n");
    
    printf("  Destination: %s", packet_dstip);
    if (dst_hostname) {
        printf(" (%s)", dst_hostname);
    }
    printf("\n");

    packet_ptr += (4 * packet_hlen);
    int transport_protocol = ip_hdr->ip_p;

    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    struct icmp *icmp_hdr;
    int src_port, dst_port;
    char src_port_str[32], dst_port_str[32];
    
    printf("Transport Layer:\n");
    switch (transport_protocol) {
        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr *)packet_ptr;
            src_port = ntohs(tcp_hdr->th_sport);
            dst_port = ntohs(tcp_hdr->th_dport);
            
            format_port_service(src_port_str, sizeof(src_port_str), src_port);
            format_port_service(dst_port_str, sizeof(dst_port_str), dst_port);
            
            printf("  Protocol: TCP\n");
            printf("  Source Port: %s\n", src_port_str);
            printf("  Destination Port: %s\n", dst_port_str);
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
            
            format_port_service(src_port_str, sizeof(src_port_str), src_port);
            format_port_service(dst_port_str, sizeof(dst_port_str), dst_port);
            
            printf("  Protocol: UDP\n");
            printf("  Source Port: %s\n", src_port_str);
            printf("  Destination Port: %s\n", dst_port_str);
            printf("  Length: %d bytes\n", ntohs(udp_hdr->uh_ulen));
            break;
        case IPPROTO_ICMP:
            icmp_hdr = (struct icmp *)packet_ptr;
            printf("  Protocol: ICMP\n");
            printf("  Type: %d", icmp_hdr->icmp_type);
            
            // Add ICMP type descriptions
            switch(icmp_hdr->icmp_type) {
                case 0: printf(" (Echo Reply)\n"); break;
                case 3: printf(" (Destination Unreachable)\n"); break;
                case 8: printf(" (Echo Request/Ping)\n"); break;
                case 11: printf(" (Time Exceeded)\n"); break;
                default: printf("\n");
            }
            
            printf("  Code: %d\n", icmp_hdr->icmp_code);
            break;
        default:
            printf("  Unknown protocol: %d\n", transport_protocol);
    }
    printf("----------------------------------------\n");
}

void print_usage(const char *program_name) {
    printf("Usage: %s <interface> <packet_count> [-n]\n", program_name);
    printf("  interface    : Network interface to capture packets from (e.g., en0)\n");
    printf("  packet_count : Number of packets to capture (-1 for infinite)\n");
    printf("  -n           : Disable DNS hostname resolution\n");
    printf("\nExample: %s en0 10\n", program_name);
}

int main(int argc, char *argv[]) {
    // Check command-line arguments
    if (argc < 3 || argc > 4) {
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
    
    // Optional argument to disable DNS resolution
    if (argc == 4 && strcmp(argv[3], "-n") == 0) {
        enable_dns_resolution = 0;
        printf("DNS hostname resolution disabled\n");
    } else {
        printf("DNS hostname resolution enabled (use -n to disable)\n");
    }
    
    // Initialize hostname cache
    init_hostname_cache();

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