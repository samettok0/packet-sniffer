#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    
    printf("************************************" "**************************************\n");
    printf("ID: %d | SRC: %s | DST: %s | TOS: 0x%x | TTL: %d\n", packet_id, packet_srcip, packet_dstip, packet_tos, packet_ttl);
}

int main(int argc, char *argv[]) {
    // Network interface to capture packets from
    char *device = "en0"; 
    char errBuf[PCAP_ERRBUF_SIZE];

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

    // Number of packets to capture (use -1 for infinite)
    int packet_count = 5;

    // Start packet capture loop
    if (pcap_loop(capture_device, packet_count, call_me_pls, (u_char*)NULL)) {
        printf("ERROR: pcap_loop() failed!\n");
        return 1;
    }

    return 0;
}