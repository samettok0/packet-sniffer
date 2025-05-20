
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

// Callback function for pcap_loop()
// Executed for each captured packet
void call_me_pls(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet_ptr) {
    printf("YOU GOT A PACKET!\n");
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

    // Number of packets to capture (use -1 for infinite)
    int packet_count = 5;

    // Start packet capture loop
    if (pcap_loop(capture_device, packet_count, call_me_pls, (u_char*)NULL)) {
        printf("ERROR: pcap_loop() failed!\n ");
        return 1;
    }

    return 0;
}