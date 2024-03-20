LDLIBS=-lpcap
CXXFLAGS=-std=c++11

all: send-arp-test

main.o: header/mac.h header/ip.h header/ethhdr.h header/arphdr.h main.cpp

arphdr.o: header/mac.h header/ip.h header/arphdr.h arphdr.cpp

ethhdr.o: header/mac.h header/ethhdr.h ethhdr.cpp

ip.o: header/ip.h ip.cpp

mac.o : header/mac.h mac.cpp

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
