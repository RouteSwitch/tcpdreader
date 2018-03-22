all: tcpdr

tcpdr: tcpdreader.c tcpdreader.h 
		gcc -o tcpdreader tcpdreader.c -Wall -g -ldnet -lpcap

clean:
		rm -f tcpdreader *.o

run:
		./tcpdreader ./assign4/network.log
