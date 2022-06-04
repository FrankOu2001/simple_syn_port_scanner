sniffer:	sniffer.c
	gcc sniffer.c -lpthread -lpcap -Wall -o sniffer -g

clean:
	rm sniffer
	rm -rf *.o
	rm -rf *.out
