arp_sender : main.o my_mac.o my_ip.o
	g++ -o arp_sender main.o my_mac.o my_ip.o -lpcap
main.o : main.cpp
	g++ -c -o main.o main.cpp -lpcap
my_mac.o : my_mac.cpp
	g++ -c -o my_mac.o my_mac.cpp
my_ip.o : my_ip.cpp
	g++ -c -o my_ip.o my_ip.cpp
clean :
	rm main.o my_mac.o arp_sender
