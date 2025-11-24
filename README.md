## Compile `spoof`

First af all, install the necessary development package:
```bash
sudo apt update
sudo apt install libnet1 libnet1-dev
```

Then, you need root privileges (or use `sudo`) to run the program. Additionally, you must enable packet forwarding on your machine by running the following commands:
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
sudo iptables -P FORWARD ACCEPT
```

Finally, you can run the program with:
```bash
gcc main.c arpSpoofFunctions.c -o arpSpoof -lnet
```

And you can execute it with:
```bash
./arpSpoof <Victim_IP> <Victim_MAC> <Router_IP> <Router_MAC> <Web_Interface>
```



## Compile `sniff`

First, install the necessary development package:

```bash
sudo apt update
sudo apt install libpcap-dev
```

Then, compile the program with:
```bash
gcc -o sniff main.c handle_http_packet.c -lpcap
```



