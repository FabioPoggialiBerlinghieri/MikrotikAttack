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
**Note:** You need root privileges (or use `sudo`) to run the program. Additionally, you must enable packet forwarding on your machine by running the following commands:
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
sudo iptables -P FORWARD ACCEPT
```
