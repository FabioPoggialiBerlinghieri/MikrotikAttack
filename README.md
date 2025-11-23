## Compile `sniff`

First, install the necessary development package:

```bash
sudo apt update
sudo apt install libpcap-dev
```

Then, compile the program with:
```bash
gcc -o sniff main.c sniff.c handle_http_packet.c -lpcap
```
**Note:** You need root privileges (or use `sudo`) to run the program.
