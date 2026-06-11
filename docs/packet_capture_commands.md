# Packet Capture Commands

Run these in a separate terminal before each test.

## None mode
```bash
sudo tcpdump -i lo -w captures/none_mode.pcap port 1883
```

## Sign mode
```bash
sudo tcpdump -i lo -w captures/sign_mode.pcap port 1883
```

## SignAndEncrypt mode
```bash
sudo tcpdump -i lo -w captures/signandencrypt_mode.pcap port 1883
```

Stop capture with CTRL+C.

Analyze:
```bash
tshark -r captures/none_mode.pcap -V | less
tshark -r captures/sign_mode.pcap -V | less
tshark -r captures/signandencrypt_mode.pcap -V | less
```

Expected:
- None: soil values visible.
- Sign: soil values visible plus signature.
- SignAndEncrypt: soil values hidden, encrypted bytes visible.
