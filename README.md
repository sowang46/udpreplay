# udpreplay
Replay pcap trace over UDP.

## Usage
  -`dst_ip`: destination IP address
  
  -`dst_port`: destination port
  
  -`pcap_file`: path to pcap file
  
  -`src_ip`: source IP address
  
  -`src_port`: source port

  ## Song's modification
  - Add a sequence number to the head of payload.
  - Limiting the maximum datagram size to 1400 bytes.
