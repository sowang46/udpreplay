import argparse
from scapy.all import rdpcap
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

def main(args):
    tx_pcap = rdpcap(args.tx_pcap)
    rx_pcap = rdpcap(args.rx_pcap)

    # Record Tx timestamps
    tx_timestamp = []
    for ii in range(len(tx_pcap)):
        tx_timestamp.append(tx_pcap[ii].time)

    latency = np.empty((len(tx_pcap),))
    latency[:] = np.nan
    delta_t = rx_pcap[0].time - tx_timestamp[0] + args.time_offset
    for ii in range(len(rx_pcap)):
        pkt = rx_pcap[ii]
        sn = pkt.load[0]+pkt.load[1]*256+pkt.load[2]*65536
        latency[sn] = pkt.time - tx_timestamp[sn] - delta_t
    latency_data = pd.DataFrame({"Timestamp": tx_timestamp, "Latency": latency})

    # Visualization
    plt.figure()
    sns.set_theme(style="whitegrid")
    sns.lineplot(data=latency_data, x="Timestamp", y="Latency")
    plt.xlabel("Timestamp (s)")
    plt.ylabel("Latency estimation (s)")
    plt.show()

if __name__=="__main__":
    parser = argparse.ArgumentParser(description='Parse and compare pcap file from Tx/Rx side of udp replay tool')
    parser.add_argument('--tx_pcap', type=str, default='HL2_trace_DL.pcapng', help='The path to Tx pcap file')
    parser.add_argument('--rx_pcap', type=str, default='', help='The path to Rx pcap file')
    parser.add_argument('--time_offset', type=float, default=0, help='Time offset added to Tx packets (second)')
    args = parser.parse_args()

    main(args)