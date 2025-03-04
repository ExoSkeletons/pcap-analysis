import glob

import numpy as np
from matplotlib import pyplot as pl
from matplotlib.ticker import StrMethodFormatter
from scapy import all as scpy
from scapy.layers.http import HTTP
from scapy.layers.inet import *
from scapy.layers.tls.record import *

avg = lambda d: float(sum(d)) / len(d)


class Metadata:
    def __init__(self, packets):
        self.__packets = packets
        norm_time = packets[0].time
        self.d_times = [float(p.time) - float(norm_time) for p in packets]
        self.sizes = [len(p) for p in packets]
        self.inter_times = [self.d_times[0]]
        for i in range(1, len(self.d_times)):
            self.inter_times.append(self.d_times[i] - self.d_times[i - 1])
        self.windows = [0]
        for i, p in enumerate(packets):
            self.windows.append(p[TCP].window if p.haslayer(TCP) else self.windows[i - 1])
        self.windows.pop(0)
        self.flags = [int(p[TCP].flags) if p.haslayer(TCP) else 0 for p in packets]

    def count(self, proto):
        return len(list(filter(lambda p: p.haslayer(proto), self.__packets)))


ext = "pcapng"
pcap_list = glob.glob(r"*." + ext, recursive=False)
if len(pcap_list) == 0:
    print("found no ." + ext + " files.")
    exit(1)

scpy.load_layer("tls")

data = {}
meta = {}
for pcap_file in pcap_list:
    print("loading " + pcap_file)
    data[pcap_file] = scpy.rdpcap(pcap_file)
    meta[pcap_file] = Metadata(data[pcap_file])

if not data or len(list(data.values())) == 0:
    print("no packets found in capture.")
    exit(1)

fig, ax = pl.subplots(len(data), 5)
s = .8
width = .5

protos = [UDP, TCP, TLS, HTTP]
names = ["UDP", "TCP", "TLS", "HTTP"]

for n, (name, packets) in enumerate(data.items()):
    # packet meta over time
    m = meta[name]
    by_size = ax[n, 0]
    by_size.set_title(f"\"{name.replace(f".{ext}", "")}\": Packet size (b)")
    by_size.scatter(m.d_times, m.sizes, s=s)
    by_size.set_yscale('log')
    by_size.axhline(y=avg(m.sizes), color='orange')

    by_inter = ax[n, 1]
    by_inter.set_title("Inter-arrival time (s)")
    by_inter.scatter(m.d_times, m.inter_times, s=s)
    by_inter.axhline(y=avg(m.inter_times), color='orange')

    by_flags = ax[n, 2]
    by_flags.set_title("TCP flags")
    by_flags.scatter(m.d_times, m.flags, s=s)
    by_flags.yaxis.set_ticks(np.arange(0, 32, 4))
    by_flags.yaxis.set_ticks(np.arange(0, 32, 1), minor=True)
    by_flags.yaxis.set_tick_params(which='both')
    by_flags.yaxis.grid(True, which='both')
    by_flags.yaxis.set_major_formatter(StrMethodFormatter("{x:05b}"))

    by_window = ax[n, 3]
    by_window.set_title("TCP window")
    by_window.plot(m.d_times, m.windows)
    by_window.axhline(y=avg(m.windows), color='orange')

    # proto distribution
    a = ax[n, 4]
    for i, proto in enumerate(protos):
        a.bar(i + width * 2, meta[name].count(proto), width, label=names[i])
        a.set_yscale('log')
        a.legend()
    a.set_title("Prot. dist.")

fig.tight_layout()

pl.show()
