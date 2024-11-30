# Input data
data = [
    ('PcapTracesAssignment3/group1-trace1.pcap', 1, 11.366667),
('PcapTracesAssignment3/group1-trace1.pcap', 2, 16.850667),
('PcapTracesAssignment3/group1-trace1.pcap', 3, 16.008667),
('PcapTracesAssignment3/group1-trace1.pcap', 4, 17.562),
('PcapTracesAssignment3/group1-trace1.pcap', 5, 18.361),
('PcapTracesAssignment3/group1-trace1.pcap', 6, 11.861333),
('PcapTracesAssignment3/group1-trace1.pcap', 7, 13.507333),
('PcapTracesAssignment3/group1-trace1.pcap', 8, 14.095667),
('PcapTracesAssignment3/group1-trace1.pcap', 9, 18.234333),
('PcapTracesAssignment3/group1-trace1.pcap', 10, 16.911667),
('PcapTracesAssignment3/group1-trace1.pcap', 11, 19.429),
('PcapTracesAssignment3/group1-trace1.pcap', 12, 14.697),
('PcapTracesAssignment3/group1-trace1.pcap', 13, 19.620333333333335),
('PcapTracesAssignment3/group1-trace2.pcap', 1, 11.385),
('PcapTracesAssignment3/group1-trace2.pcap', 2, 15.933),
('PcapTracesAssignment3/group1-trace2.pcap', 3, 15.450333),
('PcapTracesAssignment3/group1-trace2.pcap', 4, 17.711667),
('PcapTracesAssignment3/group1-trace2.pcap', 5, 16.878),
('PcapTracesAssignment3/group1-trace2.pcap', 6, 11.641),
('PcapTracesAssignment3/group1-trace2.pcap', 7, 13.429333),
('PcapTracesAssignment3/group1-trace2.pcap', 8, 50.242),
('PcapTracesAssignment3/group1-trace2.pcap', 9, 16.794667),
('PcapTracesAssignment3/group1-trace2.pcap', 10, 17.578),
('PcapTracesAssignment3/group1-trace2.pcap', 11, 19.223333),
('PcapTracesAssignment3/group1-trace2.pcap', 12, 15.622250000000001),
('PcapTracesAssignment3/group1-trace2.pcap', 13, 18.018666666666668),
('PcapTracesAssignment3/group1-trace3.pcap', 1, 11.686),
('PcapTracesAssignment3/group1-trace3.pcap', 2, 15.732333),
('PcapTracesAssignment3/group1-trace3.pcap', 3, 16.314333),
('PcapTracesAssignment3/group1-trace3.pcap', 4, 17.158),
('PcapTracesAssignment3/group1-trace3.pcap', 5, 17.914667),
('PcapTracesAssignment3/group1-trace3.pcap', 6, 12.113333),
('PcapTracesAssignment3/group1-trace3.pcap', 7, 14.406),
('PcapTracesAssignment3/group1-trace3.pcap', 8, 15.182333),
('PcapTracesAssignment3/group1-trace3.pcap', 9, 18.085667),
('PcapTracesAssignment3/group1-trace3.pcap', 10, 18.865),
('PcapTracesAssignment3/group1-trace3.pcap', 11, 20.102667),
('PcapTracesAssignment3/group1-trace3.pcap', 12, 12.7695),
('PcapTracesAssignment3/group1-trace3.pcap', 13, 20.839666666666666),
('PcapTracesAssignment3/group1-trace4.pcap', 1, 11.214),
('PcapTracesAssignment3/group1-trace4.pcap', 2, 15.712667),
('PcapTracesAssignment3/group1-trace4.pcap', 3, 15.420667),
('PcapTracesAssignment3/group1-trace4.pcap', 4, 16.688667),
('PcapTracesAssignment3/group1-trace4.pcap', 5, 17.442667),
('PcapTracesAssignment3/group1-trace4.pcap', 6, 11.519333),
('PcapTracesAssignment3/group1-trace4.pcap', 7, 13.587667),
('PcapTracesAssignment3/group1-trace4.pcap', 8, 14.006333),
('PcapTracesAssignment3/group1-trace4.pcap', 9, 16.930667),
('PcapTracesAssignment3/group1-trace4.pcap', 10, 18.181),
('PcapTracesAssignment3/group1-trace4.pcap', 11, 19.434),
('PcapTracesAssignment3/group1-trace4.pcap', 12, 13.940000000000001),
('PcapTracesAssignment3/group1-trace4.pcap', 13, 19.775333333333332),
('PcapTracesAssignment3/group1-trace5.pcap', 1, 11.298333),
('PcapTracesAssignment3/group1-trace5.pcap', 2, 16.691333),
('PcapTracesAssignment3/group1-trace5.pcap', 3, 17.484333),
('PcapTracesAssignment3/group1-trace5.pcap', 4, 18.246667),
('PcapTracesAssignment3/group1-trace5.pcap', 5, 19.010333),
('PcapTracesAssignment3/group1-trace5.pcap', 6, 11.917667),
('PcapTracesAssignment3/group1-trace5.pcap', 7, 13.539),
('PcapTracesAssignment3/group1-trace5.pcap', 8, 18.522333),
('PcapTracesAssignment3/group1-trace5.pcap', 9, 16.708333),
('PcapTracesAssignment3/group1-trace5.pcap', 10, 17.964667),
('PcapTracesAssignment3/group1-trace5.pcap', 11, 19.327333),
('PcapTracesAssignment3/group1-trace5.pcap', 12, 13.892),
('PcapTracesAssignment3/group1-trace5.pcap', 13, 19.634666666666664),
('PcapTracesAssignment3/group2-trace1.pcap', 1, 3.329667),
('PcapTracesAssignment3/group2-trace1.pcap', 2, 15.811667),
('PcapTracesAssignment3/group2-trace1.pcap', 3, 18.869333),
('PcapTracesAssignment3/group2-trace1.pcap', 4, 22.843),
('PcapTracesAssignment3/group2-trace1.pcap', 5, 26.502),
('PcapTracesAssignment3/group2-trace1.pcap', 6, 24.263667),
('PcapTracesAssignment3/group2-trace1.pcap', 7, 18.408),
('PcapTracesAssignment3/group2-trace1.pcap', 8, 22.970667),
('PcapTracesAssignment3/group2-trace2.pcap', 1, 2.710667),
('PcapTracesAssignment3/group2-trace2.pcap', 2, 17.118333),
('PcapTracesAssignment3/group2-trace2.pcap', 3, 20.096667),
('PcapTracesAssignment3/group2-trace2.pcap', 4, 19.42),
('PcapTracesAssignment3/group2-trace2.pcap', 5, 21.555333),
('PcapTracesAssignment3/group2-trace2.pcap', 6, 19.982333),
('PcapTracesAssignment3/group2-trace2.pcap', 7, 51.658),
('PcapTracesAssignment3/group2-trace2.pcap', 8, -224.262333),
('PcapTracesAssignment3/group2-trace3.pcap', 1, 7.854),
('PcapTracesAssignment3/group2-trace3.pcap', 2, 11.835333),
('PcapTracesAssignment3/group2-trace3.pcap', 3, 22.579333),
('PcapTracesAssignment3/group2-trace3.pcap', 4, 19.460333),
('PcapTracesAssignment3/group2-trace3.pcap', 5, 20.321333),
('PcapTracesAssignment3/group2-trace3.pcap', 6, 21.849667),
('PcapTracesAssignment3/group2-trace3.pcap', 7, 22.763333),
('PcapTracesAssignment3/group2-trace3.pcap', 8, 20.592),
('PcapTracesAssignment3/group2-trace4.pcap', 1, 3.415333),
('PcapTracesAssignment3/group2-trace4.pcap', 2, 13.245),
('PcapTracesAssignment3/group2-trace4.pcap', 3, 21.672333),
('PcapTracesAssignment3/group2-trace4.pcap', 4, 19.754667),
('PcapTracesAssignment3/group2-trace4.pcap', 5, 35.771333),
('PcapTracesAssignment3/group2-trace4.pcap', 6, 22.674667),
('PcapTracesAssignment3/group2-trace4.pcap', 7, 18.337333),
('PcapTracesAssignment3/group2-trace4.pcap', 8, 24.574333),
('PcapTracesAssignment3/group2-trace5.pcap', 1, 1.745667),
('PcapTracesAssignment3/group2-trace5.pcap', 2, 16.153667),
('PcapTracesAssignment3/group2-trace5.pcap', 3, 21.601667),
('PcapTracesAssignment3/group2-trace5.pcap', 4, 18.558333),
('PcapTracesAssignment3/group2-trace5.pcap', 5, 20.717),
('PcapTracesAssignment3/group2-trace5.pcap', 6, 43.472),
('PcapTracesAssignment3/group2-trace5.pcap', 7, 26.921333),
('PcapTracesAssignment3/group2-trace5.pcap', 8, 25.623333)
]

# Create a dictionary to store results
results = {}

# Process each entry
for trace, ttl, value in data:
    if trace not in results:
        results[trace] = {}
    results[trace][ttl] = value

# Get the unique TTL values in sorted order
unique_ttls = sorted({ttl for _, ttl, _ in data})

# Create the table header
header = ["Trace"] + [f"TTL {ttl}" for ttl in unique_ttls]
print("\t".join(header))

# Generate rows for each trace
for trace, ttl_values in results.items():
    row = [trace] + [str(ttl_values.get(ttl, "")) for ttl in unique_ttls]
    print(" ".join(row))
