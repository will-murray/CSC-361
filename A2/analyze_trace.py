from parse_cap_file import *

#globally available capture data    
data = parse_cap_file('sample-capture-file.cap')
connection_ids = unique_conns(data)



def display_output(data, connection_ids):

    print(f"A) Total Number of connections : {len(connection_ids)} " )
    print("_"*60)

    cons = [Connection(i,connection_ids,data) for i in range(len(connection_ids))]
    print(f"\nB) Connections' details:\n")
    for C in cons:
        print(C.connection_summary())
    print("_"*60)

    print(f"\nC) General\n")

    print(f"The total number of complete TCP connections: {len([i for i in cons if i.is_complete()])}")
    print(f"The number of reset TCP connections: {len([i for i in cons if len( [pack for pack in i.D if 'RST' in pack[6]] ) ])}") # 😩
    print(f"The number of TCP connections that were still open when the trace capture ended: {len([i for i in cons if not i.is_closed()])}")
    print(f"The number of TCP connections established before the capture started: {len([i for i in cons if 'SYN' not in i.D[0][6]])}")
    print("_"*60)

    print(f"\nD) Complete TCP Connections\n")
    RTTs = []
    DURS = []
    NUM_PACKS = []
    WIN = []
    for C in cons:
        if C.is_complete():
            RTTs += C.get_RTTs()
            DURS.append(C.get_duration(dur_only = True))
            NUM_PACKS.append(C.num_packets())
            WIN += C.window_size()



            

    print(f"\nMinimum time duration: {min(DURS).total_seconds()} seconds")
    print(f"Mean time duration value {timedelta(seconds=sum([t.total_seconds() for t in DURS]) / len(DURS) ).total_seconds() } seconds")
    print(f"Maximum time duration {max(DURS).total_seconds()} seconds\n\n")

    print(f"Minimum RTT value: {min(RTTs).total_seconds()}")
    print(f"Mean RTT value {timedelta(seconds=sum([t.total_seconds() for t in RTTs]) / len(RTTs) ).total_seconds() }")
    print(f"Maximum RTT value {max(RTTs).total_seconds()}\n\n")

    print(f"Minimum  number of packets including both send/received: {min(NUM_PACKS)}")
    print(f"Mean number of packets including both send/received: {sum(NUM_PACKS) / len(NUM_PACKS)  } ")
    print(f"Maximum  number of packets including both send/received: {max(NUM_PACKS)}\n\n")

    print(f"Minimum recieve window size including both send/received: {min(WIN)} bytes")
    print(f"Mean recieve window size including both send/received: {sum(WIN) / len(WIN)  } bytes")
    print(f"Maximum  recieve window size including both send/received: {max(WIN)} bytes\n\n")


            


display_output(data,connection_ids)


