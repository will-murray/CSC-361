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

    print(f"\nC) General")
    RTTs = []
    DURS = []
    NUM_PACKS = []
    for C in cons:
        if C.is_complete():
            RTTs += C.get_RTTs()
            DURS.append(C.get_duration(dur_only = True))
            NUM_PACKS.append(C.num_packets())


            

    print(f"\nMinimum time duration: {min(DURS)}")
    print(f"Mean time duration value {timedelta(seconds=sum([t.total_seconds() for t in DURS]) / len(DURS) ) }")
    print(f"Maximum time duration {max(DURS)}\n\n")

    print(f"Minimum RTT value: {min(RTTs)}")
    print(f"Mean RTT value {timedelta(seconds=sum([t.total_seconds() for t in RTTs]) / len(RTTs) ) }")
    print(f"Maximum RTT value {max(RTTs)}\n\n")

    print(f"Minimum  number of packets including both send/received:: {min(NUM_PACKS)}")
    print(f"Mean number of packets including both send/received: {sum(NUM_PACKS) / len(NUM_PACKS)  }")
    print(f"Maximum  number of packets including both send/received: {max(NUM_PACKS)}\n\n")



            


display_output(data,connection_ids)
