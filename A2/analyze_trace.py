from parse_cap_file import *

#globally available capture data    
data = parse_cap_file('sample-capture-file.cap')
connection_ids = unique_conns(data)

for d in data:
    print(d)

# C = Connection(0,connection_ids,data)
# for idx in range(len(connection_ids)):
#     C = Connection(idx,connection_ids,data)
#     if C.is_complete():
#         pass
        


