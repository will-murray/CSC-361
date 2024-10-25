from parse_cap_file import *

#globally available capture data    
data = parse_cap_file('sample-capture-file.cap')
connection_ids = unique_conns(data)

        
C = Connection(0,connection_ids,data)
print(C.connection_summary())

