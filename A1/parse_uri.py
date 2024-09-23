#checks if a string s is a uri by determining if it follows the format <protocol>://<everything else>
def is_URI(s):
    return len(s.split("://")) == 2
    

def parse(uri):
    tokens = uri.split("://")
    protocol = tokens[0]

    if protocol == 'http':
        port = 80
    elif protocol == 'https':
        port = 443

    hostname = tokens[1].split('/')[0]
    
    if len(hostname.split(':')) == 2:
        hostname, port = hostname.split(':')


    parts = tokens[1].split('/', 1)
    filepath = parts[1] if len(parts) > 1 else ""

    return [hostname,port,filepath]
