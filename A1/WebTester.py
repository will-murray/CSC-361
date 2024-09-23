import socket
import sys
import ssl


#If theres no protocol specified in the uri, use https://
def preprocess_uri(uri):
    if not (uri.startswith("http://") or uri.startswith("https://")):
        uri = "https://" + uri
    return uri


def check_http2(sock):
    L = sock.selected_alpn_protocol()
    if L is None:
        return False
    else:
        return 'h2' in L

def get_response_head_and_body(res):
    parts = res.split("\r\n\r\n", 1)
    if len(parts) < 2:
        return [parts[0], None]
    return [parts[0], parts[1]]


def find_server_info(uri):
    #create the socket

    try:
        
        if uri.startswith("http://"):
            # Remove "http://" from the URI, extract hostname and optional path
            hostname = uri[7:].split('/')[0]
            port = 80
            path = '/' + '/'.join(uri[7:].split('/')[1:]) if '/' in uri[7:] else '/'

            # Create a plain socket for HTTP
            
            sock = socket.create_connection((hostname, port))
        
        else:
            # Remove "https://" from the URI, extract hostname and optional path
            hostname = uri[8:].split('/')[0]
            port = 443
            path = '/' + '/'.join(uri[8:].split('/')[1:]) if '/' in uri[8:] else '/'

            # Create a socket and wrap it with SSL for HTTPS
            context = ssl.create_default_context()
            context.set_alpn_protocols(['http/1.1', 'h2'])

            raw_sock = socket.create_connection((hostname, port))
            sock = context.wrap_socket(raw_sock, server_hostname=hostname)



    except socket.gaierror as err:
        print(f"{err}: failed to connect to given URI")
        exit(1)


    # Send Request
    print("---Request begin---")
    request = f"GET {uri} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
    print(request)
    sock.send(request.encode())
    print("--Request end---\nHTTP request sent, awaiting response...\n")


    res= sock.recv(4096).decode()
    res_header, res_body = get_response_head_and_body(res)
    #print("---Response header---\n", res_header)


    print("Supports http2 :" ,check_http2(sock))

    return None




assert(len(sys.argv) == 2)


start_uri = sys.argv[1]
start_uri = preprocess_uri(start_uri)

response = find_server_info(start_uri)



