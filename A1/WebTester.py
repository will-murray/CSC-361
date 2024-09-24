import socket
import sys
import ssl
import re



def parse_uri(uri):
    
    #if the uri doesn't start with a protocol give it http://
    if len(uri.split("://")) == 1 :
        uri = "http://" + uri


    #split the uri on the "://" and then split the section to the right of the "://" on the first instance of "/"
    tokens = uri.split('://')[1].split('/',1)
    if len(tokens) == 1 :
        return [uri,tokens[0], "/"]
    
    tokens[1] = "/" + tokens[1]
    return[uri, tokens[0], tokens[1]]

#Given a hostname and path send the http request and return the response
def https_request(hostname,path = "/"):
    context = ssl.create_default_context()
    S = context.wrap_socket(
        sock = socket.socket(socket.AF_INET),
        server_hostname= hostname
    )

    S.connect((hostname, 443))

    http_request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
    S.send(http_request.encode())
    http_response = S.recv(4096)

    if S.selected_alpn_protocol():
            http2 = 'h2' in S.selected_alpn_protocol()
    else:
        http2 = False

    return(http_response.decode("utf-8"), http2)
#Given a hostname and path send the http request and return the response, and the string 'no' to indicate that this page doesnt support http 2
def http_request(hostname,path):
    
    S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        S.connect((hostname, 80))
    except socket.gaierror as err:
        print(f"{err} : Failed to connect to {hostname} via HTTP")
        exit(1)


    http_request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
    S.send(http_request.encode())
    http_response = S.recv(4096)

    return([http_response.decode("utf-8"), False])
#given the decoded http response, return a formatted list decribing the cookies
def grab_cookies(response):
    cookies = [line for line in response.split('\n') if line.startswith('Set-Cookie')]
    for idx,c in enumerate(cookies):
        cookie_name = c[12:].split("=")[0]
        cookies[idx] = "cookie name: "+cookie_name

        expiry = re.search(r'expires=[^;]+;', c)
        if expiry:
            expiry = expiry.group(0)[8:]
            cookies[idx] += ", expires time: " + expiry
        
        
        domain = re.search(r'domain=[^;]+;', c)
        if domain:
            domain = domain.group(0)[7:]  
            cookies[idx] += ", domain name: " + domain

    return cookies

def grab_status(response):
    return re.search(r'\b\d{3}\b',response.split('\n')[0]).group()


def grab_location(response):
    return [line for line in response.split('\n') if line.startswith('Location')][0][10:]




def send_request(uri, depth = 1):
    if depth > 10 :
        return

    print(f"request {depth}")
    uri, hostname, path = parse_uri(uri)  

    if(uri.startswith("http://")):
        response, http2 = http_request(hostname,path)
    elif(uri.startswith("https://")):
        response, http2 = https_request(hostname)

    status = grab_status(response)
    print(f"status : {status}")
    
    if not status.startswith("3"):
        print(f"website : {hostname}")
        print(f"2. Supports http2 : {http2}")
        print(f"3. List of Cookies:")
        for c in grab_cookies(response):
            print(c)
    
    else:

        location = grab_location(response)
        print(f"redirecting to = {location}")

        send_request(location, depth + 1)

    



##############################################################
#                           MAIN                             #
##############################################################

input_uri = sys.argv[1]

send_request(input_uri)




