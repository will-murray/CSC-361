import socket
import sys
import ssl

def find_cookies(response):
    #split the response into lines
    lines = response.split("\n")
    lines = [line for line in lines if "Cookie" in line]
    if(len(lines) == 0 ):
        print("no cookies found")
    for line in lines:
        print(line)

def get_header_and_body(response):
    header_body_split = response.split('\r\n\r\n', 1)  # Split on the first occurrence
    headers = header_body_split[0]
    body = header_body_split[1] if len(header_body_split) > 1 else ''  # Handle the case where there may be no body
    return [headers,body]

def get_status(response):
    
    return response.split('\n')[0].split(' ')[1] #grab the second token from the first line of the decoded response

def get_next_url(headers):
    
    location = [line for line in headers.split("\n") if line.startswith("Location")][0]
    location = location[10: len(location) -2]
    return location

def create_socket_connection(url):
    try:
        if url.startswith("https://"):
            hostname = url[8:]
            port = 443  # Default port for HTTPS

            # Create a socket and wrap it with SSL
            context = ssl.create_default_context()
            raw_sock = socket.create_connection((hostname, port))
            sock = context.wrap_socket(raw_sock, server_hostname=hostname)
            print(f"Connected to {url} using HTTPS")
            return sock
                
        else:
            hostname = url
            port = 80  # Default port for HTTP

            # Create a plain socket
            sock = socket.create_connection((hostname, port))
            print(f"Connected to {url} using HTTP")
            return sock

    except socket.gaierror as err:
        print(f"{err} : failed to connect to given url")
        return None


    
def send_HTTP_request(url):
    print(f"*********starting request on {url}**********")
    #create the socket
    
    S = create_socket_connection(url)
    
    urls.append(url)

    #send, recieve and decode the request
    request = "GET / HTTP/2.0\r\nHost: {}\r\nConnection: close\r\n\r\n".format(url)
    S.send(request.encode())
    response = S.recv(4096).decode()

    #extract headers and body
    headers, body = get_header_and_body(response)
    #print(f"HEADERS\n {headers} \n\n********")
    #print(f"********\nBODY\n {body} \n\n********")
    status = get_status(response) 
    print(f"STATUS : {status}")
    if(status[0] == "4"):
        return "Client Error"

    if(status[0] == "3"):
      next_url = get_next_url(headers)
      print(f"LOCATION : {next_url}")
      return send_HTTP_request(next_url)


      
    print("Sucess")
    return response

#extract the status code from the decoded response object



assert(len(sys.argv) == 2)
start_url = sys.argv[1]

#list of visited URLS
urls = []


    
    

response = send_HTTP_request(start_url)



    