import socket
import ssl

# For the HTTPS URL
def connect_https(url):
    hostname = 'docs.engr.uvic.ca'
    port = 443  # Default port for HTTPS

    # Create a socket and wrap it with SSL
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            print(f"Connected to {url} using HTTPS")

# For the non-scheme hostname (assuming HTTP)
def connect_http(url):
    hostname = 'docs.engr.uvic.ca'
    port = 80  # Default port for HTTP

    # Create a plain socket
    with socket.create_connection((hostname, port)) as sock:
        print(f"Connected to {url} using HTTP")

# Connect using HTTPS
connect_https('https://docs.engr.uvic.ca')

# Connect using HTTP
connect_http('docs.engr.uvic.ca')
