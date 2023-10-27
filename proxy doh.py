#besoin de réceptionner la requête transmise apartir du script client
#besoin d'etablir le formalism d'affichage correct (voir cahier de charge)
#besoin de verifier que script marche sur la machine boxa
import socket
import struct
import base64
#import dns.resolver
#with open("/etc/resolv.conf", "r") as file:
#        resolver_address = file.read().strip()

    # Creating a DNS resolver object
#    resolver = dns.resolver.Resolver()
#   resolver.nameservers = [resolver_address]

def findaddrserver():
  """recupere l'adresse de couche transport du proxy DoH depuis le fichier /etc/resolv.conf"""
  resolvconf = open("/etc/resolv.conf", "r")
  lines = resolvconf.readlines()
  i=0
  while lines[i].split()[0]!='nameserver':
    i=i+1
  resolver_address = lines[i].split()[1]
  resolvconf.close()
  return resolver_address
############################################################################################# how to catch baseurl64 for doh client?
def base64url_to_binary_dns(base64url):
    """
    Converts a base64url encoded string to the binary representation of a DNS query.

    Parameters:
    - base64url: str
        The base64url encoded string representing a DNS query.

    Returns:
    - bytes:
        The binary representation of the DNS query.

    Raises:
    - ValueError:
        Raises an error if the input string is not a valid base64url encoded string.
    """

    # Replacing the characters '-' and '_' with '+' and '/' respectively
    base64_encoded = base64url.replace('-', '+').replace('_', '/')

    # Padding the base64 encoded string with '=' characters if necessary
    padding_length = 4 - (len(base64_encoded) % 4)
    base64_padded = base64_encoded + '=' * padding_length

    try:
        # Decoding the base64 padded string to obtain the binary representation
        binary_dns = base64.b64decode(base64_padded)
        return binary_dns
    except Exception as e:
        raise ValueError("Invalid base64url encoded string.") from e
##########################################################################################

def send_dns_request(binary_dns: bytes,resolver_address: str) -> str:
    """
    Sends a DNS request to the resolver server and returns the response.

    Parameters:
    - binary_dns: bytes
        The domain name for which the DNS request is to be made.
    - resolver_address: str
        The IP address of the resolver server.

    Returns:
    - str:
        The DNS response received from the resolver server.

    Raises:
    - socket.gaierror:
        If there is an error resolving the IP address of the resolver server.
    - socket.error:
        If there is an error in the socket connection or sending/receiving data.
    """

    # Create a TCP socket connection to the resolver server
    resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the resolver server using the provided IP address
        resolver_socket.connect((resolver_address, 53))

        # Create the DNS request message
        dns_request = create_dns_request(binary_dns)

        # Add the length prefix to the DNS request message for TCP
        dns_request_with_length = struct.pack('>H', len(dns_request)) + dns_request

        # Send the DNS request to the resolver server
        resolver_socket.sendall(dns_request_with_length)

        # Receive the DNS response from the resolver server
        dns_response_with_length = resolver_socket.recv(4096)

        # Extract the length prefix from the DNS response for TCP
        dns_response_length = struct.unpack('>H', dns_response_with_length[:2])[0]

        # Extract the actual DNS response message from the received data
        dns_response = dns_response_with_length[2:2+dns_response_length]

        return dns_response.decode()

    finally:
        # Close the socket connection to the resolver server
        resolver_socket.close()

def create_dns_request(binary_dns: bytes) -> bytes:
    """
    Creates a DNS request message for the given domain.

    Parameters:
    - binary_dns: bytes
        The domain name for which the DNS request is to be made.

    Returns:
    - bytes:
        The DNS request message as bytes.

    Raises:
    - ValueError:
        If the domain name is not valid.
    """

    

    # Create the DNS request message with the necessary fields
    dns_request = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'

    # Split the domain name into its labels
    labels = binary_dns.split('.')

    # Add each label to the DNS request message
    for label in labels:
        label_length = len(label)
        dns_request += struct.pack('B', label_length)
        dns_request += label.encode()

    # Add the terminating byte to the DNS request message
    dns_request += b'\x00'

    # Add the QTYPE and QCLASS fields to the DNS request message
    dns_request += b'\x00\x01\x00\x01'

    return dns_request


# Example usage:
binary_dns = "example.com"
resolver_address = "192.168.1.1"

try:
    dns_response = send_dns_request(binary_dns, resolver_address)
    print(f"DNS response for {binary_dns}: {dns_response}") #incorrect message format 
except (socket.gaierror, socket.error) as e:
    print(f"Error sending DNS request: {e}")
except ValueError as e:
    print(f"Invalid domain name: {e}")