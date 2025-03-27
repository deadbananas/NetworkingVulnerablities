import ipaddress
import socket
import ssl
import sys


def bytes_to_ip(b):
    return ipaddress.IPv4Address(b)

def parse_dns_response(offset, response):

    length_first = response[offset]
    i = 1
    domain = ''
    while i < (length_first + 1):
        domain += chr(response[offset + i])
        i = i+1
    offset += i
    length_sec = response[offset]
    i = 1
    domain += '.'
    while i < (length_sec + 1):
        domain += chr(response[offset + i])
        i = i+1
    offset += i
    if response[offset] != 0x00:
        domain += '.'
        length_third = response[offset]
        i = 1
        while i < (length_third + 1):
            domain += chr(response[offset + i])
            i = i + 1
        offset += i
    offset += 2
    if response[offset] == 1:
        ans = domain + "." + " A"
        offset = offset + 9
        ans += ' ' + str(response[offset])
        ans += '.' + str(response[offset + 1])
        ans += '.' + str(response[offset + 2])
        ans += '.' + str(response[offset + 3])
        offset = offset + 4
    elif response[offset] == 16:
        ans = domain + "." + " TXT "
        offset = offset + 9
        length_txt = response[offset]
        i = 1
        txt = ''
        while i < (length_txt + 1):
            txt += chr(response[offset + i])
            i = i+1
        offset += i
        ans += txt
    else:
        offset + 15
        ans = "skip"
    return (ans, offset)



certificate_chain, private_key = sys.argv[1], sys.argv[2]
resolver_domain = sys.argv[3]
resolver_port = sys.argv[4]

context = ssl.create_default_context()
context.load_cert_chain(certfile=certificate_chain, keyfile=private_key)

resolver_ip = socket.getaddrinfo(resolver_domain, resolver_port)[0][4][0]

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
    with context.wrap_socket(tcp_socket, server_hostname=resolver_domain) as ssl_socket:
        ssl_socket.connect((resolver_ip, int(resolver_port)))
        
        domain = ".evil-corp.ink."
        dns_query = bytearray()
        dns_query.extend(b"\xb3\xf3")
        dns_query.extend(b"\x01\x00")
        dns_query.extend(b"\x00\x01")
        dns_query.extend(b"\x00\x00")
        dns_query.extend(b"\x00\x00")
        dns_query.extend(b"\x00\x00")
        dns_query.extend(b"\x09")
        dns_query.extend(b"evil-corp")
        dns_query.extend(b"\x03ink")
        dns_query.append(0)  
        dns_query.extend(b"\x00\xff")
        dns_query.extend(b"\x00\x0f") 
        dns_query = len(dns_query).to_bytes(2, 'big') + dns_query
        ssl_socket.sendall(dns_query)

        while True:
            response_length_bytes = ssl_socket.recv(2)
            if not response_length_bytes:
                break 
            response_length = int.from_bytes(response_length_bytes, 'big')
            response = b"" 
            while len(response) < response_length:
                response_part = ssl_socket.recv(min(1024, response_length - len(response)))
                if not response_part:
                    break
                response += response_part

        dns_records = []
        off = 31
        i = 0
        record = ''
        while off < len(response):
            record, off = (parse_dns_response(off, response))
            i += 1
            dns_records.append(record)
        for x in dns_records:
            print(x)
        

