
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
import socket
import ssl
import sys


def generate_or_load_private_key(filename="private.pem"):
    try:
        return load_pem_private_key(open(filename, "rb").read(), password=None)
    except FileNotFoundError:
        pass
    private_key = ed25519.Ed25519PrivateKey.generate()
    open(filename, "wb").write(
        private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
    )
    return private_key


def get_public_bytes(priv):
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )


public_key = get_public_bytes(generate_or_load_private_key())
mdm_domain = sys.argv[1]
mdm_port = sys.argv[2]

username = "calcraig"
password = "loveu"
username_bytes = username.encode('utf-8')
password_bytes = password.encode('utf-8')

request = (
    len(username_bytes).to_bytes(2, 'big') +
    username_bytes +
    len(password_bytes).to_bytes(2, 'big') +
    password_bytes +
    len(public_key).to_bytes(2, 'big') +
    public_key
)

context = ssl.create_default_context()
with socket.create_connection((mdm_domain, int(mdm_port))) as sock:
    with context.wrap_socket(sock, server_hostname=mdm_domain) as ssock:
        ssock.sendall(request)
        data_length_bytes = ssock.recv(2)
        data_length = int.from_bytes(data_length_bytes, 'big')
        response_data = ssock.recv(data_length)
        print(response_data.decode('utf-8'))