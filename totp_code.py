
from PIL import Image
from pyzbar.pyzbar import decode
from urllib.parse import parse_qs, urlparse
import base64
import hmac
import sys
import time


def hotp(k, c, digits):
    hmac_digest = hmac.new(k, c.to_bytes(8, byteorder='big'), 'sha1').digest()
    offset = hmac_digest[-1] & 0x0F
    dynamic_binary = hmac_digest[offset:offset+4]
    dynamic_integer = int.from_bytes(dynamic_binary, byteorder='big') & 0x7FFFFFFF
    hotp_value = dynamic_integer % (10 ** digits)
    return hotp_value


def totp(k, digits, window):
    t = int(time.time()) // window
    hotp_code = hotp(k, t, digits)
    return str(hotp_code).zfill(digits)


contents = decode(Image.open(sys.argv[1]))[0].data
parsed_url = urlparse(contents.decode("utf-8"))
query_params = parse_qs(parsed_url.query)
secret = base64.b32decode(query_params['secret'][0])
digits = int(query_params['digits'][0])
window = int(query_params['period'][0])
print(totp(secret, digits, window))