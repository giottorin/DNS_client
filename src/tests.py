import re

import bitstring
import dns_client

# first test
host_name_to = 'google.com'.split(".")

DNS_QUERY_FORMAT = [
    "hex=id",
    "bin=flags",
    "uintbe:16=qdcount",
    "uintbe:16=ancount",
    "uintbe:16=nscount",
    "uintbe:16=arcount"]

DNS_QUERY = {
    "id": "0x1a2b",
    "flags": "0b0000000100000000",  # флаг для рекурсии
    "qdcount": 1,
    "ancount": 0,
    "nscount": 0,
    "arcount": 0}

a = (bitstring.pack(",".join(DNS_QUERY_FORMAT), **DNS_QUERY))

b = (dns_client.get_response_from_server(bitstring.pack(",".join(DNS_QUERY_FORMAT), **DNS_QUERY)))

if a != b:
    print('first test passed')
else:
    print('first test failed')
# смотррим что полученная сточка не равна отправляемой -> сервер среагировал???


# second test
chek = dns_client.receive_host_name('google.com')
ip = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.[0-9]{1,3}', str(chek[0]))
if str(chek[0]) == ip[0]:
    print('second test passed')
else:
    print('second test failed')
# нашелся ли хоть 1 ip

# third test
if dns_client.to_hex_string(456) == ("0x" + hex(456)):
    print('third test passed')
else:
    print('third test failed')
