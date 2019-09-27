import codecs
import socket
import struct
import bitstring
import sys


# преобразовываем х в шестнадцатиричное
def to_hex_string(x):
    hex_result = "0"

    if x.__class__.__name__ == "int" and x >= 0:
        hex_result = hex(x)

        if x < 16:
            hex_result = "0" + hex_result[2:]

    elif x.__class__.__name__ == "str":
        hex_result = "".join([hex(ord(y))[2:] for y in x])

    return "0x" + hex_result


def get_response_from_server(data):
    address = (sys.argv[1], int(sys.argv[2]))  # спец кортеж для sendto
    type_of_query = sys.argv[5]
    if type_of_query.upper() == 'UDP':
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(10)
        client.sendto(data.tobytes(), address)  # кидаем data через гугловский хост на нужный
        data, address = client.recvfrom(1024)  # размер буфера для считывания из пакета
        return data

    elif type_of_query.upper() == 'TCP':
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.connect(address)
        client.send(data.tobytes())
        client.settimeout(10)
        data = client.recv(1024)
        client.close()
        return data

    else:
        print('wrong type')


def receive_host_name(host_name_to):
    host_name_to = host_name_to.split(".")

# строим пакет сосотоящий из заголовков QNAME QTYPE QCLASS
    DNS_QUERY_FORMAT = [
        "hex=id",
        "bin=flags",
        "uintbe:16=qdcount",
        "uintbe:16=ancount",
        "uintbe:16=nscount",
        "uintbe:16=arcount"]

    if sys.argv[4] == '1':
        DNS_QUERY = {
            "id": "0x1a2b",
            "flags": "0b0000000100000000",  # флаг для рекурсии
            "qdcount": 1,
            "ancount": 0,
            "nscount": 0,
            "arcount": 0}
    else:
        DNS_QUERY = {
            "id": "0x1a2b",
            "flags": "0b0000000000000000",
            "qdcount": 1,
            "ancount": 0,
            "nscount": 0,
            "arcount": 0}

# здесь делаем QNAME по принципу |размер |заголовок| ... |заголовок| 0х00
    j = 0
    for i, _ in enumerate(host_name_to):

        host_name_to[i] = host_name_to[i].strip()
        DNS_QUERY_FORMAT.append("hex=" + "qname" + str(j))
        DNS_QUERY["qname" + str(j)] = to_hex_string(len(host_name_to[i]))

        j += 1

        DNS_QUERY_FORMAT.append("hex=" + "qname" + str(j))
        DNS_QUERY["qname" + str(j)] = to_hex_string(host_name_to[i])

        j += 1

    DNS_QUERY_FORMAT.append("hex=qname" + str(j))
    DNS_QUERY["qname" + str(j)] = to_hex_string(0)  # кидаем туда terminate byte
    DNS_QUERY_FORMAT.append("uintbe:16=qtype")
    DNS_QUERY["qtype"] = sys.argv[3]  # здесь тип записи а или аааа
    DNS_QUERY_FORMAT.append("hex=qclass")
    DNS_QUERY["qclass"] = "0x0001"

    # делаем из всего этого битовую строку
    data = get_response_from_server(bitstring.pack(",".join(DNS_QUERY_FORMAT), **DNS_QUERY))

    # смотрим имя хоста из полученного пакета
    host_name_from = []
    x = 96
    y = x + 8

# все также строится по принципу |размер |заголовок| ... |заголовок| 0х00
# и много битоов после октета указывает на следующий размер заголовка
#  считаем что размер заголовка не превышает одного байта
    new_data = bitstring.BitArray(bytes=data)
    for i, _ in enumerate(host_name_to):

        # получаем размер метки в hex преобр в целое и *8 чтобы получить кол-во бит
        increment = (int(str(new_data[x:y].hex), 16) * 8)

        x = y
        y = x + increment
        host_name_from.append(codecs.decode(new_data[x:y].hex, "hex_codec").decode())

        x = y
        y = x + 8


# смотрим код ответа из пакета с 28 по 32 бит
    response_code = str(new_data[28:32].hex)
    result = {'host_name': None}

    if response_code == "0":
        count = int(data[7])
        ip_datas = []
        ip_datas.append(data[-4:])
        for i in range(1, count):
            ip_datas.append(data[-4 - i*16:-i*16])

        ips = []
        for ip in ip_datas:
            ips.append('.'.join(map(str, struct.unpack('!BBBB', ip))))

        # если все нормально то собираем ip
        result['host_name'] = ".".join(host_name_from)

    elif response_code == "1":
        print("\nFormat error. Unable to interpret query.\n")

    elif response_code == "2":
        print("\nServer failure. Unable to process query.\n")

    elif response_code == "3":
        print("\nName error. Domain name does not exist.\n")

    elif response_code == "4":
        print("\nQuery request type not supported.\n")

    elif response_code == "5":
        print("\nServer refused query.\n")

    return ips


if __name__ == "__main__":
    # print('Write the host name:')
    # result = receive_host_name(input())
    result = receive_host_name(sys.argv[6])
    print("\nIP address:\n", result, "\n")
