import socket

GOOGLE_QUERY = bytearray([
    0x30, 0x79, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,

    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,

    0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x72,

    0x9e, 0x4c, 0x23, 0x4c, 0x3e, 0xcc, 0x37
])


def pretty_send(sock, content):
    print('SEND', repr(content))
    sock.send(content)


def pretty_recv(sock, length):
    content = sock.recv(length)
    print('RECV', repr(content))
    return content


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 2333))

    pretty_send(s, b'\x05\x01\x00')
    pretty_recv(s, 2)

    pretty_send(s, b'\x05\x03\x00\x01\x08\x08\x08\x08\x00\x35')
    c = pretty_recv(s, 1024)

    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.connect(('127.0.0.1', c[8] * 256 + c[9]))

    pretty_send(u, b'\x00\x00\x00\x01\x08\x08\x08\x08\x00\x35' + GOOGLE_QUERY)
    pretty_recv(u, 1024)

    s.close()
    u.close()
