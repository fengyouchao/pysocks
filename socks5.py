#!/usr/bin/env python
from SocketServer import ThreadingTCPServer, StreamRequestHandler, DatagramRequestHandler
import logging
from socket import socket, AF_INET, SOCK_STREAM
import thread
import struct
import sys

__author__ = 'fengyouchao'


def byte_to_int(b):
    """
    Convert Unsigned byte to int
    :param b: byte value
    :return:  int value
    """
    return b & 0xFF


def port_from_byte(b1, b2):
    """

    :param b1: First byte of port
    :param b2: Second byte of port
    :return: Port in Int
    """
    return byte_to_int(b1) << 8 | byte_to_int(b2)


def host_from_ip(a, b, c, d):
    a = byte_to_int(a)
    b = byte_to_int(b)
    c = byte_to_int(c)
    d = byte_to_int(d)
    return "%d.%d.%d.%d" % (a, b, c, d)


def get_command_name(value):
    """
    Gets command name by value
    :param value:  value of Command
    :return: Command Name
    """
    if value == 1:
        return 'CONNECT'
    elif value == 2:
        return 'BIND'
    elif value == 3:
        return 'UDP_ASSOCIATE'
    else:
        return None


class Session(object):
    index = 0

    def __init__(self, client_socket):
        self.index += 1
        self._id = self.index
        self._client_socket = client_socket


class AddressType(object):
    IPV4 = 1
    DOMAIN_NAME = 3
    IPV6 = 4


class SocksCommand(object):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class SocksMethod(object):
    NO_AUTHENTICATION_REQUIRED = 0
    GSS_API = 1
    USERNAME_PASSWORD = 2


class SocketPipe(object):
    BUFFER_SIZE = 1024 * 1024

    def __init__(self, socket1, socket2):
        self._socket1 = socket1
        self._socket2 = socket2
        self.__running = False

    def __transfer(self, socket1, socket2, name='pipe'):
        while self.__running:
            try:
                data = socket1.recv(self.BUFFER_SIZE)
                if len(data) > 0:
                    socket2.sendall(data)
                else:
                    break
            except IOError, e:
                self.stop()
        self.stop()

    def start(self):
        self.__running = True
        thread.start_new_thread(self.__transfer, (self._socket1, self._socket2))
        thread.start_new_thread(self.__transfer, (self._socket2, self._socket1))

    def stop(self):
        self._socket1.close()
        self._socket2.close()
        self.__running = False

    def is_running(self):
        return self.__running


class CommandExecutor(object):
    def __init__(self, client, remote_server_host, remote_server_port):
        self.__proxy_socket = socket(AF_INET, SOCK_STREAM)
        self._remote_server_host = remote_server_host
        self._remote_server_port = remote_server_port
        self._client = client

    def do_connect(self):
        """
        Do SOCKS CONNECT method
        :return: None
        """
        result = self.__proxy_socket.connect_ex(self.__get_address())
        if result == 0:
            self._client.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            socket_pipe = SocketPipe(self._client, self.__proxy_socket)
            socket_pipe.start()
            while socket_pipe.is_running():
                pass
            logging.info("Thread[%s] connection closed" % thread.get_ident())

    def do_bind(self):
        pass

    def do_udp_associate(self):
        pass

    def __get_address(self):
        return self._remote_server_host, self._remote_server_port


class Socks5RequestHandler(StreamRequestHandler):
    def handle(self):
        logging.info('Thread[%s] Handle connection from %s:%d' % (
            thread.get_ident(), self.client_address[0], self.client_address[1]))
        self.handle_request()

    def handle_request(self):
        socks_client = self.connection
        socks_client.recv(1)
        method_num, = struct.unpack('b', socks_client.recv(1))
        methods = struct.unpack('b' * method_num, socks_client.recv(method_num))
        if methods.__contains__(SocksMethod.NO_AUTHENTICATION_REQUIRED):
            socks_client.send(b"\x05\x00")
        # elif methods.__contains__(SocksMethod.USERNAME_PASSWORD):
        #     socks_client.send(b"\x05\x02")
        else:
            socks_client.send(b"\x05\xFF")
            return None
        version, command, reserved, atype = struct.unpack('b' * 4, socks_client.recv(4))
        host = None
        port = None
        if atype == AddressType.IPV4:
            ip_a, ip_b, ip_c, ip_d, p1, p2 = struct.unpack('b' * 6, socks_client.recv(6))
            host = host_from_ip(ip_a, ip_b, ip_c, ip_d)
            port = port_from_byte(p1, p2)
        elif atype == AddressType.DOMAIN_NAME:
            host_length, = struct.unpack('b', socks_client.recv(1))
            host = socks_client.recv(host_length)
            p1, p2 = struct.unpack('b' * 2, socks_client.recv(2))
            port = port_from_byte(p1, p2)

        command_executor = CommandExecutor(socks_client, host, port)
        if command == SocksCommand.CONNECT:
            logging.info("Thread[%s] Request connect %s:%d" % (thread.get_ident(), host, port))
            command_executor.do_connect()


class User(object):
    def __init__(self, username, password):
        self._username = username
        self._password = password


class Socks5Server(object):
    def __init__(self, port, enable_log=False, log_file='socks.log', console_log=False):
        self._port = port
        self._server = ThreadingTCPServer(('', port), Socks5RequestHandler)
        if enable_log:
            logging.basicConfig(level=logging.DEBUG,
                                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                                datefmt='%a, %d %b %Y %H:%M:%S',
                                filename=log_file,
                                filemode='a')
            console = logging.StreamHandler()
            console.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s %(levelname)-5s %(filename)s %(lineno)-3d - %(message)s')
            console.setFormatter(formatter)
            logging.getLogger('').addHandler(console)

    def start(self):
        logging.info("Create SOCKS5 server at port %d" % self._port)
        self._server.serve_forever()

    def shutdown(self):
        self._server.shutdown()


def show_help():
    print 'Usage:'
    print '  --port=<val>             Sets server port, default 1080'
    print '  --enable-log=true|false  Logging on, default true'
    print '  -h                       Show Help'


def main():
    port = 1080
    enable_log = True
    for arg in sys.argv:
        if arg.startswith('--port='):
            port = int(arg.split('=')[1])
        if arg == '-h':
            show_help()
            sys.exit()
        if arg.startswith('--enable-log='):
            enable_log = bool(arg.split('=')[1])
    socks5_server = Socks5Server(port, enable_log)
    try:
        socks5_server.start()
    except KeyboardInterrupt, e:
        socks5_server.shutdown()
        logging.info("SOCKS5 server shutdown")


if __name__ == '__main__':
    main()
