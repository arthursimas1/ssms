from typing import Tuple
import socket
from sys import stdin
import protocol

Address = Tuple[str, int]


class Connection:
    """
    Both methods are static, that way we do not need to initialize any variable into our class.
    With Static Methods both functions become linked to the class, not the object.
    """

    @staticmethod
    def send(conn: socket.socket, msg: bytes) -> None:
        # Total sent bytes counter, used to determine
        # whether the message has been sent successfully or not
        total_sent = 0

        # Keeps sending message bytes until there's none to send
        while total_sent < len(msg):
            # .send is a socket's function. Used to send data through a TCP based socket.
            # [init:] = it skips init bytes of the message
            bytes_sent = conn.send(msg[total_sent:])

            # If 0 bytes was sent, then there's a problem
            if bytes_sent == 0:
                raise RuntimeError('socket connection broken')
            total_sent += bytes_sent

    @staticmethod
    def receive(conn: socket.socket, msg_size: int) -> bytes:
        # Variable to store the message. It's initialized to an empty byte string.
        msg = b''

        # Keeps receiving expected message bytes until there's none to receive
        while len(msg) < msg_size:

            # .recv is a socket's function. Used to recovery data through a TCP based socket.
            # If the message has more than 2048, it's broken into parts
            chunk = conn.recv(min(msg_size - len(msg), 2048))

            # If 0 bytes was received, then there's a problem
            if chunk == b'':
                raise RuntimeError('socket connection broken')
            msg += chunk

        return msg


class Server:
    """
    By default, the server will be created into a given address, using the TCP protocol.
    The shared key used by the cryptography is also passed.
    """
    def __init__(self, addr: Address, key: bytes) -> None:
        self.addr: Address = addr
        self.key: bytes = key
        self.sock: socket.socket = None
        self.conn: socket.socket = None
        self.source_id: int = None
        self.dest_id: int = None
        self._message: bytes = None

    """
    Creates a socket with the AF_INET protocol (provides IPv4 support) and
    the TCP protocol (SOCK_STREAM), then starts a server.
    """
    def start(self) -> None:
        self.sock = socket.create_server(address=self.addr, family=socket.AF_INET)

    """
    Accepts a connection and returns the client address. 
    """
    def wait_for_connection(self) -> Address:
        self.conn, client_address = self.sock.accept()

        return client_address

    """
    Receives and stores all the data.
    """
    def receive(self) -> None:
        receive = protocol.Receive(self.conn, self.key)
        receive.process()
        self.source_id = receive.source_id
        self.dest_id = receive.dest_id
        self._message = receive.message

    """
    Message getter
    """
    @property
    def message(self) -> bytes:
        if self._message is None:
            raise RuntimeError('message not ready')
        return self._message

    """
    Closes the socket and the connection to the client.
    """
    def close(self) -> None:
        if self.conn:
            self.conn.close()

        if self.sock:
            self.sock.close()


class Client:
    """
    By default, the server will connect into a specific address, using the TCP protocol.
    The shared key used by the cryptography is also passed.
    """
    def __init__(self, addr: Address, source_id: int, dest_id: int, key: bytes, algorithm: str, pkcs5: bool) -> None:
        self.addr: Address = addr
        self.source_id: int = source_id
        self.dest_id: int = dest_id
        self.key: bytes = key
        self.algorithm: str = algorithm
        self.pkcs5: bool = pkcs5
        self.conn: socket.socket = None

    """
    Connects to a server given the parameters.
    """
    def connect(self) -> None:
        self.conn = socket.create_connection(address=self.addr)

    """
    Sends a message to the client in a given connection, from a source id,
    to a destination id, using a given cryptography key, cryptography algorithm and an optional PKCS5 padding. 
    """
    def send(self, msg: bytes) -> None:
        send = protocol.Send(self.conn, self.key, self.source_id, self.dest_id, self.algorithm, self.pkcs5, msg)
        send.process()

    """
    Closes the connection to the server.
    """
    def close(self) -> None:
        if self.conn:
            self.conn.close()


def open_server(addr: Address, key: bytes) -> None:
    """
    Primary function used to open the server and receive a message.
    """

    # Creates a server listening in addr, and with a shared key
    s = Server(addr, key)

    try:
        s.start()  # Start listening to connections
        print(f'server listening on {addr}')
    except ConnectionRefusedError:
        print(f'couldn\'t start server on {addr}.')
        return

    try:
        print('waiting for a connection... press Ctrl + C to interrupt')
        client_addr = s.wait_for_connection()  # Waits for a connection to establish
        print(f'connection accepted from {client_addr}')

        # Starts receiving the message
        s.receive()

        # Gets source id, destination id, and the message itself
        source = s.source_id
        dest = s.dest_id
        message = s.message
        print(f'>>> (FROM: {source}; TO: {dest})\n>>>MESSAGE START\n{message.decode("utf-8")}\n>>> MESSAGE END')
    except KeyboardInterrupt:
        s.close()
        print('interrupted')
        return
    except Exception as e:
        print(f'error: {e}')
        return

    print('closing...')
    s.close()

    print('done.')


def open_client(addr: Address, source_id: int, dest_id: int, key: bytes, algorithm: str, pkcs5: bool) -> None:
    """
    Primary function used to connect the a server and send a message.
    """

    # Creates a client with a given source id, destination id, shared key,
    # cryptographic algorithm and pkcs5 padding option.
    # It will try to connect to a server in addr.
    c = Client(addr, source_id, dest_id, key, algorithm, pkcs5)

    try:
        c.connect()  # Tries to connect to the server
    except ConnectionRefusedError:
        print('couldn\'t connect to server.')
        return

    print(f'connected to server on {addr}')

    try:
        print('type your message (reading until EOF, Ctrl + D in some terminals)... press Ctrl + C to interrupt')

        # Reads stdin. Strip whitespaces at the beginning and the end fo the string to disallow empty messages
        # which can lead to 0 bytes being sent and breaking the socket
        terminal_input = ''
        while terminal_input.strip() == '':
            terminal_input = stdin.read()
            if terminal_input.strip() == '':
                print('message cannot be empty')

        print('\n')
    except KeyboardInterrupt:
        c.close()
        print('interrupted')
        return

    try:
        # Sends to the server the read message
        c.send(terminal_input.encode('utf-8'))
    except Exception as e:
        print(f'some error occurred: {e}')
        return

    print('closing...')
    c.close()

    print('done.')
