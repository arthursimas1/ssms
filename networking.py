from typing import Tuple
import socket
from sys import stdin
import protocol

Address = Tuple[str, int]


class Connection:
    @staticmethod
    def send(conn, msg):
        total_sent = 0

        while total_sent < len(msg):
            bytes_sent = conn.send(msg[total_sent:])
            if bytes_sent == 0:
                raise RuntimeError('socket connection broken')
            total_sent += bytes_sent

    @staticmethod
    def receive(conn, msg_size):
        msg = b''

        while len(msg) < msg_size:
            chunk = conn.recv(min(msg_size - len(msg), 2048))
            if chunk == b'':
                raise RuntimeError('socket connection broken')
            msg += chunk

        return msg


class Server:
    """
    Por padrão, cria um servidor ouvindo no endereço indicado, usando o protocolo TCP
    """
    def __init__(self, addr: Address, key: bytes) -> None:
        self.addr: Address = addr
        self.key: bytes = key
        self.sock: socket.socket = None
        self.conn: socket.socket = None
        self.source_id: int = None
        self.dest_id: int = None
        self._message: bytes = None

    def start(self) -> None:
        # função de conveniência cujo cria um socket da família de protocolos AF_INET, cujo suporta IPv4,
        # usando o protocolo do tipo SOCK_STREAM, ou seja, TCP
        self.sock = socket.create_server(address=self.addr, family=socket.AF_INET)

    def wait_for_connection(self) -> Address:
        self.conn, client_address = self.sock.accept()

        return client_address

    def receive(self) -> None:
        receive = protocol.Receive(self.conn, self.key)
        receive.process()
        self.source_id = receive.source_id
        self.dest_id = receive.dest_id
        self._message = receive.message

    @property
    def message(self) -> bytes:
        if self._message is None:
            raise KeyError('message not ready')
        return self._message

    def close(self) -> None:
        if self.conn:
            self.conn.close()

        if self.sock:
            self.sock.close()


class Client:
    """
    Por padrão, conecta a um servidor no endereço indicado, usando o protocolo TCP
    """
    def __init__(self, addr: Address, source_id: int, dest_id: int, key: bytes, algorithm: str, pkcs5: bool) -> None:
        self.addr: Address = addr
        self.source_id: int = source_id
        self.dest_id: int = dest_id
        self.key: bytes = key
        self.algorithm: str = algorithm
        self.pkcs5: bool = pkcs5
        self.conn: socket.socket = None

    def connect(self) -> None:
        # função de conveniência cujo se conecta a um servidor existente
        self.conn = socket.create_connection(address=self.addr)

    def send(self, msg: bytes) -> None:
        send = protocol.Send(self.conn, self.key, self.source_id, self.dest_id, self.algorithm, self.pkcs5, msg)
        send.process()

    def close(self) -> None:
        if self.conn:
            self.conn.close()


def open_server(addr: Address, key: bytes) -> None:
    s = Server(addr, key)

    try:
        s.start()
        print(f'server listening on {addr}')
    except ConnectionRefusedError:
        print(f'couldn\'t start server on {addr}.')
        return

    try:
        print('waiting for a connection... press Ctrl + C to interrupt')
        client_addr = s.wait_for_connection()
        print(f'connection accepted from {client_addr}')

        s.receive()

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
    c = Client(addr, source_id, dest_id, key, algorithm, pkcs5)

    try:
        c.connect()
    except ConnectionRefusedError:
        print('couldn\'t connect to server.')
        return

    print(f'connected to server on {addr}')

    try:
        print('type your message (reading until EOF, Ctrl + D in some terminals)... press Ctrl + C to interrupt')

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
        c.send(terminal_input.encode('utf-8'))
    except Exception as e:
        print(f'some error occurred: {e}')
        return

    print('closing...')
    c.close()

    print('done.')
