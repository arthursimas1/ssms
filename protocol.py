import typing
import socket
import networking
import crypto


class ErrorCodes:
    OK = 0
    NotSupportedParams = 1
    Internal = 2
    KeyNotShared = 3
    UnexpectedType = 4
    NullIV = 5
    DataError = 6
    UnexpectedError = 7

    error_types = {
        0: 'OK',
        1: 'NotSupportedParams',
        2: 'Internal',
        3: 'KeyNotShared',
        4: 'UnexpectedType',
        5: 'NullIV',
        6: 'DataError',
        7: 'UnexpectedError',
    }

    def __init__(self, code):
        if code not in self.error_types:
            raise KeyError()

        self.code = code

    def __repr__(self):
        return f'Error.{self.error_types[self.code]}'


class ParReq:
    type = 0

    def __init__(self) -> None:
        self.code: ErrorCodes  # reserved
        self.source = None
        self.destination = None
        self.algorithm = None
        self.mode = None
        self.padding = None
        self.total_received_bytes = 0
        self._left_bytes: int = 0
        self._response: bytes = b''

    @property
    def left_bytes(self) -> int:
        return self._left_bytes

    @property
    def response(self) -> bytes:
        return self._response

    def update(self, data):
        pass

    def decode(self, data):
        self.type = data['type']
        self.source = data['source']
        self.destination = data['destination']
        self.algorithm = data['algorithm']
        self.mode = data['mode']
        self.padding = data['padding']


class ParConf:
    type = 1

    def __init__(self, code: ErrorCodes) -> None:
        self.code: ErrorCodes = code
        self.initialization_vector = None
        self.total_received_bytes = 0
        self._left_bytes = 0

    @property
    def left_bytes(self) -> int:
        return self._left_bytes


class Dados:
    type = 2

    def __init__(self, code: ErrorCodes) -> None:
        self.code: ErrorCodes = code
        self.size: int = 0
        self.encrypted_data = None
        self.total_received_bytes = 0
        self._left_bytes = 0

    @property
    def left_bytes(self) -> int:
        return self._left_bytes


class Lista:
    type = 3

    def __init__(self, code: ErrorCodes) -> None:
        self.code: ErrorCodes = code
        self.size: int = 0
        self.supported_params: list = []
        self.total_received_bytes: int = 0
        self._left_bytes: int = 0

    @property
    def left_bytes(self) -> int:
        self.size = 0
        return self._left_bytes


class Conf:
    type = 4

    def __init__(self, code: ErrorCodes) -> None:
        self.code: ErrorCodes = code
        self.total_received_bytes: int = 0
        self._left_bytes: int = 0

    @property
    def left_bytes(self) -> int:
        return self._left_bytes


class Message:
    supported_message_types = [ParReq, ParConf, Dados, Lista, Conf]

    def __init__(self, conn: socket.socket, key: bytes, source_id: int = None, dest_id: int = None, algorithm: str = None, pkcs5: bool = None, msg: bytes = None) -> None:
        self.conn: socket.socket = conn
        self.key: bytes = key
        self.source_id: int = source_id
        self.dest_id: int = dest_id
        self.algorithm: str = algorithm
        self.pkcs5: bool = pkcs5
        self._message: bytes = msg

    def process(self) -> None:
        pass
        if self._message is not None:
            pass

        while True:
            data = networking.Connection.receive(self.conn, 1)
            eight_bits = '{:0>8}'.format(bin(int(data, base=16)).lstrip('0b'))
            message_type = int(eight_bits[:4], base=2)
            message_code = int(eight_bits[4:8], base=2)
            message_object = None

            for t in self.supported_message_types:
                if t.type == message_type:
                    e = ErrorCodes(message_code)
                    message_object = t(e, self.conn)
                    break

            if message_object is None:
                raise KeyError()

            message_object.process()
            #message_object.

    @property
    def message(self) -> bytes:
        if self._message is None:
            raise KeyError('message not ready')
        return self._message


class Receive(Message):
    def __init__(self, conn: socket.socket, key: bytes) -> None:
        super().__init__(conn, key)

    def process(self) -> None:
        pass
        # <<< ParReq.receive()
        # >>> ParConf.send(), in case of error Lista.send()
        # <<< Dados.receive()
        # >>> Conf.send()


class Send(Message):
    def __init__(self, conn: socket.socket, key: bytes, source_id: int, dest_id: int, algorithm: str, pkcs5: bool, msg: bytes) -> None:
        super().__init__(conn, key, source_id, dest_id, algorithm, pkcs5, msg)

    def process(self) -> None:
        pass
        # >>> ParReq.send()
        # <<< ParConf.receive(), or Lista.receive, ParReq.send() and ParConf.receive()
        # >>> Dados.send()
        # <<< Conf.receive()
