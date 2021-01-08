import typing
import socket
import struct
import networking
import os
import crypto


"""
Convert that byte to an 8 bit string.
"""
def byte_to_bitstring(data: bytes) -> str:
    assert len(data) == 1, 'it only works with one byte at time'
    return '{:0>8}'.format(bin(int.from_bytes(data, 'big')).lstrip('0b'))


class ErrorCodes(Exception):
    """
    Error Codes class
    """

    # Give an id to all the possible errors
    OK = 0
    NotSupportedParams = 1
    Internal = 2
    KeyNotShared = 3
    UnexpectedType = 4
    NullIV = 5
    DataError = 6

    # Maps back the id to the error string
    error_types = {
        0: 'OK',
        1: 'NotSupportedParams',
        2: 'Internal',
        3: 'KeyNotShared',
        4: 'UnexpectedType',
        5: 'NullIV',
        6: 'DataError',
    }

    def __init__(self, code: int) -> None:
        # Thrown an error error if the error code isn't found.
        if code not in self.error_types:
            raise KeyError('error code not found')

        self._code: int = code
        super(ErrorCodes, self).__init__(self.__repr__())

    """
    Error code getter
    """
    @property
    def code(self) -> int:
        return self._code

    """
    Defines a string representation for this class.
    """
    def __repr__(self) -> str:
        return f'Error.{self.error_types[self._code]}'

    """
    Operator overloading to enable comparisons as error == ErrorCodes.OK
    """
    def __eq__(self, other: int) -> bool:
        return self._code == other


class Protocol:
    ParReq = 0
    ParConf = 1
    Dados = 2
    Lista = 3
    Conf = 4

    alg_to_code = {
        'AES128': 0,
        'AES192': 1,
        'AES256': 2,
        'DES': 3,
        '3DES-EDE2': 4,
        '3DES-EDE3': 5,
    }

    code_to_alg = {
        0: 'AES128',
        1: 'AES192',
        2: 'AES256',
        3: 'DES',
        4: '3DES-EDE2',
        5: '3DES-EDE3',
    }

    mode_to_code = {
        'ECB': 0,
        'CBC': 1,
        # 'CFB1': 2,
        'CFB8': 3,
        # 'CFB64': 4,
        # 'CFB128': 5,
        'CTR': 6,
    }

    code_to_mode = {
        0: 'ECB',
        1: 'CBC',
        # 2: 'CFB1',
        3: 'CFB8',
        # 4: 'CFB64',
        # 5: 'CFB128',
        6: 'CTR',
    }

    def __init__(self, conn: socket.socket, key: bytes, source_id: int = None, dest_id: int = None, algorithm: str = None, pkcs5: bool = None, msg: bytes = None) -> None:
        self.conn: socket.socket = conn
        self.key: bytes = key
        self.source_id: int = source_id
        self.dest_id: int = dest_id

        if algorithm is not None:
            try:
                alg, mode = algorithm.split(',')
            except:
                raise RuntimeError('algorithm bad formatted')

            # Algorithm and mode strings
            self.algorithm: str = alg
            self.algorithm_mode: str = mode

            # Algorithm and mode codes

            try:
                self.algorithm_code: int = self.alg_to_code[alg]
                self.algorithm_mode_code: int = self.mode_to_code[mode]
            except:
                raise RuntimeError('algorithm not supported')

        self.pkcs5: bool = pkcs5
        self.iv: bytes = b''

        if msg is not None:
            if len(msg) > 1440:
                raise ErrorCodes(ErrorCodes.Internal)

            self._message: bytes = msg

    @property
    def message(self) -> bytes:
        if self._message is None:
            raise RuntimeError('message not ready')
        return self._message

    """
    Checks if the message type is as expected
    """
    def first_byte_check(self, expected_type: int) -> ErrorCodes:
        # Fetch a single byte
        data = networking.Connection.receive(self.conn, 1)

        eight_bits = byte_to_bitstring(data)

        if int(eight_bits[:4], base=2) != expected_type:
            raise ErrorCodes(ErrorCodes.UnexpectedType)

        error_code = int(eight_bits[4:], base=2)
        return ErrorCodes(error_code)

    def par_req_send(self) -> None:
        # B unsigned char (1 byte)
        # H unsigned short (2 bytes)

        data: bytes = struct.pack('>BHHBB',
                                  self.ParReq << 4 | ErrorCodes.OK,
                                  self.source_id,
                                  self.dest_id,
                                  self.algorithm_code << 4 | self.pkcs5,
                                  self.algorithm_mode_code)

        networking.Connection.send(self.conn, data)

    def par_req_recv(self) -> None:
        error: ErrorCodes = self.first_byte_check(self.ParReq)
        if error != ErrorCodes.OK:
            raise ErrorCodes(ErrorCodes.Internal)

        data: bytes = networking.Connection.receive(self.conn, 6)
        self.source_id = int.from_bytes(data[:2], 'big')
        self.dest_id = int.from_bytes(data[2:4], 'big')

        alg_padding = byte_to_bitstring(data[4:5])
        alg = int(alg_padding[:4], base=2)
        if alg not in self.code_to_alg:
            raise ErrorCodes(ErrorCodes.NotSupportedParams)
        self.algorithm = self.code_to_alg[alg]
        self.algorithm_code = alg

        padding = int(alg_padding[4:], base=2)
        if padding not in [0, 1]:
            raise ErrorCodes(ErrorCodes.NotSupportedParams)
        self.pkcs5 = padding

        mode = int.from_bytes(data[5:6], 'big')
        if mode not in self.code_to_mode:
            raise ErrorCodes(ErrorCodes.NotSupportedParams)

        self.algorithm_mode = self.code_to_mode[mode]
        self.algorithm_mode_code = mode

    def par_conf_send(self) -> None:
        # B unsigned char (1 byte)
        self.iv = os.urandom(16)

        data: bytes = struct.pack('>B', self.ParConf << 4 | ErrorCodes.OK)
        data += self.iv

        networking.Connection.send(self.conn, data)

    def par_conf_recv(self, error: ErrorCodes) -> None:
        data: bytes = networking.Connection.receive(self.conn, 16)
        if error != ErrorCodes.OK:
            raise ErrorCodes(ErrorCodes.Internal)

        self.iv = data

        if self.iv == b'0' * 16:
            raise ErrorCodes(ErrorCodes.NullIV)

    def dados_send(self) -> None:
        # B unsigned char (1 byte)
        # H unsigned short (2 bytes)

        err = ErrorCodes.OK
        err_obj = None
        try:
            payload: bytes = crypto.encrypt(self._message,
                                            self.key,
                                            self.iv,
                                            self.algorithm,
                                            self.algorithm_mode,
                                            self.pkcs5)
        except Exception as e:
            payload = b''
            err = ErrorCodes.Internal
            err_obj = e

        data: bytes = struct.pack('>BH',
                                  self.Dados << 4 | err,
                                  len(payload))
        data += payload

        networking.Connection.send(self.conn, data)

        if err != ErrorCodes.OK:
            raise err_obj

    def dados_recv(self) -> ErrorCodes:
        error: ErrorCodes = self.first_byte_check(self.Dados)
        if error != ErrorCodes.OK:
            return error

        payload_size: int = int.from_bytes(networking.Connection.receive(self.conn, 2), 'big')
        payload: bytes = networking.Connection.receive(self.conn, payload_size)

        try:
            self._message = crypto.decrypt(payload,
                                           self.key,
                                           self.iv,
                                           self.algorithm,
                                           self.algorithm_mode,
                                           self.pkcs5)
        except:
            raise ErrorCodes(ErrorCodes.DataError)

        return error

    """
    This protocol implementation doesn't support sending Lista message.
    """
    def lista_send(self) -> None:
        raise RuntimeError('not implemented')

    def lista_recv(self, error: ErrorCodes) -> typing.Tuple[ErrorCodes, list]:
        payload_size: int = int.from_bytes(networking.Connection.receive(self.conn, 1), 'big')
        payload: bytes = networking.Connection.receive(self.conn, payload_size)

        recv_list = []

        for pos in range(len(payload) // 2):
            i = pos * 2

            opt = {}
            alg_padding = byte_to_bitstring(payload[i:i+1])

            alg = int(alg_padding[:4], base=2)
            opt['algorithm'] = self.code_to_alg[alg]

            padding = int(alg_padding[4:], base=2)
            opt['padding'] = padding == 1

            mode = int.from_bytes(payload[i+1:i+2], 'big')
            opt['algorithm_mode'] = self.code_to_alg[mode]

            recv_list.append(opt)

        return error, recv_list

    def conf_send(self, error: ErrorCodes) -> None:
        # B unsigned char (1 byte)
        data: bytes = struct.pack('>B', self.Conf << 4 | error.code)
        networking.Connection.send(self.conn, data)

    def conf_recv(self) -> ErrorCodes:
        return self.first_byte_check(self.Conf)

    def par_conf_OR_lista_recv(self) -> typing.Any:
        data = networking.Connection.receive(self.conn, 1)

        eight_bits = byte_to_bitstring(data)
        type_code = int(eight_bits[:4], base=2)
        error_code = int(eight_bits[4:], base=2)
        error = ErrorCodes(error_code)

        if type_code == self.ParConf:
            return self.par_conf_recv(error)
        elif type_code == self.Lista:
            return self.lista_recv(error)

        raise ErrorCodes(ErrorCodes.UnexpectedType)


class Receive(Protocol):
    def __init__(self, conn: socket.socket, key: bytes) -> None:
        super().__init__(conn, key)

    def process(self) -> None:
        try:
            self.par_req_recv()
        except ErrorCodes as e:
            self.conf_send(ErrorCodes(ErrorCodes.Internal))
            raise e

        self.par_conf_send()

        try:
            err = self.dados_recv()
        except ErrorCodes as e:
            self.conf_send(e)
            raise e

        if err != ErrorCodes.OK:
            raise err

        self.conf_send(ErrorCodes(ErrorCodes.OK))


class Send(Protocol):
    def __init__(self, conn: socket.socket, key: bytes, source_id: int, dest_id: int, algorithm: str, pkcs5: bool, msg: bytes) -> None:
        super().__init__(conn, key, source_id, dest_id, algorithm, pkcs5, msg)

    def process(self) -> None:
        self.par_req_send()

        try:
            ret = self.par_conf_OR_lista_recv()
            if ret is not None:  # Message of type Lista received
                raise ret[0]
        except ErrorCodes as e:
            self.conf_send(ErrorCodes(ErrorCodes.Internal))
            raise e

        try:
            self.dados_send()
        except ErrorCodes as e:
            self.conf_send(ErrorCodes(ErrorCodes.Internal))
            raise e

        err = self.conf_recv()
        if err != ErrorCodes.OK:
            raise err
