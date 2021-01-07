import argparse
import networking


'''
--client --key "chave 1 de teste"
--client --key "chave 1 de teste" --key-type=ascii
--client --key "63686176652031206465207465737465" --key-type=hex
--client --key "chave 1 de teste" --addr=192.168.0.1,8000
--client --key "chave 1 de teste" --addr=example.com,120
--client --key "chave 1 de teste" --algorithm=AES256,CFB128
--client --key "chave 1 de teste" --pkcs5
--client --key "chave 1 de teste" --algorithm=AES256,CFB128 --pkcs5
--client --key "chave 1 de teste" --algorithm=3DES-EDE2,CFB128
--server --key "chave 1 de teste"
--server --key "chave 1 de teste" --addr=10.0.0.20,8080
'''


def main():
    parser = argparse.ArgumentParser(prog='python3 main.py',
                                     description='Send encrypted messages to someone.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--server',
                       help='Set server mode.',
                       action='store_true')
    group.add_argument('--client',
                       help='Set client mode. Optionally can define --algorithm and --pkcs5. Requires --source-id and --dest-id.',
                       action='store_true')
    parser.add_argument('--key',
                        help='Define the key used in the communication.',
                        required=True)
    parser.add_argument('--source-id',
                        help='ID of source ID.',
                        type=int,
                        required=False)
    parser.add_argument('--dest-id',
                        help='ID of destination ID.',
                        type=int,
                        required=False)
    parser.add_argument('--key-type',
                        help='Define how the key parameter should be interpreted, either ascii or hex mode.',
                        choices=['ascii', 'hex'],
                        default='ascii',
                        required=False)
    parser.add_argument('--addr',
                        help='Set server address and port (delimited by a comma), either to bind or connect to it.',
                        default='127.0.0.1,50000',
                        required=False)
    parser.add_argument('--algorithm',
                        help='Define algorithm and mode to be used (delimited by a comma). An error is thrown if it isn\'t supported.',
                        default='AES128,ECB',
                        required=False)
    parser.add_argument('--pkcs5',
                        help='Enable PKCS5 padding mode.',
                        action='store_true')
    args = parser.parse_args()

    address, port = args.addr.split(',')
    #key = 1, args.key_type: str
    # args.key
    key = b'chave 1 de teste'

    if args.server:
        if args.source_id is not None:
            parser.error("--server doesn't need --source-id parameter.")
        if args.dest_id is not None:
            parser.error("--server doesn't need --dest-id parameter.")

        networking.open_server((address, int(port)), key)
    else:
        if args.source_id is None or args.dest_id is None:
            parser.error("--client requires --source-id and --dest-id.")

        networking.open_client((address, int(port)), args.source_id, args.dest_id, key, args.algorithm, args.pkcs5)


if __name__ == '__main__':
    main()
