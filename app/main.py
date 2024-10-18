import json
import socket
import sys
import hashlib
import bencodepy 
import requests
import struct
# import requests - available if you need it!
import hashlib



def download_piece(decoded_data, info_hash, piece_index, output_file):
    peers = get_peers(decoded_data, info_hash)
    peer_ip, peer_port = peers[0].split(":")
    peer_port = int(peer_port)
    get_peer_id(peer_ip, peer_port, info_hash)
    protocol_name_length = struct.pack(">B", 19)
    protocol_name = b"BitTorrent protocol"
    reserved_bytes = b"\x00" * 8
    peer_id = b"PC0001-7694471987235"
    payload = (
        protocol_name_length + protocol_name + reserved_bytes + info_hash + peer_id
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((peer_ip, peer_port))
        sock.sendall(payload)
        response = sock.recv(68)
        message = receive_message(sock)
        while int(message[4]) != 5:
            message = receive_message(sock)
        interested_payload = struct.pack(">IB", 1, 2)
        sock.sendall(interested_payload)
        message = receive_message(sock)
        while int(message[4]) != 1:
            message = receive_message(sock)
        file_length = decoded_data["info"]["length"]
        total_number_of_pieces = len(
            extract_pieces_hashes(decoded_data["info"]["pieces"])
        )
        default_piece_length = decoded_data["info"]["piece length"]
        if piece_index == total_number_of_pieces - 1:
            piece_length = file_length - (default_piece_length * piece_index)
        else:
            piece_length = default_piece_length
        number_of_blocks = math.ceil(piece_length / (16 * 1024))
        data = bytearray()
        for block_index in range(number_of_blocks):
            begin = 2**14 * block_index
            print(f"begin: {begin}")
            block_length = min(piece_length - begin, 2**14)
            print(
                f"Requesting block {block_index + 1} of {number_of_blocks} with length {block_length}"
            )
            request_payload = struct.pack(
                ">IBIII", 13, 6, piece_index, begin, block_length
            )
            print("Requesting block, with payload:")
            print(request_payload)
            print(struct.unpack(">IBIII", request_payload))
            print(int.from_bytes(request_payload[:4]))
            print(int.from_bytes(request_payload[4:5]))
            print(int.from_bytes(request_payload[5:9]))
            print(int.from_bytes(request_payload[17:21]))
            sock.sendall(request_payload)
            message = receive_message(sock)
            data.extend(message[13:])
        with open(output_file, "wb") as f:
            f.write(data)
    finally:
        sock.close()
    return True
def receive_message(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    # If we didn't receive the full message for some reason, keep gobbling.
    while len(message) < int.from_bytes(length):
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message







def decode_part(value, start_index):
    if chr(value[start_index]).isdigit():
        return decode_string(value, start_index)
    elif chr(value[start_index]) == "i":
        return decode_integer(value, start_index)
    elif chr(value[start_index]) == "l":
        return decode_list(value, start_index)
    elif chr(value[start_index]) == "d":
        return decode_dict(value, start_index)
    else:
        raise NotImplementedError(
            "Only strings and integers are supported at the moment"
        )
def decode_string(bencoded_value, start_index):
    if not chr(bencoded_value[start_index]).isdigit():
        raise ValueError("Invalid encoded string", bencoded_value, start_index)
    bencoded_value = bencoded_value[start_index:]
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    length = int(bencoded_value[:first_colon_index])
    word_start = first_colon_index + 1
    word_end = first_colon_index + length + 1
    return bencoded_value[word_start:word_end], start_index + word_end
def decode_integer(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "i":
        raise ValueError("Invalid encoded integer", bencoded_value, start_index)
    bencoded_value = bencoded_value[start_index:]
    end_marker = bencoded_value.find(b"e")
    if end_marker == -1:
        raise ValueError("Invalid encoded integer", bencoded_value)
    return int(bencoded_value[1:end_marker]), start_index + end_marker + 1
def decode_list(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "l":
        raise ValueError("Invalid encoded list", bencoded_value, start_index)
    current_index = start_index + 1
    values = []
    while chr(bencoded_value[current_index]) != "e":
        value, current_index = decode_part(bencoded_value, current_index)
        values.append(value)
    return values, current_index + 1
def decode_dict(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "d":
        raise ValueError("Invalid encoded dict", bencoded_value, start_index)
    current_index = start_index + 1
    values = {}
    while chr(bencoded_value[current_index]) != "e":
        key, current_index = decode_string(bencoded_value, current_index)
        value, current_index = decode_part(bencoded_value, current_index)
        values[key.decode()] = value
    return values, current_index
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    return decode_part(bencoded_value, 0)[0]
def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        file_name = sys.argv[2]
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()
        torrent = decode_bencode(bencoded_content)
        if "info" in torrent:
            info = torrent["info"]
        elif b"info" in torrent:
            info = torrent[b"info"]
        else:
            print("Error: 'info' key not found in the torrent file.")
            sys.exit(1)

        # Calculate the info hash
        info_hashed = hashlib.sha1(bencodepy.encode(info)).hexdigest()
        print("Tracker URL:", torrent["announce"].decode())
        print("Length:", torrent["info"]["length"])
        print("Info Hash:",info_hashed)
        print("Piece Length:",torrent["info"]["piece length"])
        print('Piece Hashes:')
        for i in range(0, len(torrent["info"]["pieces"]), 20):
            piece_hash = torrent["info"]["pieces"][i:i + 20]
            print(piece_hash.hex())
    elif command == "peers":
        file_name = sys.argv[2]
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()
        torrent = decode_bencode(bencoded_content)
        url = torrent["announce"].decode()
        query_params = dict(
            info_hash=hashlib.sha1(bencodepy.encode(torrent["info"])).digest(),
            peer_id="00112233445566778899",
            port=6881,
            uploaded=0,
            downloaded=0,
            left=torrent["info"]["length"],
            compact=1,
        )
        response = decode_bencode(requests.get(url, query_params).content)
        peers = response["peers"]
        for i in range(0, len(peers), 6):
            peer = peers[i : i + 6]
            ip_address = f"{peer[0]}.{peer[1]}.{peer[2]}.{peer[3]}"
            port = int.from_bytes(peer[4:], byteorder="big", signed=False)
            print(f"{ip_address}:{port}")

    elif command == "handshake":
        file_name = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")
        with open(file_name, "rb") as file:
            parsed = decode_bencode(file.read())
            info = parsed["info"]
            bencoded_info = bencodepy.encode(info)
            info_hash = hashlib.sha1(bencoded_info).digest()
            handshake = (
                b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
                + info_hash
                + b"00112233445566778899"
            )
            # make request to peer
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, int(port)))
                s.send(handshake)
                print(f"Peer ID: {s.recv(68)[48:].hex()}")
    elif command=='download_piece':
            output_file = sys.argv[3]
            piece_index = int(sys.argv[5])
            torrent_file = sys.argv[4]
            with open(torrent_file, "rb") as f:
                torrent_data = f.read()
            decoded_data = decode_bencode(torrent_data)[0]
            if download_piece(
                decoded_data,
                hashlib.sha1(extract_info_hash(torrent_data)).digest(),
                piece_index,
                output_file,
            ):
                print(f"Piece {piece_index} downloaded to {output_file}.")
            else:
                raise RuntimeError("Failed to download piece")


    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()