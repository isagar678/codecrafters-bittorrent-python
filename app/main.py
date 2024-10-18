import json
import sys
import bencodepy
import hashlib
import requests
import struct
import random
import string
import socket
import math
def generate_random_string(length):
    """Generates a random string of the specified length containing digits 0-9."""
    digits = string.digits  # String containing digits 0-9
    return "".join(random.choice(digits) for _ in range(length))
# import bencodepy - available if you need it!
# import requests - available if you need it!
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    def extract_string(data):
        length, rest = data.split(b":", 1)
        length = int(length)
        return rest[:length], rest[length:]
    def Decode(data):
        if data == b"" or data == b"e":
            return str(""), str("")
        if data[0:1].isdigit():
            decoded_str, rest = extract_string(data)
            return decoded_str, rest
        elif data.startswith(b"i"):  # to handle bencoded integers
            end = data.index(b"e")
            decoded_integer, rest = int(data[1:end]), data[end + 1 :]
            return decoded_integer, rest
        elif data.startswith(b"l"):  # to handle bencoded lists
            data = data[1:]
            result = []
            while not data.startswith(b"e"):
                item, data = Decode(data)
                result.append(item)
            return result, data[1:]
        elif data.startswith(b"d"):
            data = data[1:]
            result = {}
            while not data.startswith(b"e"):
                key, data = Decode(data)
                # print("key is", key)
                if not isinstance(key, bytes):
                    raise ValueError("Dictionary key should be a byte string")
                value, data = Decode(data)
                result[key.decode()] = value
            return result, data[1:]
        else:
            raise ValueError("Unsuppored or invalid bencoded value")
    decoded_value, _ = Decode(bencoded_value)
    return decoded_value
def extract_torrent_info(filename):
    with open(filename, "rb") as f:
        content = f.read()
    # decoded = bencodepy.decode(content)
    decoded = decode_bencode(content)
    # Ensure both announce and info exist in the decoded dictionary
    if "announce" not in decoded or "info" not in decoded:
        raise ValueError("Invalid torrent file")
    # Extract the required values
    tracker_url = decoded["announce"].decode("utf-8")
    file_length = decoded["info"]["length"]
    info_hash = hashlib.sha1(bencodepy.encode(decoded["info"])).hexdigest()
    piece_length = decoded["info"]["piece length"]
    print("Tracker URL:", tracker_url)
    print("Length:", file_length)
    print("Info Hash:", info_hash)
    print("Piece Length:", piece_length)
    print("Piece Hashes:")
    for i in range(0, len(decoded["info"]["pieces"]), 20):
        print(decoded["info"]["pieces"][i : i + 20].hex())
def get_peers(filename):
    with open(filename, "rb") as f:
        content = f.read()
    torrent_info = decode_bencode(content)
    tracker_url = torrent_info.get("announce", "").decode()
    info_dict = torrent_info.get("info", {})
    bencoded_info = bencodepy.encode(info_dict)
    info_hash = hashlib.sha1(bencoded_info).digest()
    peer_id = generate_random_string(20)
    params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": torrent_info.get("info", {}).get("length", 0),
        "compact": 1,
    }
    response = requests.get(tracker_url, params=params)
    response_dict = decode_bencode(response.content)
    peers = response_dict.get("peers", b"")
    for i in range(0, len(peers), 6):
        ip = ".".join(str(b) for b in peers[i : i + 4])
        port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
        print(f"Peer: {ip}:{port}")
def get_peers_list(filename):
    with open(filename, "rb") as f:
        content = f.read()
    result = []
    torrent_info = decode_bencode(content)
    tracker_url = torrent_info.get("announce", "").decode()
    info_dict = torrent_info.get("info", {})
    bencoded_info = bencodepy.encode(info_dict)
    info_hash = hashlib.sha1(bencoded_info).digest()
    peer_id = generate_random_string(20)
    params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": torrent_info.get("info", {}).get("length", 0),
        "compact": 1,
    }
    response = requests.get(tracker_url, params=params)
    response_dict = decode_bencode(response.content)
    peers = response_dict.get("peers", b"")
    for i in range(0, len(peers), 6):
        ip = ".".join(str(b) for b in peers[i : i + 4])
        port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
        result.append(f"{ip}:{port}")
    return result
def handshake_peer(filename, ip, port):
    with open(filename, "rb") as f:
        content = f.read()
    parsed = decode_bencode(content)
    info = parsed["info"]
    bencoded_info = bencodepy.encode(info)
    info_hash = hashlib.sha1(bencoded_info).digest()
    peer_id = generate_random_string(20)
    handshake = (
        b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
        + info_hash
        + bytes(peer_id, encoding="utf-8")
    )
    # make tcp connection with peer
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, int(port)))
        s.send(handshake)
        print(f"Peer ID: {s.recv(68)[48:].hex()}")
def get_peer_id(filename, ip, port):
    with open(filename, "rb") as f:
        content = f.read()
    parsed = decode_bencode(content)
    info = parsed["info"]
    bencoded_info = bencodepy.encode(info)
    info_hash = hashlib.sha1(bencoded_info).digest()
    peer_id = generate_random_string(20)
    handshake = (
        b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
        + info_hash
        + bytes(peer_id, encoding="utf-8")
    )
    # make tcp connection with peer
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, int(port)))
        s.send(handshake)
        return s.recv(68)[48:].hex()
def download_piece(decoded_data, info_hash, piece_index, torrent_file, output_file):
    peers = get_peers_list(torrent_file)
    peer_ip, peer_port = peers[0].split(":")
    peer_port = int(peer_port)
    peer_id = get_peer_id(torrent_file, peer_ip, peer_port)
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
        # waiting for a bitfield message
        while int(message[4]) != 5:
            message = receive_message(sock)
        # Send interested message
        interested_payload = struct.pack(">IB", 1, 2)
        sock.sendall(interested_payload)
        message = receive_message(sock)
        while int(message[4]) != 1:
            message = receive_message(sock)
        # waiting for an unchoke message
        while int(message[4]) != 1:
            message = receive_message(sock)
        file_length = decoded_data["info"]["length"]
        total_number_of_pieces = int(len(decoded_data["info"]["pieces"]) / 20)
        default_piece_length = decoded_data["info"]["piece length"]
        if piece_index == total_number_of_pieces - 1:
            piece_length = file_length - (default_piece_length * piece_index)
        else:
            piece_length = default_piece_length
        number_of_blocks = math.ceil(piece_length / (16 * 1024))
        data = bytearray()
        for block_index in range(number_of_blocks):
            begin = 2**14 * block_index
            # print(f"begin: {begin}")
            block_length = min(piece_length - begin, 2**14)
            print()  # f"Requesting block {block_index + 1} of {number_of_blocks} with length {block_length}"
            # print(f"Requesting block {block_index + 1} of {number_of_blocks} with length {block_length}")
            request_payload = struct.pack(
                ">IBIII", 13, 6, piece_index, begin, block_length
            )
            # print("Requesting block, with payload:")
            # print(request_payload)
            # print(struct.unpack(">IBIII", request_payload))
            # print(int.from_bytes(request_payload[:4]))
            # print(int.from_bytes(request_payload[4:5]))
            # print(int.from_bytes(request_payload[5:9]))
            # print(int.from_bytes(request_payload[17:21]))
            sock.sendall(request_payload)
            message = receive_message(sock)
            data.extend(message[13:])
        with open(output_file, "ab") as f:
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
def main():
    command = sys.argv[1]
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")
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
        torrent_file = sys.argv[2].encode()
        extract_torrent_info(torrent_file)
    elif command == "peers":
        torrent_file = sys.argv[2].encode()
        get_peers(torrent_file)
    elif command == "handshake":
        file_name = sys.argv[2].encode()
        ip, port = sys.argv[3].split(":")
        print(file_name, ip, port)
        handshake_peer(file_name, ip, port)
    elif command == "download_piece":
        output_file = sys.argv[3]
        piece_index = int(sys.argv[5])
        torrent_file = sys.argv[4]
        with open(torrent_file, "rb") as f:
            torrent_data = f.read()
        decoded_data = decode_bencode(torrent_data)
        # print(hashlib.sha1(bencodepy.encode(decoded_data['info'])).hexdigest())
        if download_piece(
            decoded_data,
            hashlib.sha1(bencodepy.encode(decoded_data["info"])).digest(),
            piece_index,
            torrent_file,
            output_file,
        ):
            print(f"Piece {piece_index} downloaded to {output_file}")
        else:
            raise RuntimeError("Failed to download piece")
    elif command == "download":
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        with open(torrent_file, "rb") as f:
            torrent_data = f.read()
        decoded_data = decode_bencode(torrent_data)
        total_number_of_pieces = int(len(decoded_data["info"]["pieces"]) / 20)
        info_hash = hashlib.sha1(bencodepy.encode(decoded_data["info"])).digest()
        # For all pieces, download and apppend to the output_file
        for i in range(0, total_number_of_pieces):
            if download_piece(decoded_data, info_hash, i, torrent_file, output_file):
                print(f"Piece {i} appended to {output_file}")
            else:
                raise RuntimeError(
                    f"Failed to download file. Piece {i} could not be downloaded"
                )
    elif command == "magnet_parse":
        magnet_link = sys.argv[2]
        tracker_url = (
            magnet_link.split("&tr=")[1].replace("%3A", ":").replace("%2F", "/")
        )
        info_hash = (
            magnet_link.split("xt=urn:btih:")[1]
            .split("&dn=")[0]
            .replace("%3A", ":")
            .replace("%2F", "/")
        )
        print("Tracker URL:", tracker_url)
        print("Info Hash:", info_hash)
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()