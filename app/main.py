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
        ip, import json
import sys
import hashlib
import bencodepy
import requests
from urllib.parse import unquote
import struct
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import threading
def list_decode(bencoded_value):
    decode_list = []
    while chr(bencoded_value[0]) != "e":
        value, bencoded_value = _decode_bencode(bencoded_value)
        decode_list += [value]
    return decode_list, bencoded_value[1:]
def str_decode(bencoded_value):
    first_colon_index = bencoded_value.find(b":")
    key_length = int((bencoded_value[:first_colon_index]))
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    key = bencoded_value[first_colon_index + 1 : first_colon_index + key_length + 1]
    bencoded_value = bencoded_value[first_colon_index + key_length + 1 :]
    return key, bencoded_value
def int_decode(bencoded_value):
    int_len = bencoded_value.find(b"e")
    value = int(bencoded_value[:int_len])
    bencoded_value = bencoded_value[int_len + 1 :]
    return value, bencoded_value
def dict_decode(bencoded_value):
    # print(bencoded_value)
    decoded_dict = {}
    while chr(bencoded_value[0]) != "e":
        key, bencoded_value = _decode_bencode(bencoded_value)
        # print(key,":",bencoded_value)
        value, bencoded_value = _decode_bencode(bencoded_value)
        decoded_dict[key] = value
    # print(decoded_dict)
    return decoded_dict, bencoded_value[1:]
def _decode_bencode(bencoded_value):
    # print("decode 2",bencoded_value)
    if chr(bencoded_value[0]).isdigit():
        return str_decode(bencoded_value)
    elif chr(bencoded_value[0]) == "i":
        return int_decode(bencoded_value[1:])
    elif chr(bencoded_value[0]) == "d":
        return dict_decode(bencoded_value[1:])
    elif chr(bencoded_value[0]) == "l":
        return list_decode(bencoded_value[1:])
    elif chr(bencoded_value[0]) == "e":
        return _decode_bencode(bencoded_value[1:])
def decode_bencode(bencoded_value):
    return_value = []
    while len(bencoded_value) > 0:
        # print("before : ",bencoded_value,len(bencoded_value))
        value, bencoded_value = _decode_bencode(bencoded_value)
        # print("value in decode ",value)
        return_value += [value]
        # print("after : ",bencoded_value,len(bencoded_value))
    if len(return_value) == 1:
        return return_value[0]
    else:
        return return_value
def decode_file(file):
    with open(file, "rb") as pointer:
        data = pointer.read()
    return decode_bencode(data)
def extractInfo(data):
    info = bencodepy.encode(data[b"info"])
    info_hash = hashlib.sha1(info).hexdigest()
    url = bytes_to_str(data[b"announce"])
    length = data[b"info"][b"length"]
    piece_length = data[b"info"][b"piece length"]
    pieces = data[b"info"][b"pieces"]
    # print("pieces : ",len(pieces))
    # Each piece is of 20 bytes therefore the following
    hash_length = 20
    # pieces_sep = [pieces[num:num+hash_length] for num in range(0,len(pieces),20)]
    # #Hashes for the above
    # pieces_hash = "".join(peice.hex()+"\n" for peice in pieces_sep)
    pieces_hash = "".join(
        pieces[index : index + 20].hex() + "\n" for index in range(0, len(pieces), 20)
    )
    # print(f"Tracker URL: {url} ")
    # print(f"Length: {length}")
    # print(f"Info Hash: {info_hash}")
    # print(f"Piece Length: {piece_length}")
    # # print("Length of Pieces : ",len(pieces))
    # print(f"Piece Hashes:\n{pieces_hash}")
    return (url, length, info_hash, piece_length, pieces_hash)
def discoverPeers(data):
    url, length, info_hash, piece_length, pieces_hash = extractInfo(data)
    # url = bytes_to_str(data[b'announce'])
    # length = data[b"info"][b"length"]
    info = bencodepy.encode(data[b"info"])
    info_hash = hashlib.sha1(info).digest()
    # print(info)
    params = {
        "info_hash": info_hash,
        "peer_id": "12345678901234567890",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": length,
        "compact": 1,
    }
    response = requests.get(url, params=params)
    response_dict = decode_bencode(response.content)
    peers = response_dict.get(b"peers")
    # print(peers)
    peers_lst = {}
    for i in range(0, len(peers), 6):
        ip = ".".join(str(b) for b in peers[i : i + 4])
        port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
        peers_lst[ip] = port
        # print(f"Peer: {ip}:{port}")
    return peers_lst
def bytes_to_str(data):
    if isinstance(data, bytes):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            # If decoding fails, return a fallback representation of the bytes
            return repr(data)
    elif isinstance(data, dict):
        return {bytes_to_str(key): bytes_to_str(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [bytes_to_str(item) for item in data]
    else:
        return data
def tcpHandshake(data, ip, port, timeout=5):
    info = bencodepy.encode(data[b"info"])
    info_hash = hashlib.sha1(info).digest()
    """hanshake consist of 19+BitTorrent Protocol+8 zeros+info_hash+peerID"""
    handshake = (
        b"\x13"
        + b"BitTorrent protocol"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        + info_hash
        + b"01234567890123456789"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(25)
    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((ip, int(port)))
    sock.send(handshake)
    data = sock.recv(68)
    # sock.close()
    """ 48 because 1byte(19)+19bytes(BitTorrent Protocol)+8bytes(0's)+20bytes(info hash) then we have the peerID"""
    peer_id = data[48:].hex()
    # print("Peer ID:",peer_id)
    return peer_id, sock
def create_peer_message(message_id, length_prefix=1, payload=b""):
    # Calculate the length prefix as the length of the message ID + payload
    length_prefix = length_prefix
    length_prefix_bytes = length_prefix.to_bytes(4, byteorder="big")
    # Construct the message
    message = length_prefix_bytes + bytes([message_id]) + payload
    return message
def generate_send(
    piece_index,
    piece_length,
    msg_socket,
    file_length,
    total_pieces,
    block_size=16 * 1024,
):
    data_length = piece_length
    # Handle the last piece size if it's smaller than the standard piece length
    if piece_index == total_pieces - 1:
        data_length = file_length % piece_length
        # print(f"Last piece length: {data_length}")
    total_blocks = (
        data_length + block_size - 1
    ) // block_size  # Correct number of blocks for the last piece
    # print(f"Total Blocks = {total_blocks}")
    # print("data length ",data_length)
    DATA = bytearray()
    for block in range(total_blocks):
        begin = block * block_size
        length = min(block_size, data_length - begin)
        # Create the payload for the request message
        payload = (
            piece_index.to_bytes(4, byteorder="big")
            + begin.to_bytes(4, byteorder="big")
            + length.to_bytes(4, byteorder="big")
        )
        # Send the request to the peer
        msg_socket.sendall(
            create_peer_message(
                message_id=6, length_prefix=1 + 4 + 4 + 4, payload=payload
            )
        )
        # Receive the length of the incoming data
        len_byte = msg_socket.recv(4)
        Tlength = int.from_bytes(len_byte, byteorder="big")
        # Receive the actual data
        data = msg_socket.recv(Tlength)
        while len(data) < Tlength:
            data += msg_socket.recv(Tlength - len(data))
        # Append the data to the bytearray (ignore the header bytes if present)
        DATA.extend(data[9:])
    print(f"data got for peice {piece_index} of length", len(DATA))
    # if type(DATA)==bytearray and DATA:
    # print("DOne Here")
    return DATA
def download_piece(data, piece_index, msg_socket=None):
    url, length, info_hash, piece_length, pieces_hash = extractInfo(data)
    total_pieces = len(pieces_hash.splitlines())
    if total_pieces <= piece_index:
        print("piece index out of range")
        return
    # print(pieces_hash.splitlines()[piece_index])
    if msg_socket == None:
        peers_lst = discoverPeers(data)
        ip, port = list(peers_lst.keys()), list(peers_lst.values())
        peer_id, msg_socket = tcpHandshake(data, ip[0], port[0])
    recv = msg_socket.recv(1024)
    message_id = recv[4]  # --> 5 read and ignore
    # print(" bit field received message ID : ",message_id)
    msg_interested = create_peer_message(2)
    msg_socket.send(msg_interested)
    # print("interested sent")
    while message_id != 1:
        recv = msg_socket.recv(1024)
        message_id = recv[4]
        # message_id = int.from_bytes(recv[:4], byteorder='big')
        # print(recv[1],"\nreceived  : ",message_id)
    # print("received unchoke : ",message_id)
    piece_data = generate_send(
        piece_index=piece_index,
        piece_length=piece_length,
        msg_socket=msg_socket,
        file_length=length,
        total_pieces=total_pieces,
    )  # ,num_blocks=len(pieces_hash.splitlines()))
    # print(hashlib.sha1(data).hexdigest())
    if hashlib.sha1(piece_data).hexdigest() == pieces_hash.splitlines()[piece_index]:
        # print("Got the data perfectly")
        return piece_data
    else:
        return b""
def get_data(data, peers_lst, piece_index, max_retries=3):
    """Attempts to download a piece from the list of peers with retries."""
    # retries = 0
    # while retries < max_retries:
    # Make sure there are peers available to try
    if not peers_lst:
        print(f"No available peers to download piece {piece_index}")
        # break
        return None, peers_lst
    for ip, port in list(
        peers_lst.items()
    ):  # Make a list copy of peers to avoid modification issues
        try:
            _, msg_socket = tcpHandshake(data, ip, port)
            piece_data = download_piece(data, piece_index, msg_socket)
            if piece_data:
                return piece_data, peers_lst  # Successfully downloaded piece
        except Exception as e:
            print(f"Exception occurred with peer {ip}:{port}: {e}")
    return None, peers_lst  # Return None if all retries fail
def download_torrent(data, dest_file):
    file_data = {}
    url, length, info_hash, piece_length, pieces_hash = extractInfo(data)
    total_pieces = len(pieces_hash.splitlines())
    with open(dest_file, "ab") as temp:
        peers_lst = discoverPeers(data)
        lst_pieces = list(range(total_pieces))
        while lst_pieces:
            if not peers_lst:
                print("No peers left to attempt downloading pieces.")
                break  # Exit if there are no peers available
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_data = {
                    executor.submit(get_data, data, peers_lst, piece_index): piece_index
                    for piece_index in lst_pieces
                }
                for future in as_completed(future_data):
                    piece_index = future_data[future]
                    try:
                        piece_data, peers_lst = future.result()
                        if piece_data:
                            file_data[piece_index] = piece_data
                            lst_pieces.remove(
                                piece_index
                            )  # Only remove the piece if it was successfully downloaded
                    except Exception as e:
                        print(
                            f"Exception occurred while processing piece {piece_index}: {e}"
                        )
        # Write the downloaded pieces to the file in order
        if len(file_data) == total_pieces:
            for i in range(total_pieces):
                temp.write(file_data[i])
            print("Download completed successfully.")
        else:
            print(f"Download incomplete. {len(lst_pieces)} pieces failed to download.")
def extract_magnet_info(magnet_url):
    string_url = magnet_url.split("&")
    # print(f"String Url {string_url}")
    # parsed_url = urlparse(magnet_url)
    # params = parse_qs(parsed_url.query)
    info_hash = string_url[0].split(":")[-1]
    display_name = string_url[1].split("=")[-1]
    tracker = unquote(string_url[2].split("=")[-1])
    return {"info_hash": info_hash, "display_name": display_name, "tracker": tracker}
def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        print(json.dumps(bytes_to_str(decode_bencode(bencoded_value))))
    elif command == "info":
        file = sys.argv[2]
        url, length, info_hash, piece_length, pieces_hash = extractInfo(
            decode_file(file)
        )
        print(f"Tracker URL: {url} ")
        print(f"Length: {length}")
        print(f"Info Hash: {info_hash}")
        print(f"Piece Length: {piece_length}")
        print(f"Piece Hashes:\n{pieces_hash}")
    elif command == "peers":
        file = sys.argv[2]
        peers_lst = discoverPeers(decode_file(file))
        for ip, port in peers_lst.items():
            print(f"Peer: {ip}:{port}")
    elif command == "handshake":
        file = sys.argv[2]
        ip, port = sys.argv[3].split(":")
        peer_id, _ = tcpHandshake(decode_file(file), ip, port)
        print("Peer ID:", peer_id)
    elif command == "download_piece" and len(sys.argv) >= 5:
        # print("Download piece impl")
        # -o /tmp/test-piece-0 sample.torrent 0
        tag = sys.argv[2]
        dest_file = sys.argv[3]
        file = sys.argv[4]
        piece_index = int(sys.argv[5])
        if tag == "-o":
            data = download_piece(decode_file(file), piece_index)
            if data != None:
                with open(dest_file, "wb") as dest:
                    dest.write(data)
                    dest.close()
    elif command == "download" and len(sys.argv) >= 4:
        tag = sys.argv[2]
        dest_file = sys.argv[3]
        file = sys.argv[4]
        if tag == "-o":
            data = download_torrent(decode_file(file), dest_file)
    elif command == "magnet_parse":
        magnet_url = sys.argv[2]
        # print(magnet_url)
        magnet_extract = extract_magnet_info(magnet_url)
        print(
            f"Tracker URL: {magnet_extract['tracker']}\nInfo Hash: {magnet_extract['info_hash']}"
        )
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()port = sys.argv[3].split(":")
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