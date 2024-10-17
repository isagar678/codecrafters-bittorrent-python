import json
import sys
import hashlib
import bencodepy 
import requests
# import requests - available if you need it!
import hashlib
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
    elif command=="peers":
        file_name=sys.argv[2]
        with open(file_name,"rb") as torrent_file:
            bencoded_content=torrent_file.read()
        torrent=decode_bencode(bencoded_content)
        if "info" in torrent:
            info = torrent["info"]
        elif b"info" in torrent:
            info = torrent[b"info"]
        info_hashed = hashlib.sha1(bencodepy.encode(info)).hexdigest()
        url=torrent["announce"].decode()
        query_params={
            "info_hash":info_hashed,
            "port":6881,
            "peer_id": "00112233445566778899",
            "uploaded":0,
            "downloaded":0,
            "left":torrent["info"]["piece length"],
            "compact":1
        }
        response=requests.get(url,query_params)
        peers,_=decode_bencode(response.content)
        for i in range(0, len(peers), 6):
            ip = ".".join(str(b) for b in peers[i : i + 4])
            port = int.from_bytes(peers[i + 4 : i + 6], byteorder='big')
            print(f"Peer: {ip}:{port}")


    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()