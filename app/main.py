import json
import sys
import bencodepy 

def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        return bencoded_value[first_colon_index+1:]
    elif chr(bencoded_value[0]) == 'i' and chr(bencoded_value[-1]) == 'e':
        return int(bencoded_value[1:-1])
    elif chr(bencoded_value[0]) == 'l' and chr(bencoded_value[-1]) == 'e':
        return bencodepy.decode(bencoded_value)
    elif chr(bencoded_value[0]) == 'd' and chr(bencoded_value[-1]) == 'e':
        return bencodepy.Bencode(encoding="utf-8").decode(bencoded_value)
    else:
        raise NotImplementedError("Only strings are supported at the moment")

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode(errors='replace')  # Handle non-UTF-8 chars gracefully
            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))

    elif command == "info":
        file_name = sys.argv[2]
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()
        torrent = decode_bencode(bencoded_content)

        # Use 'replace' to avoid errors in case non-utf-8 characters exist
        print("Tracker URL:", torrent["announce"].decode('utf-8', errors='replace'))
        print("Length:", torrent["info"]["length"])

    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
