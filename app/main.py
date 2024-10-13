import json
import sys
import bencodepy

# Using bencodepy to decode bencoded values
def decode_bencode(bencoded_value):
    return bencodepy.decode(bencoded_value)

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
                return data.decode('utf-8', errors='replace')  # safely decode bytes to string
            elif isinstance(data, list):
                return [bytes_to_str(item) for item in data]
            elif isinstance(data, dict):
                return {bytes_to_str(key): bytes_to_str(value) for key, value in data.items()}
            return data

        # Decode the bencoded value and convert bytes to strings where needed
        decoded_data = decode_bencode(bencoded_value)
        print(json.dumps(bytes_to_str(decoded_data)))

    elif command == "info":
        file_name = sys.argv[2]

        # Read the torrent file and decode it
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()

        # Decode the torrent using bencodepy
        torrent = decode_bencode(bencoded_content)

        # Extracting and printing the necessary fields
        try:
            print("Tracker URL:", torrent[b"announce"].decode('utf-8'))
        except KeyError:
            print("No 'announce' key found in the torrent file.")

        try:
            print("Length:", torrent[b"info"][b"length"])
        except KeyError:
            print("No 'info' key or 'length' field found in the torrent file.")
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
