import json
import sys
import bencodepy

# Manual decoding functions
def decode_string(bencoded_value, start_index):
    """Manually decode a bencoded string."""
    if not chr(bencoded_value[start_index]).isdigit():
        raise ValueError("Invalid encoded string", bencoded_value, start_index)
    
    first_colon_index = bencoded_value.find(b":", start_index)
    if first_colon_index == -1:
        raise ValueError("Invalid bencoded value, missing colon for string.")
    
    length = int(bencoded_value[start_index:first_colon_index])
    word_start = first_colon_index + 1
    word_end = word_start + length
    
    return bencoded_value[word_start:word_end], word_end

def decode_integer(bencoded_value, start_index):
    """Manually decode a bencoded integer."""
    if chr(bencoded_value[start_index]) != "i":
        raise ValueError("Invalid encoded integer", bencoded_value, start_index)
    
    end_marker = bencoded_value.find(b"e", start_index)
    if end_marker == -1:
        raise ValueError("Invalid bencoded integer, missing 'e'.")
    
    return int(bencoded_value[start_index+1:end_marker]), end_marker + 1

def decode_list(bencoded_value, start_index):
    """Manually decode a bencoded list."""
    if chr(bencoded_value[start_index]) != "l":
        raise ValueError("Invalid encoded list", bencoded_value, start_index)
    
    current_index = start_index + 1
    values = []
    
    while chr(bencoded_value[current_index]) != "e":
        value, current_index = decode_part(bencoded_value, current_index)
        values.append(value)
    
    return values, current_index + 1

def decode_dict(bencoded_value, start_index):
    """Manually decode a bencoded dictionary."""
    if chr(bencoded_value[start_index]) != "d":
        raise ValueError("Invalid encoded dictionary", bencoded_value, start_index)
    
    current_index = start_index + 1
    values = {}
    
    while chr(bencoded_value[current_index]) != "e":
        key, current_index = decode_string(bencoded_value, current_index)
        value, current_index = decode_part(bencoded_value, current_index)
        values[key.decode()] = value
    
    return values, current_index

def decode_part(bencoded_value, start_index):
    """Dispatches decoding based on the first character."""
    if chr(bencoded_value[start_index]).isdigit():
        return decode_string(bencoded_value, start_index)
    elif chr(bencoded_value[start_index]) == "i":
        return decode_integer(bencoded_value, start_index)
    elif chr(bencoded_value[start_index]) == "l":
        return decode_list(bencoded_value, start_index)
    elif chr(bencoded_value[start_index]) == "d":
        return decode_dict(bencoded_value, start_index)
    else:
        raise ValueError(f"Unknown type at position {start_index}: {bencoded_value[start_index]}")

# Bencodepy decoder wrapper with manual fallbacks
def decode_bencode(bencoded_value):
    try:
        return bencodepy.decode(bencoded_value)
    except bencodepy.exceptions.BencodeDecodeError:
        # Fallback to manual decoding in case bencodepy fails
        return decode_part(bencoded_value, 0)[0]

# Command handler
def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode(errors='replace')  # Graceful handling of decode errors
            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))

    elif command == "info":
        file_name = sys.argv[2]
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()
        
        torrent = decode_bencode(bencoded_content)
        print("Tracker URL:", torrent["announce"].decode('utf-8'))
        print("Length:", torrent["info"]["length"])

    else:
        raise NotImplementedError(f"Unknown command {command}")

# Run the main function if the script is executed
if __name__ == "__main__":
    main()
