import sys
import bencodepy

# Manual decoding functions for backup in case bencodepy fails
def decode_string(bencoded_value, start_index):
    first_colon_index = bencoded_value.find(b":", start_index)
    if first_colon_index == -1:
        raise ValueError("Invalid bencoded value, missing colon for string.")
    
    length = int(bencoded_value[start_index:first_colon_index])
    word_start = first_colon_index + 1
    word_end = word_start + length
    
    return bencoded_value[word_start:word_end], word_end

def decode_integer(bencoded_value, start_index):
    end_marker = bencoded_value.find(b"e", start_index)
    if end_marker == -1:
        raise ValueError("Invalid bencoded integer, missing 'e'.")
    
    return int(bencoded_value[start_index + 1:end_marker]), end_marker + 1

def decode_list(bencoded_value, start_index):
    current_index = start_index + 1
    values = []
    
    while chr(bencoded_value[current_index]) != "e":
        value, current_index = decode_part(bencoded_value, current_index)
        values.append(value)
    
    return values, current_index + 1

def decode_dict(bencoded_value, start_index):
    current_index = start_index + 1
    values = {}
    
    while chr(bencoded_value[current_index]) != "e":
        key, current_index = decode_string(bencoded_value, current_index)
        value, current_index = decode_part(bencoded_value, current_index)
        values[key.decode()] = value
    
    return values, current_index

def decode_part(bencoded_value, start_index):
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

# Wrapper to decode bencode data using bencodepy or manual fallback
def decode_bencode(bencoded_value):
    try:
        # Try using bencodepy first
        return bencodepy.decode(bencoded_value)
    except bencodepy.exceptions.BencodeDecodeError:
        # Fallback to manual decoding
        return decode_part(bencoded_value, 0)[0]

# Main function to handle commands
def main():
    command = sys.argv[1]
    
    if command == "info":
        file_name = sys.argv[2]
        
        # Read the .torrent file
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()
        
        # Decode the bencoded content
        torrent_data = decode_bencode(bencoded_content)
        
        # Extract and print the "announce" key (tracker URL)
        
        print("Tracker URL:", torrent_data["announce"].decode('utf-8'))
        
        
        # Extract and print the "length" field from the "info" dictionary
        if "info" in torrent_data and "length" in torrent_data["info"]:
            print("Length:", torrent_data["info"]["length"])
        else:
            print("No 'info' key or 'length' field found in the torrent file.")
    
    else:
        raise NotImplementedError(f"Unknown command {command}")

# Run the main function if the script is executed
if __name__ == "__main__":
    main()
