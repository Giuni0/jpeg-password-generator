import hashlib
import sys
from typing import Optional

def hash256(data: bytes) -> str:
    """Generate SHA-256 hash of input data."""
    return hashlib.sha256(data).hexdigest()

def xor_hex_string(hex_string: str) -> str:
    """Perform XOR operation on two halves of a hex string."""
    length = len(hex_string) // 2
    first_half = int(hex_string[:length], 16)
    second_half = int(hex_string[length:], 16)
    return hex(first_half ^ second_half)[2:].zfill(length)

def collect_jpeg_data(file_path: str) -> Optional[bytes]:
    """Extract compressed image data from a JPEG file."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        sos_marker = b'\xFF\xDA'
        sos_position = data.find(sos_marker)

        if sos_position == -1:
            print("Error: Start of Scan (SOS) marker not found")
            return None

        length = (data[sos_position + 2] << 8) | data[sos_position + 3]
        data_start = sos_position + 2 + length
        image_data = data[data_start:]

        eoi_marker = b'\xFF\xD9'
        eoi_position = image_data.find(eoi_marker)

        if eoi_position != -1:
            image_data = image_data[:eoi_position + 2]  # Include the EOI marker
        else:
            print("Warning: End of Image (EOI) marker not found")

        return image_data
    except IOError as e:
        print(f"Error reading file: {e}")
        return None

def generate_password(jpeg_data: bytes, website: str) -> str:
    """Generate a password using JPEG data and website name."""
    combined_data = jpeg_data + website.encode('utf-8')
    hashed = hash256(combined_data)
    return xor_hex_string(xor_hex_string(hashed))

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_jpeg_file>")
        sys.exit(1)

    jpg_file_path = sys.argv[1]
    collected_data = collect_jpeg_data(jpg_file_path)

    if collected_data is None:
        print("Failed to collect image data. Exiting.")
        sys.exit(1)

    print("JPEG Password Generator")
    print("Enter 'quit' to exit")

    while True:
        website = input("Website: ").strip()
        if website.lower() == 'quit':
            break
        password = generate_password(collected_data, website)
        print(f"Generated password: {password}")

if __name__ == "__main__":
    main()
