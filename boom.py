import struct
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import BinaryIO
from io import BytesIO

def rot_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes((b - key[i % len(key)]) & 0xFF for i, b in enumerate(data))

def read_unicode_string(file: BinaryIO, length: int) -> str:
    return file.read(length * 2).decode('utf-16-le', errors='replace')

def safe_unpack(format: str, buffer: bytes, default=None):
    try:
        return struct.unpack(format, buffer)[0]
    except struct.error:
        print(f"Warning: Failed to unpack {format}. Buffer size: {len(buffer)}")
        return default

def extract_aispace_archive(archive_path: str, output_dir: str = None, debug: bool = False):
    try:
        with open(archive_path, 'rb') as f:
            file_content = f.read()
            f = BytesIO(file_content)
            
        print(f"File size: {len(file_content)} bytes")

        # Check signature
        if f.read(4) != b'FPMF':
            print("Invalid file format. This script is for FPMF archives (HED extension).")
            return

        f.seek(4, 1)  # Skip 2 shorts
        data_size = safe_unpack('<I', f.read(4), 0)
        print(f"Data size: {data_size}")
        f.seek(4, 1)  # Skip another long

        offset = f.tell()
        print(f"Current offset: {offset}")
        f.seek(1, 1)  # Skip byte
        zero = safe_unpack('<H', f.read(2), 0)
        print(f"Zero value: 0x{zero:04x}")

        # Determine encryption key
        if zero == 0x16f6:
            key = b"\x0B\xF6\x16\xB7\x6D\x61\x21\x40\x75\x76\x15\x27\x88\xF1\x59\xAB\x88\xE7\xF1\xDA\x0F\x8B\x50\x6A\xB1\xBD\x24\xB0\x73\xC6\x04\xFC\x43\x09\xB3\xCD\xEB\xC7\xB1\x66\x96\x8A\xC0\x13\xC8\xA0\x56\xD0\x65\x55\x4F\x0A\xB2\x69\x9C\x97\x31\x06\x12\x8A\x0F\xBF\x0F\x40"
        elif zero == 0x84d4:
            key = b"\x5f\xd4\x84\xe0\xc1\x5c\x0c\x3d\xed\x9b\xf6\x08\x79\x36\x01\x3d\x34\x40\x78\x3a\xce\xb1\x00\xa8\xe2\x08\x79\xb8\x75\x8b\x10\x18\x0e\xa0\xd9\xd5\x4d\x8f\x60\x58\xd1\xae\x9a\x34\xef\xd6\xa0\xe3\xe6\x15\x04\x7c\xa5\xae\xce\x60\xd4\x4e\xff\x1d\x3c\x56\x3c\xfa"
        elif zero == 0x9495:
            key = b"\x77\x95\x94\xcc\xb1\x18\x42\x19\x0c\xc2\x73\x3a\xca\x0b\x03\x68\x53\xa5\x89\xd3\x1b\x25\x01\x41\x4e\xfb\x83\x3d\xfc\xbf\x65\x3c\xe6\x3b\xce\xac\x30\x38\x1e\xa2\x57\x67\xdc\x02\x62\xc6\x5e\x0f\xbd\x5a\x94\x2d\xf4\xdd\x08\x95\x87\x49\x38\x8c\x86\xcd\xa0\x6a"
        else:
            print(f"Unknown key (0x{zero:04x}), contact the script author.")
            return

        print("Header decryption key:")
        print(key.hex())

        # Decrypt and read header
        f.seek(offset)
        header_data = rot_decrypt(f.read(data_size), key)
        header = BytesIO(header_data)

        print("Decrypted header (first 100 bytes):", header_data[:100].hex())

        header.seek(8)  # Skip two longs
        name_sz = header.read(1)[0]
        if name_sz > 100:  # Sanity check
            print(f"Warning: Unusually large name size: {name_sz}")
            name_sz = min(name_sz, 100)
        base_name = read_unicode_string(header, name_sz)
        print(f"Base name: {base_name}")
        
        header.seek(16, 1)  # Skip four longs
        key_size = safe_unpack('<I', header.read(4), 0)
        print(f"Key size: {key_size}")
        data_key = header.read(key_size)
        
        print("Data file decryption key:")
        print(data_key.hex())
        
        header.seek(8, 1)  # Skip two longs
        files_count = safe_unpack('<I', header.read(4), 0)
        print(f"Files count: {files_count}")

        # Determine the dat file directory based on the input hed file
        hed_dir = os.path.dirname(archive_path)
        hed_name = os.path.splitext(os.path.basename(archive_path))[0]
        dat_dir = os.path.join(hed_dir, hed_name)

        prev_packnum = -1
        data_file = None

        for i in range(files_count):
            print(f"\nProcessing file {i+1}/{files_count}")
            folder_sz = header.read(1)[0]
            folder = read_unicode_string(header, folder_sz)
            name_sz = header.read(1)[0]
            name = read_unicode_string(header, name_sz)
            print(f"File: {folder}/{name}")

            packnum, offset, size, crc, zero = struct.unpack('<IIIII', header.read(20))
            print(f"Pack number: {packnum}, Offset: {offset}, Size: {size}")

            if packnum != prev_packnum:
                if data_file:
                    data_file.close()
                data_file_name = os.path.join(dat_dir, f"{packnum:04d}.dat")
                print(f"Looking for data file: {data_file_name}")
                if not os.path.exists(data_file_name):
                    print(f"Warning: Data file {data_file_name} not found. Skipping...")
                    continue
                data_file = open(data_file_name, 'rb')
                prev_packnum = packnum

            if output_dir:
                full_name = os.path.join(output_dir, folder.strip('.\\'), name)
            else:
                full_name = os.path.join(os.path.dirname(archive_path), folder.strip('.\\'), name)
            
            os.makedirs(os.path.dirname(full_name), exist_ok=True)

            data_file.seek(offset)
            file_data = data_file.read(size)
            if len(file_data) != size:
                print(f"Warning: Expected {size} bytes, but read {len(file_data)} bytes.")
            
            if debug:
                print(f"First 16 bytes of encrypted data: {file_data[:16].hex()}")
            
            decrypted_data = rot_decrypt(file_data, data_key)
            
            if debug:
                print(f"First 16 bytes of decrypted data: {decrypted_data[:16].hex()}")

            with open(full_name, 'wb') as out_file:
                out_file.write(decrypted_data)

            print(f"Extracted: {full_name}")

        if data_file:
            data_file.close()

        print("Extraction completed successfully!")
        return True

    except FileNotFoundError:
        print(f"Error: The file '{archive_path}' was not found.")
    except PermissionError:
        print(f"Error: Permission denied when trying to access '{archive_path}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
    
    return False

def main():
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    # Select input file
    input_file = filedialog.askopenfilename(title="Select HED file", filetypes=[("HED files", "*.hed")])
    if not input_file:
        print("No input file selected. Exiting.")
        return

    # Select output directory
    output_dir = filedialog.askdirectory(title="Select output directory")
    if not output_dir:
        print("No output directory selected. Exiting.")
        return

    # Perform extraction
    success = extract_aispace_archive(input_file, output_dir)

    # Show result message
    if success:
        messagebox.showinfo("Extraction Complete", "Files have been successfully extracted.")
    else:
        messagebox.showerror("Extraction Failed", "An error occurred during extraction. Please check the console for details.")

if __name__ == "__main__":
    main()
