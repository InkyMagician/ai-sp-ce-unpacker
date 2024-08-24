# AI Space Archive Extractor

A Python-based tool for extracting files from AI Space game archives (.hed files).

## Features

- Extracts files from AI Space .hed archives and associated .dat files
- User-friendly GUI for easy file and output directory selection
- Supports multiple encryption keys for different archive types
- Handles complex file structures and nested directories
- Provides detailed console output for debugging

## Requirements

- Python 3.x.x+
- tkinter (usually comes pre-installed with Python)

## Usage

1. Run the script:
2. Select the .hed file you want to extract when prompted
3. Choose the output directory for extracted files
4. Wait for the extraction to complete

## How it works

The script decrypts the header of the .hed file, reads the file structure, and then extracts and decrypts individual files from the associated .dat files. It handles various encryption keys and file structures used in different AI Space archives.
