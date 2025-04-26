# LoaF — Linear Object Archive Format 🍞

LoaF (`.loaf`) is a delightfully simple, single-line, self-validating archive format perfect for the command line. Think of it as taking your files or directories, rolling them up in a standard `tar.gz` bundle, hex-encoding the whole thing so it travels nicely through text-only systems, and sticking a checksum label on top so you know it hasn't been nibbled on arrival.

It's designed to be stream-friendly, easily verifiable, and play nicely with all your favorite shell tools.

LoaF is baked fresh for:

- **Stream Team:** Sending archives smoothly through shell pipelines (`|`).
- **Plaintext Pal:** Copying binary data safely via email, chat, logs, or anywhere newlines fear to tread.
- **Shell Shenanigans:** Enabling simple, powerful, composable workflows using standard UNIX tools (`tar`, `gzip`, `xxd`, `sha256sum`).
- **Trusty Transfers:** Delivering artifacts where you can easily verify they haven't been tampered with (thanks, SHA256!).
- **Simple Storage:** Packaging files or directories into a single, verifiable blob.
- **Easy Integration:** Plays well with scripts and existing command-line utilities.
- **Quick Checks:** Human-readable enough (well, the header is!) for basic inspection.

## 🛠 Usage Examples

Let's get baking! (`loaf.sh` is assumed to be executable in the current path, e.g., `./loaf.sh`)

### Creating a LoaF (`make`, `c`)

```bash
# Archive a file/directory into a .loaf file
./loaf.sh c path/to/input my_archive.loaf

# Archive a file/directory and print the .loaf content to stdout
./loaf.sh c path/to/input

# Pipe data into a .loaf file (archive contains 'some_data' contents in a file named '-' by default)
cat some_data | ./loaf.sh c - my_data.loaf

# Pipe data and print the .loaf content to stdout (archive contains 'some_data' contents in a file named '-' by default)
cat some_data | ./loaf.sh c

# Pipe data, name the file inside the archive `image.png`, save the .loaf archive to a file named image.png.loaf
cat image.png | ./loaf.sh c -image.png image.png.loaf

# Pipe data, give the archived file a name, print the .loaf to stdout
cat image.png | ./loaf.sh c -image.png

# Create a .loaf interactively and save it to file named 'interactive.loaf' (type the contents you want to archive in the .loaf file, then press Enter, then press Ctrl+D to finish and save)
./loaf.sh make - interactive.loaf

# Use -v for verbose output during any operation
./loaf.sh -v c path/to/input my_archive.loaf
```

## Verifying a LoaF (`verify`)

```bash
# Check if the loaf is fresh and untampered
./loaf.sh verify my_archive.loaf
# (Outputs status to stderr and exits 0 if OK, 1 if mismatch/error)
```

### Extracting a LoaF (`extract`, `x`)

```bash
# Extract contents into the current directory (.)
./loaf.sh x my_archive.loaf

# Extract contents into a specific directory (which will be created if it doesn't exist)
./loaf.sh x my_archive.loaf ./output_directory

# Extract to stdout - RAW concatenated content of all files
# (Useful for single-file archives or specific streaming tasks)
./loaf.sh x my_archive.loaf -

# Extract to stdout - DELIMITED content (Default: '␜' symbol)
# Inserts the delimiter *between* the content of each extracted file.
./loaf.sh x my_archive.loaf --

# Extract to stdout - DELIMITED content with a custom delimiter (e.g., newline)
# Use --$'...' for special characters like null bytes (\0) or newlines (\n), or
# simply do similar as --"$DELIMETER" for any other string delimiter.
./loaf.sh x my_archive.loaf --$'\n'
# or
./loaf.sh x my_archive.loaf --"$DELIMITER"

# Extract using a command's output as a (potentially chaotic!) delimiter
# (The command runs *first*, its output becomes the delimiter string)
./loaf.sh x my_archive.loaf --"$(date)"
```

## 📄 Format Explained

A valid LoaF file is always one single line structured like this:

```plaintext
SHA256(-)=<64-hex-hash> <hex-encoded-gzipped-tar-data>
```

1. SHA256(-)=<hash>: The verification header. The hash is calculated from the <hex-encoded-gzipped-tar-data> part only.
2. (Space): A single space separates the header from the data.
3. <hex-encoded-gzipped-tar-data>: The actual archive content. This is created by:
   - Taking the input file/directory.
   - Archiving it using tar.
   - Compressing the tarball using gzip.
   - Hex-encoding the compressed bytes using xxd -p -c0.

Extraction reverses this process: hex-decode -> gunzip -> untar.

## 💡 Philosophy

LoaF aims to be:

- Simple: Easy to understand, implement, and use with standard tools.
- Verifiable: Built-in checksum ensures data integrity.
- Composable: Designed for easy use in shell pipelines.
- Streamable: The single-line format is ideal for text-based streams.
- Robust: Avoids issues with newlines or binary data in text channels.
- (A Little) Fun: Because why not? 🍞

## 🛠️ Dependencies

Nothing fancy! Just standard UNIX tools:

- `tar`
- `gzip`
- `xxd`
- `sha256sum`
- `awk`
- ... etc.

## 📜 License

MIT — see LICENSE for the full terms.
