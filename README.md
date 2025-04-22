# LoaF — Linear Object Archive Format 🍞

LoaF (`.loaf`) is a minimalist, self-validating, stream-friendly archive format. It wraps a compressed tar archive in a newline-free hex encoding, topped with a SHA256 hash for verification. LoaF is designed to be simple, lightweight, and easy to use in shell pipelines.

LoaF is ideal for:

- 🧵 Sending archives over pipes
- 🧾 Copying binary payloads over email, chat, or plaintext logs
- 🛠 Simple, shell-compatible workflows
- 🔐 Tamper-evident artifact delivery
- 📦 Packaging and distributing files
- 🧩 Easy integration with existing tools
- 🧩 Composable with other UNIX tools
- 🧩 Compatible with `tar`, `gzip`, `xxd`, and `sha256sum`
- 🔄 Stream-friendly for easy integration with other tools
- 🔄 Supports compression and checksum verification
- 🔄 Human-readable format for easy inspection
- 🔄 Lightweight and efficient for quick operations
- 🔄 Easy to use with shell pipelines
- 🔄 Compatible with existing UNIX tools for easy integration
- 🔄 Flexible for various use cases, from packaging to distribution
- 🔄 Designed for simplicity and ease of use
- 🔄 Supports both file and directory archiving
- 🔄 Provides a clear and concise format for archiving
- 🔄 Allows for easy inspection and verification of archives
- 🔄 Ensures compatibility with various UNIX tools
- 🔄 Provides a simple command-line interface for easy use

## 🛠 Usage Examples

### Create a LoaF Archive

```bash
# Create a LoaF archive from an input directory or file, and save it to a new .loaf file:
./loaf.sh c path/to/input/file/or/directory path/to/output/file.loaf

# Create a LoaF archive from an input directory or file, and output the .loaf to stdout:
./loaf.sh c path/to/input/file/or/directory

# Create a LoaF archive from arbitrary stdin contents, and output the .loaf to stdout. By default, the file inside the archive will be named `-`:
cat path/to/input/file | ./loaf.sh c

# Create a LoaF archive from arbitrary stdin contents, and save it to a new .loaf file. By default, the file inside the archive will be named `-`:
cat path/to/input/file | ./loaf.sh c - path/to/output/file.loaf

# Create a LoaF archive from arbitrary stdin contents, providing a custom filename for the file inside the archive (`custom_filename.txt` in this example), and save it to a new .loaf file:
cat path/to/input/file | ./loaf.sh c -custom_filename.txt path/to/output/file.loaf

# Create a LoaF archive from arbitrary stdin contents, providing a custom filename for the file inside the archive, and output the .loaf to stdout:
cat path/to/input/file | ./loaf.sh c -custom_filename.txt

# Verbose output of the LoaF archive creation process:
./loaf.sh -v c path/to/input/file/or/directory path/to/output/file.loaf
```

## 📄 Format

Each `.loaf` file is structured as:

```
SHA256(-)=<64-character hash> <hex-encoded gzip’d tarball>
```

- Guaranteed **one-line** (newline-free) if valid
- `exit 0` from `loaf.sh make` when loaf is clean
- Fully compatible with standard UNIX tools (`tar`, `gzip`, `xxd`, `sha256sum`)

## 💡 Philosophy

LoaF is designed to be:

- Deterministic and verifiable
- Composable in shell pipelines
- Lightweight
- Human-readable and fun to use

## 📜 License

MIT — see [LICENSE](./LICENSE) for the full terms of the license.
