#!/bin/bash

# loaf.sh - Reference implementation of LoaF (Linear Object Archive Format) 🍞
# 
# Created with loaf by Jeremy Carter, Tim and Tuesday (ChatGPT GPT-4o-based 
# Custom GPTs), and Gemini Code Assist (Google Gemini 2.0 Flash in VSCode 
# IDE Google Cloud Code Extension's Gemini Code Assist Chat).
#
# This script is a reference implementation of the LoaF format, which
# is a simple, linear archive format designed for easy creation and
# verification of archives. It supports compression and checksum
# verification, and is intended to be used in a variety of contexts,
# including command-line usage and integration with other tools.
#
# The script is designed to be portable and should work on most Unix-like
# systems. It uses standard tools like tar, gzip, xxd, and sha256sum to
# create and verify archives. The script is also designed to be easy to
# read and understand, with clear error messages and usage instructions.
#
# The script is released under the MIT License, which allows for
# modification and redistribution. The author is not responsible for
# any damages or issues that arise from the use of this script. Use at
# your own risk. See the LICENSE file for the full terms of the license.

# --- Strict Mode & Options ---
set -e # Exit immediately if a command exits with a non-zero status.
set -u # Treat unset variables as an error when substituting. Alias for -o nounset
set -o pipefail # Return value of a pipeline is the status of the last command to exit with non-zero status, or zero if no command exited with non-zero status.
set -o noclobber # Prevent output redirection (>) from overwriting existing files.
set -o posix # Enable POSIX mode for better compatibility with POSIX shell standards.
set -o errexit # Exit immediately if a command exits with a non-zero status.
set -o errtrace # Allow traps on functions in a pipeline to be inherited by the shell.
set -o functrace # Allow traps on functions to be inherited by the shell.

# --- Global Variables ---
VERBOSE=false
TMPFILE_PATH=""

# --- Cleanup Function ---
cleanup() {
  # Check if TMPFILE_PATH is non-empty and points to an existing file before attempting removal
  if [[ -n "$TMPFILE_PATH" && -f "$TMPFILE_PATH" ]]; then
    rm -f "$TMPFILE_PATH"
  fi
}
trap cleanup EXIT INT TERM HUP

# --- Functions ---

loaf_make() {
  local input="$1"
  local output="$2"
  local LOAFCRUMB=""
  local LOAFCRUST=""
  local OUTPUT_LINE=""
  local archive_name=""

  # Determine input source
  if [[ -p /dev/stdin || ! -t 0 ]] && { [[ -z "$input" ]] || [[ "$input" == "-" ]] || [[ "$input" == -* ]]; }; then
      [[ "$VERBOSE" == true ]] && echo "[i] Reading input from stdin pipe/redirect" >&2
      if [[ "$input" =~ ^-([^[:space:]].*)$ ]]; then
        archive_name="${BASH_REMATCH[1]}"
        [[ "$VERBOSE" == true ]] && echo "[i] Using archive name from argument: '$archive_name'" >&2
      else
        archive_name="-"
         [[ "$VERBOSE" == true ]] && echo "[i] Using default archive name: '$archive_name'" >&2
      fi
      # Assign temp file path to global var for trap
      TMPFILE_PATH=$(mktemp /tmp/loaf-stdin.XXXXXX)
      # Redirect stdin, temporarily disabling noclobber
      ( set +o noclobber; cat > "$TMPFILE_PATH" )

      # Generate LOAFCRUMB for stdin
      if [[ "$VERBOSE" == false ]]; then
        LOAFCRUMB=$( { tar --numeric-owner  --transform="s|^$(basename "$TMPFILE_PATH")|$archive_name|" -cvpf - -C "$(dirname "$TMPFILE_PATH")" "$(basename "$TMPFILE_PATH")" | gzip -9 | xxd -p -c0; } 2>/dev/null )
      else
        echo "[i] Archiving '$TMPFILE_PATH' as '$archive_name'..." >&2
        LOAFCRUMB=$(tar --numeric-owner  --transform="s|^$(basename "$TMPFILE_PATH")|$archive_name|" -cvpf - -C "$(dirname "$TMPFILE_PATH")" "$(basename "$TMPFILE_PATH")" | gzip -9 | xxd -p -c0)
      fi
      # Temp file cleaned up by trap

  elif [[ "$input" == "-" ]]; then
      if [[ -e "-" ]]; then
          [[ "$VERBOSE" == true ]] && echo "[i] Processing literal file named '-'" >&2
          # Generate LOAFCRUMB for literal '-'
          if [[ "$VERBOSE" == false ]]; then
              LOAFCRUMB=$( { tar --numeric-owner  -cvpf - "./-" | gzip -9 | xxd -p -c0; } 2>/dev/null )
          else
               LOAFCRUMB=$(tar --numeric-owner  -cvpf - "./-" | gzip -9 | xxd -p -c0)
          fi
      else
          echo "[!] Error: Input is '-', stdin is not piped, and file '-' not found." >&2
          echo "[i] Interactive stdin reading not implemented in this version." >&2
          exit 1
      fi
  elif [[ -n "$input" ]]; then
    if [[ ! -e "$input" ]]; then
        echo "[!] Error: Input path '$input' does not exist." >&2
        exit 1
    fi
     [[ "$VERBOSE" == true ]] && echo "[i] Processing input path: $input" >&2
     # Generate LOAFCRUMB for file path
    if [[ "$VERBOSE" == false ]]; then
        LOAFCRUMB=$( { tar --numeric-owner  -cvpf - "$input" | gzip -9 | xxd -p -c0; } 2>/dev/null )
    else
        LOAFCRUMB=$(tar --numeric-owner  -cvpf - "$input" | gzip -9 | xxd -p -c0)
    fi
  else
      echo "[!] Error: No input file provided and stdin is not piped." >&2
      echo "[i] Interactive stdin reading not implemented in this version." >&2
      exit 1
  fi

  if [[ -z "$LOAFCRUMB" ]]; then
      echo "[!] Error: Failed to generate loaf data (LOAFCRUMB is empty)." >&2
      exit 1
  fi

  # Generate LOAFCRUST (Checksum Header)
  if [[ "$VERBOSE" == false ]]; then
      # Group commands, redirect stderr, and explicitly remove null bytes
      LOAFCRUST=$( { printf "%s" "$LOAFCRUMB" | sha256sum -z --tag | awk '{print $1 $2 $3 $4}' | tr -d '\0'; } 2>/dev/null )
  else
      echo "[i] Generating checksum..." >&2
      # No need for tr -d '\0' here as awk should handle it and we want potential errors shown
      LOAFCRUST=$(printf "%s" "$LOAFCRUMB" | sha256sum -z --tag | awk '{print $1 $2 $3 $4}')
  fi

  OUTPUT_LINE="${LOAFCRUST} ${LOAFCRUMB}"

  # Output Handling
  if [[ -z "$output" || "$output" == "-" ]]; then
    [[ "$VERBOSE" == true ]] && echo "[i] Writing loaf to stdout" >&2
    printf "%s" "$OUTPUT_LINE"
  else
    [[ "$VERBOSE" == true ]] && echo "[i] Baking loaf to $output ..." >&2
    # Redirect output, temporarily disabling noclobber
    ( set +o noclobber; printf "%s" "$OUTPUT_LINE" > "$output" )

    # File Validation
    [[ "$VERBOSE" == true ]] && echo "[i] Verifying output file '$output'..." >&2
    if [[ ! -f "$output" ]]; then
      (echo && echo "[✗] Error: Output file '$output' was not created (check permissions). ❌") >&2
      exit 1
    fi
    if [[ ! -s "$output" ]]; then
      (echo && echo "[✗] Error: Output file '$output' is empty. ❌") >&2
      exit 1
    fi

    local line_count
    line_count=$(wc -l < "$output")
    if [[ "$line_count" -ne 0 ]]; then
        (echo && echo "[✗] Error: Output file '$output' has unexpected line count ($line_count). Expected 0 for valid loaf. ❌") >&2
        exit 1
    fi

    # Success
    [[ "$VERBOSE" == true ]] && echo "[✓] Loaf baked successfully to $output" >&2
    [[ "$VERBOSE" == true ]] && ls -al "$output"
    [[ "$VERBOSE" == true ]] && file "$output"
    exit 0
  fi
}

# Verifies the checksum of a loaf file
loaf_verify() {
  local input="$1"
  # Input validation
  if [[ -z "$input" ]]; then echo "[!] Error: No input loaf file specified." >&2; exit 1; fi
  if [[ ! -f "$input" || ! -r "$input" ]]; then echo "[!] Error: Input file '$input' not found or not readable." >&2; exit 1; fi

  # Read header
  read -r header rest < "$input"
  if [[ ! "$header" =~ ^SHA256\(-\)=([0-9a-f]{64})$ ]]; then
      echo "[!] Error: Invalid or missing SHA256 header format in '$input'." >&2
      echo "[i] Expected format: SHA256(-)=<64_hex_chars>" >&2
      exit 1
  fi

  # Extract hex data
  local header_len=${#header}
  local hex_start_pos=$((header_len + 2))
  local file_size
  file_size=$(stat -c%s "$input" 2>/dev/null || stat -f%z "$input") # Linux/BSD stat
  if [[ "$file_size" -lt "$hex_start_pos" ]]; then echo "[!] Error: Input file '$input' is too short." >&2; exit 1; fi
  local HEX
  HEX=$(tail -c +$hex_start_pos "$input")

  # Compare Hashes
  local EMBED_HASH="${header#*=}"
  local CALC_HASH
  if [[ "$VERBOSE" == false ]]; then
      # Group commands, redirect stderr, and explicitly remove null bytes
      CALC_HASH=$( { printf "%s" "$HEX" | sha256sum -z --tag | awk '{print $4}' | tr -d '\0'; } 2>/dev/null )
  else
      echo "[i] Calculating checksum for verification..." >&2
      # No need for tr -d '\0' here as awk should handle it and we want potential errors shown
      CALC_HASH=$(printf "%s" "$HEX" | sha256sum -z --tag | awk '{print $4}')
  fi

  if [[ "$EMBED_HASH" == "$CALC_HASH" ]]; then
    echo "[✓] Loaf verified OK ✅" >&2
    exit 0
  else
    echo "[✗] Hash mismatch ❌" >&2
    echo "  Expected checksum : $EMBED_HASH" >&2
    echo "  Calculated checksum: $CALC_HASH" >&2
    echo "  The loaf may be corrupted or tampered with." >&2
    exit 1
  fi
}

# Extracts the contents of a loaf file
loaf_extract() {
  local input="$1"
  local output_dir="$2"
  # Input validation
  if [[ -z "$input" ]]; then echo "[!] Error: No input loaf file specified." >&2; exit 1; fi
  if [[ ! -f "$input" || ! -r "$input" ]]; then echo "[!] Error: Input file '$input' not found or not readable." >&2; exit 1; fi
  if [[ -z "$output_dir" ]]; then echo "[!] Error: No output directory specified." >&2; exit 1; fi

  # Create output directory
  mkdir -p "$output_dir" || { echo "[!] Error creating output directory '$output_dir'. Check permissions."; exit 1; }

  # Read header
  read -r header rest < "$input"
  if [[ ! "$header" =~ ^SHA256\(-\)=([0-9a-f]{64})$ ]]; then echo "[!] Error: Invalid or missing SHA256 header format in '$input'. Cannot extract." >&2; exit 1; fi

  # Extract hex data
  local header_len=${#header}
  local hex_start_pos=$((header_len + 2))
  local file_size
  file_size=$(stat -c%s "$input" 2>/dev/null || stat -f%z "$input") # Linux/BSD stat
  if [[ "$file_size" -lt "$hex_start_pos" ]]; then echo "[!] Error: Input file '$input' is too short." >&2; exit 1; fi
  local HEX
  HEX=$(tail -c +$hex_start_pos "$input")

  # Decode, Decompress, Extract
  [[ "$VERBOSE" == true ]] && echo "[i] Decoding, decompressing, and extracting to '$output_dir'..." >&2
  if [[ "$VERBOSE" == false ]]; then
      # Group commands and redirect stderr for the whole group
      { echo "$HEX" | xxd -r -p | gunzip | tar -xvpf - -C "$output_dir"; } 2>/dev/null
  else
      echo "$HEX" | xxd -r -p | gunzip | tar -xvpf - -C "$output_dir"
  fi
  # Check tar exit status? Pipefail should handle errors in the pipeline.

  echo "[✓] Loaf extracted successfully to $output_dir" >&2
}

# --- Option Parsing ---
OPTIND=1 # Reset OPTIND for safety
while getopts ":v" opt; do
  case $opt in
    v) VERBOSE=true ;;
    \?) echo "[!] Invalid option: -$OPTARG" >&2; exit 1 ;;
  esac
done
shift $((OPTIND-1)) # Remove processed options

# --- Main Command Dispatch ---
print_usage() {
  # Using cat with heredoc for cleaner multiline echo
  cat << EOF
Usage:
  $0 [-v] c|create|make|new [<input>] [<output>] - Make a new LoaF archive
  $0 [-v] verify <input.loaf> - Verify a LoaF archive
  $0 [-v] x|extract <input.loaf> <target_dir> - Extract contents of a LoaF archive

Make Options:
  <input>: File/folder path, or '-' for stdin, or '-name.txt' for named stdin.
           If omitted and stdin is piped, reads stdin (named '-').
           If omitted and stdin is terminal, shows error (interactive TBD).
  <output>: Output file path. If omitted or '-', writes to stdout.

Examples:
  cat file.txt | $0 make - out.loaf   # Stdin (root name) -> out.loaf
  cat file.txt | $0 make -data.bin    # Stdin (named data.bin) -> stdout
  $0 make my_folder my_folder.loaf    # Folder -> my_folder.loaf
  $0 verify my_folder.loaf
  $0 extract my_folder.loaf ./extracted_files
EOF
}

COMMAND="${1:-}" # Default to empty string if $1 is not set

# Dispatch based on command
if [[ "$COMMAND" == "make" || "$COMMAND" == "c" || "$COMMAND" == "create" || "$COMMAND" == "new" || "$COMMAND" == "loaf" || "$COMMAND" == "bake" || "$COMMAND" == "knead" || "$COMMAND" == "prepare" || "$COMMAND" == "cook" || "$COMMAND" == "spawn" || "$COMMAND" == "generate" || "$COMMAND" == "mix" || "$COMMAND" == "do" || "$COMMAND" == "cause" || "$COMMAND" == "be" || "$COMMAND" == "conjure" || "$COMMAND" == "press" || "$COMMAND" == "burn" || "$COMMAND" == "stir" || "$COMMAND" == "whip" || "$COMMAND" == "fold" || "$COMMAND" == "build" || "$COMMAND" == "embue" || "$COMMAND" == "form" || "$COMMAND" == "shape" || "$COMMAND" == "roll" || "$COMMAND" == "shape" ]]; then
  loaf_make "${2:-}" "${3:-}" # Pass potentially empty args safely
elif [[ "$COMMAND" == "verify" ]]; then
  if [[ "$#" -ne 2 ]]; then echo "[!] Error: 'verify' requires <input.loaf>" >&2; print_usage; exit 1; fi
  loaf_verify "$2"
elif [[ "$COMMAND" == "x" || "$COMMAND" == "extract" ]]; then
  if [[ "$#" -ne 3 ]]; then echo "[!] Error: 'extract' requires <input.loaf> <target_dir>" >&2; print_usage; exit 1; fi
  loaf_extract "$2" "$3"
elif [[ -z "$COMMAND" ]]; then
  if [ -p /dev/stdin ] || [ -s /dev/stdin ]; then
    # Special case: No command given, but stdin is piped. Assume 'make -'.
    [[ "$VERBOSE" == true ]] && echo "[i] No command provided, but stdin is piped. Assuming 'make -'." >&2
    loaf_make "-" "" # input='-', output=''
  else
    print_usage
    exit 1
  fi
else
  # Handle unknown command or no command/no pipe
  if [[ -n "$COMMAND" ]]; then
      echo "[!] Error: Unknown command '$COMMAND'" >&2
  fi
  print_usage
  exit 1
fi

# If functions handle their own exit, this is for successful stdout cases
exit 0
