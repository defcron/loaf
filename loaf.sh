#!/bin/bash

# loaf.sh - Reference implementation of LoaF (Linear Object Archive Format) 🍞
# Version: 1.7 (Interactive Stdin Support)
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
# set -o posix # Keep commented out for now, seems okay without it

# --- Global Variables ---
VERBOSE=false
TMPFILE_PATH=""

# --- Cleanup Function ---
cleanup() {
  # Check if TMPFILE_PATH is non-empty and points to an existing file before attempting removal
  if [[ -n "$TMPFILE_PATH" && -f "$TMPFILE_PATH" ]]; then
    # Optional: Add verbose message for cleanup
    # [[ "$VERBOSE" == true ]] && echo "[i] Cleaning up temp file: $TMPFILE_PATH" >&2
    rm -f "$TMPFILE_PATH"
  fi
}
trap cleanup EXIT INT TERM HUP # Trap ensures cleanup happens even on Ctrl+C

# --- Functions ---

loaf_make() {
  local input="$1"
  local output="$2"
  local LOAFCRUMB=""
  local LOAFCRUST=""
  local OUTPUT_LINE=""
  local archive_name=""
  local input_mode="" # 'pipe', 'file', 'interactive'

  # 1. Determine Input Mode
  if [[ -p /dev/stdin || ! -t 0 ]]; then
    # Input is piped or redirected (not a terminal)
    # We only treat it as pipe mode if the input arg suggests stdin
    if [[ -z "$input" || "$input" == "-" || "$input" == -* ]]; then
        input_mode="pipe"
    else
        # Input is piped/redirected, but an input file path was ALSO given.
        # This is ambiguous. Prioritize the explicit file path.
        echo "[!] Warning: Input is piped/redirected, but input path '$input' also specified. Using file path." >&2
        input_mode="file"
    fi
  elif [[ -z "$input" || "$input" == "-" ]]; then
    # No input file specified OR input is '-', AND stdin IS a terminal
    input_mode="interactive"
  elif [[ -n "$input" ]]; then
    # Input is specified and not '-' (must be a file/path)
    input_mode="file"
  else
     # Should not be reachable, but good practice
     echo "[!] Error: Cannot determine input mode." >&2
     exit 1
  fi
  [[ "$VERBOSE" == true ]] && echo "[i] Input mode detected: $input_mode" >&2

  # 2. Process Input based on Mode
  case "$input_mode" in
    pipe)
      [[ "$VERBOSE" == true ]] && echo "[i] Reading input from stdin pipe/redirect" >&2
      if [[ "$input" =~ ^-([^[:space:]].*)$ ]]; then
        archive_name="${BASH_REMATCH[1]}"
        [[ "$VERBOSE" == true ]] && echo "[i] Using archive name from argument: '$archive_name'" >&2
      else
        archive_name="-" # Default archive name is '-'
         [[ "$VERBOSE" == true ]] && echo "[i] Using default archive name: '$archive_name'" >&2
      fi
      TMPFILE_PATH=$(mktemp /tmp/loaf-stdin-pipe.XXXXXX)
      ( set +o noclobber; cat > "$TMPFILE_PATH" ) # Read all piped data

      if [[ "$VERBOSE" == false ]]; then
        LOAFCRUMB=$( { tar --numeric-owner --transform="s|^$(basename "$TMPFILE_PATH")|$archive_name|" -cvpf - -C "$(dirname "$TMPFILE_PATH")" "$(basename "$TMPFILE_PATH")" | gzip -9 | xxd -p -c0; } 2>/dev/null )
      else
        echo "[i] Archiving '$TMPFILE_PATH' as '$archive_name'..." >&2
        LOAFCRUMB=$(tar --numeric-owner --transform="s|^$(basename "$TMPFILE_PATH")|$archive_name|" -cvpf - -C "$(dirname "$TMPFILE_PATH")" "$(basename "$TMPFILE_PATH")" | gzip -9 | xxd -p -c0)
      fi
      ;; # End pipe case

    interactive)
      [[ "$VERBOSE" == true ]] && echo "[i] Reading input interactively from terminal (End with Ctrl+D)" >&2
      # For interactive mode, the first arg ('-' or missing) doesn't specify archive name
      archive_name="-" # Default archive name is '-'
      [[ "$VERBOSE" == true ]] && echo "[i] Using default archive name: '$archive_name'" >&2

      TMPFILE_PATH=$(mktemp /tmp/loaf-stdin-interactive.XXXXXX)

      # Use 'cat' to read from terminal until EOF (Ctrl+D)
      # Redirect output to temp file, disabling noclobber
      # If user presses Ctrl+C, 'cat' will terminate, and 'set -e' will cause script exit.
      # The trap will handle cleanup.
      ( set +o noclobber; cat > "$TMPFILE_PATH" )

      # If we reach here, Ctrl+D was pressed and cat finished successfully
      [[ "$VERBOSE" == true ]] && echo "[i] Finished reading interactive input." >&2

      # Check if temp file is empty (user might just press Ctrl+D immediately)
      if [[ ! -s "$TMPFILE_PATH" ]]; then
          echo "[!] Warning: No input received from interactive session. Loaf will be empty." >&2
          # Allow creating an empty loaf, or exit if preferred:
          # exit 1
      fi

      if [[ "$VERBOSE" == false ]]; then
        LOAFCRUMB=$( { tar --numeric-owner --transform="s|^$(basename "$TMPFILE_PATH")|$archive_name|" -cvpf - -C "$(dirname "$TMPFILE_PATH")" "$(basename "$TMPFILE_PATH")" | gzip -9 | xxd -p -c0; } 2>/dev/null )
      else
        echo "[i] Archiving '$TMPFILE_PATH' as '$archive_name'..." >&2
        LOAFCRUMB=$(tar --numeric-owner --transform="s|^$(basename "$TMPFILE_PATH")|$archive_name|" -cvpf - -C "$(dirname "$TMPFILE_PATH")" "$(basename "$TMPFILE_PATH")" | gzip -9 | xxd -p -c0)
      fi
      ;; # End interactive case

    file)
      # Handle literal file named '-'
      if [[ "$input" == "-" ]]; then
          if [[ -e "-" ]]; then
              [[ "$VERBOSE" == true ]] && echo "[i] Processing literal file named '-'" >&2
              input="./-" # Use relative path for clarity
          else
              # This case should ideally not be reached if mode detection is correct
              echo "[!] Error: Input is '-', stdin is a terminal, and file '-' not found." >&2
              exit 1
          fi
      fi

      # Handle regular file/directory path
      if [[ ! -e "$input" ]]; then
          echo "[!] Error: Input path '$input' does not exist." >&2
          exit 1
      fi
      [[ "$VERBOSE" == true ]] && echo "[i] Processing input path: $input" >&2
      if [[ "$VERBOSE" == false ]]; then
          LOAFCRUMB=$( { tar --numeric-owner -cvpf - "$input" | gzip -9 | xxd -p -c0; } 2>/dev/null )
      else
          LOAFCRUMB=$(tar --numeric-owner -cvpf - "$input" | gzip -9 | xxd -p -c0)
      fi
      ;; # End file case
  esac

  # 3. Generate Header and Output
  if [[ -z "$LOAFCRUMB" ]]; then
      # Handle case where LOAFCRUMB might be empty even if input wasn't (e.g., empty file/dir)
      # Or if user provided no interactive input and we didn't exit earlier
      echo "[!] Warning: Generated LOAFCRUMB is empty. Resulting loaf will represent empty content." >&2
      # Decide if this should be an error or allowed:
      # exit 1 # Uncomment to make empty loaf an error
  fi

  # Generate LOAFCRUST (Checksum Header)
  if [[ "$VERBOSE" == false ]]; then
      # Group commands, redirect stderr, and explicitly remove null bytes
      LOAFCRUST=$( { printf "%s" "$LOAFCRUMB" | sha256sum -z --tag | awk '{print $1 $2 $3 $4}' | tr -d '\0'; } 2>/dev/null )
  else
      echo "[i] Generating checksum..." >&2
      LOAFCRUST=$(printf "%s" "$LOAFCRUMB" | sha256sum -z --tag | awk '{print $1 $2 $3 $4}' | tr -d '\0')
  fi

  OUTPUT_LINE="${LOAFCRUST} ${LOAFCRUMB}"

  # Output Handling
  if [[ -z "$output" || "$output" == "-" ]]; then
    [[ "$VERBOSE" == true ]] && echo "[i] Writing loaf to stdout" >&2
    printf "%s" "$OUTPUT_LINE"
  else
    [[ "$VERBOSE" == true ]] && echo "[i] Baking loaf to $output ..." >&2
    ( set +o noclobber; printf "%s" "$OUTPUT_LINE" > "$output" )

    # File Validation
    [[ "$VERBOSE" == true ]] && echo "[i] Verifying output file '$output'..." >&2
    if [[ ! -f "$output" ]]; then
      (echo && echo "[✗] Error: Output file '$output' was not created (check permissions). ❌") >&2
      exit 1
    fi
    # Allow empty output file if OUTPUT_LINE was empty (empty input case)
    if [[ ! -s "$output" && -n "$OUTPUT_LINE" ]]; then
      (echo && echo "[✗] Error: Output file '$output' is empty. ❌") >&2
      exit 1
    fi

    local line_count
    line_count=$(wc -l < "$output")
    # Allow 0 lines for valid loaf, or potentially 0 if OUTPUT_LINE was empty
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
  # Check if HEX is empty after tail
  if [[ -z "$HEX" ]]; then
      echo "[!] Error: Failed to extract hex data from '$input'. File might be corrupt after header." >&2
      exit 1
  fi

  # Compare Hashes
  local EMBED_HASH="${header#*=}"
  local CALC_HASH
  if [[ "$VERBOSE" == false ]]; then
      # Group commands, redirect stderr, and explicitly remove null bytes
      CALC_HASH=$( { printf "%s" "$HEX" | sha256sum -z --tag | awk '{print $4}' | tr -d '\0'; } 2>/dev/null )
  else
      echo "[i] Calculating checksum for verification..." >&2
      CALC_HASH=$(printf "%s" "$HEX" | sha256sum -z --tag | awk '{print $4}')
  fi

  # Output verification status to stderr and exit with appropriate code
  if [[ "$EMBED_HASH" == "$CALC_HASH" ]]; then
    echo "[✓] Loaf verified OK ✅" >&2 # Status message to stderr
    exit 0 # Success exit code
  else
    echo "[✗] Hash mismatch ❌" >&2 # Status message to stderr
    echo "  Expected checksum : $EMBED_HASH" >&2
    echo "  Calculated checksum: $CALC_HASH" >&2
    echo "  The loaf may be corrupted or tampered with." >&2
    exit 1 # Failure exit code
  fi
}

# Extracts the contents of a loaf file
loaf_extract() {
  local input="$1"
  # Make output_dir optional, default to current directory '.'
  local output_dir="${2:-.}" # Use parameter expansion default

  # Input validation
  if [[ -z "$input" ]]; then echo "[!] Error: No input loaf file specified." >&2; exit 1; fi
  if [[ ! -f "$input" || ! -r "$input" ]]; then echo "[!] Error: Input file '$input' not found or not readable." >&2; exit 1; fi

  # Ensure output directory exists (even if it's '.')
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
  # Add check if HEX is empty after tail
  if [[ -z "$HEX" ]]; then
      echo "[!] Error: Failed to extract hex data from '$input'. File might be corrupt after header." >&2
      exit 1
  fi

  # Decode, Decompress, Extract
  [[ "$VERBOSE" == true ]] && echo "[i] Decoding, decompressing, and extracting to '$output_dir'..." >&2
  local pipeline_exit_status=0
  if [[ "$VERBOSE" == false ]]; then
      # Group commands and redirect stderr for the whole group
      { echo "$HEX" | xxd -r -p | gunzip | tar -xvpf - -C "$output_dir"; } 2>/dev/null || pipeline_exit_status=$?
  else
      echo "$HEX" | xxd -r -p | gunzip | tar -xvpf - -C "$output_dir" || pipeline_exit_status=$?
  fi

  # Check pipeline exit status
  if [[ "$pipeline_exit_status" -ne 0 ]]; then
      echo "[✗] Error during extraction pipeline (exit status: $pipeline_exit_status). Check archive integrity or permissions." >&2
      exit $pipeline_exit_status
  fi

  echo "[✓] Loaf extracted successfully to '$output_dir'" >&2
  exit 0
}

print_usage() {
  # Using cat with heredoc for cleaner multiline echo
  cat << EOF
Usage:
  $0 [-v] c|create|make|new [<input>] [<output>] - Make a new LoaF archive
  $0 [-v] verify <input.loaf> - Verify a LoaF archive
  $0 [-v] x|extract <input.loaf> [<target_dir>] - Extract contents of a LoaF archive

Make Options:
  <input>: File/folder path, or '-' for stdin, or '-name.txt' for named stdin.
           If omitted and stdin is piped, reads stdin (named '-').
           If omitted and stdin is terminal, reads interactively (End with Ctrl+D).
  <output>: Output file path. If omitted or '-', writes to stdout.

Extract Options:
  <target_dir>: Optional directory to extract into. Defaults to current directory ('.').

Examples:
  cat file.txt | $0 make - out.loaf   # Stdin (root name) -> out.loaf
  cat file.txt | $0 make -data.bin    # Stdin (named data.bin) -> stdout
  $0 make my_folder my_folder.loaf    # Folder -> my_folder.loaf
  $0 make                             # Read interactively -> stdout
  $0 make - my_interactive.loaf       # Read interactively -> my_interactive.loaf
  $0 verify my_folder.loaf
  $0 extract my_folder.loaf            # Extract to current directory
  $0 extract my_folder.loaf ./extracted # Extract to ./extracted directory
EOF
}

# --- Option Parsing ---
OPTIND=1 # Reset OPTIND for safety
while getopts ":v" opt; do
  case $opt in
    v) VERBOSE=true ;;
    \?) print_usage; exit 1 ;; # Invalid option, print usage and exit
  esac
done
shift $((OPTIND-1)) # Remove processed options

# --- Main Command Dispatch ---
COMMAND="${1:-}" # Default to empty string if $1 is not set

# Dispatch based on command
if [[ "$COMMAND" == "make" || "$COMMAND" == "c" || "$COMMAND" == "create" || "$COMMAND" == "new" || "$COMMAND" == "loaf" || "$COMMAND" == "bake" || "$COMMAND" == "knead" || "$COMMAND" == "prepare" || "$COMMAND" == "cook" || "$COMMAND" == "spawn" || "$COMMAND" == "generate" || "$COMMAND" == "mix" || "$COMMAND" == "do" || "$COMMAND" == "cause" || "$COMMAND" == "be" || "$COMMAND" == "conjure" || "$COMMAND" == "press" || "$COMMAND" == "burn" || "$COMMAND" == "stir" || "$COMMAND" == "whip" || "$COMMAND" == "fold" || "$COMMAND" == "build" || "$COMMAND" == "embue" || "$COMMAND" == "form" || "$COMMAND" == "shape" || "$COMMAND" == "roll" ]]; then
  loaf_make "${2:-}" "${3:-}" # Pass potentially empty args safely
elif [[ "$COMMAND" == "verify" ]]; then
  if [[ "$#" -ne 2 ]]; then echo "[!] Error: 'verify' requires <input.loaf>" >&2; print_usage; exit 1; fi
  loaf_verify "$2" # verify handles its own exit
elif [[ "$COMMAND" == "x" || "$COMMAND" == "extract" ]]; then
  # Now requires 2 or 3 arguments: $0 extract <input> [target_dir]
  if [[ "$#" -lt 2 || "$#" -gt 3 ]]; then
      echo "[!] Error: 'extract' requires <input.loaf> and optionally <target_dir>" >&2
      print_usage
      exit 1
  fi
  # Pass input ($2) and optional target_dir ($3) using default expansion
  loaf_extract "$2" "${3:-}" # extract handles its own exit
elif [[ -z "$COMMAND" ]]; then
  # Check for piped stdin OR interactive terminal
  if [[ -p /dev/stdin || ! -t 0 ]]; then
    # Special case: No command given, but stdin is piped. Assume 'make -'.
    [[ "$VERBOSE" == true ]] && echo "[i] No command provided, but stdin is piped. Assuming 'make -'." >&2
    loaf_make "-" "" # input='-', output=''
  elif [[ -t 0 ]]; then
    # Special case: No command given, stdin is terminal. Assume interactive 'make'.
    [[ "$VERBOSE" == true ]] && echo "[i] No command provided, stdin is terminal. Assuming interactive 'make'." >&2
    loaf_make "" "" # input='', output='' -> triggers interactive mode
  else
    # Should not happen (stdin is neither pipe/redirect nor terminal?)
    print_usage
    exit 1
  fi
else
  # Handle unknown command
  if [[ -n "$COMMAND" ]]; then
      echo "[!] Error: Unknown command '$COMMAND'" >&2
  fi
  print_usage
  exit 1
fi

# If we reach here, it implies success for cases like 'make' writing to stdout
exit 0
