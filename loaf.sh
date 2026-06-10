#!/bin/bash

# loaf.sh - Reference implementation of LoaF (Linear Object Archive Format) 🍞
#
# Created with loaf by Jeremy Carter, Tim and Tuesday (ChatGPT GPT-4o-based
# Custom GPTs), GitHub Copilot, and Gemini Code Assist (Google Gemini 2.0 
# Flash in VSCode IDE Google Cloud Code Extension's Gemini Code Assist Chat).
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

# --- Shell Options ---
set -o pipefail
#set -o posix

# --- Global Variables ---
VERBOSE=false
TMPDIR_BASE="${TMPDIR:-/tmp}"
TMPDIR_PATH=$(mktemp -d "${TMPDIR_BASE%/}/loaf.XXXXXX") || {
  echo "[!] Error: Failed to create temporary directory." >&2
  exit 1
}
LOAF_HEADER_PREFIX="SHA256(-)="
LOAF_HASH_LEN=64
LOAF_HEADER_LEN=$((${#LOAF_HEADER_PREFIX} + LOAF_HASH_LEN + 1))
LOAF_PAYLOAD_OFFSET=$((LOAF_HEADER_LEN + 1))

# --- Cleanup Function ---
cleanup() {
  if [[ -n "$TMPDIR_PATH" && -d "$TMPDIR_PATH" ]]; then
    rm -rf "$TMPDIR_PATH"
  fi
}
trap cleanup EXIT INT TERM HUP

# --- Functions ---

loaf_temp_path() {
  local prefix="$1"
  local path
  path=$(mktemp "$TMPDIR_PATH/${prefix}.XXXXXX") || {
    echo "[!] Error: Failed to create temporary file." >&2
    return 1
  }
  printf "%s" "$path"
}

loaf_temp_dir() {
  local prefix="$1"
  local path
  path=$(mktemp -d "$TMPDIR_PATH/${prefix}.XXXXXX") || {
    echo "[!] Error: Failed to create temporary directory." >&2
    return 1
  }
  printf "%s" "$path"
}

loaf_sha256_file() {
  local input="$1"
  local hash=""

  if command -v sha256sum >/dev/null 2>&1; then
    hash=$(sha256sum "$input" 2>/dev/null | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    hash=$(shasum -a 256 "$input" 2>/dev/null | awk '{print $1}')
  elif command -v openssl >/dev/null 2>&1; then
    hash=$(openssl dgst -sha256 -r "$input" 2>/dev/null | awk '{print $1}')
  else
    echo "[!] Error: No SHA256 tool found (need sha256sum, shasum, or openssl)." >&2
    return 1
  fi

  if [[ ! "$hash" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "[!] Error: Failed to calculate SHA256 checksum." >&2
    return 1
  fi

  printf "%s" "$hash" | tr 'A-F' 'a-f'
}

loaf_sha256_stream() {
  local hash=""

  if command -v sha256sum >/dev/null 2>&1; then
    hash=$(sha256sum 2>/dev/null | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    hash=$(shasum -a 256 2>/dev/null | awk '{print $1}')
  elif command -v openssl >/dev/null 2>&1; then
    hash=$(openssl dgst -sha256 -r 2>/dev/null | awk '{print $1}')
  else
    echo "[!] Error: No SHA256 tool found (need sha256sum, shasum, or openssl)." >&2
    return 1
  fi

  if [[ ! "$hash" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "[!] Error: Failed to calculate SHA256 checksum." >&2
    return 1
  fi

  printf "%s" "$hash" | tr 'A-F' 'a-f'
}

loaf_file_size() {
  local input="$1"
  stat -f%z "$input" 2>/dev/null || stat -c%s "$input" 2>/dev/null
}

loaf_last_byte_hex() {
  local input="$1"
  local size=""

  size=$(loaf_file_size "$input") || return 1
  if [[ "$size" -eq 0 ]]; then
    return 1
  fi

  tail -c 1 -- "$input" | od -An -tx1 | awk '{print $1}'
}

loaf_file_ends_with_newline() {
  local input="$1"
  local last_byte=""

  last_byte=$(loaf_last_byte_hex "$input") || return 1
  [[ "$last_byte" == "0a" ]]
}

loaf_chomp_final_newline() {
  local input="$1"
  local size=""
  local last_byte=""
  local new_size=""

  size=$(loaf_file_size "$input") || return 1
  if [[ "$size" -eq 0 ]]; then
    return 0
  fi

  last_byte=$(loaf_last_byte_hex "$input") || return 1
  if [[ "$last_byte" != "0a" ]]; then
    return 0
  fi

  new_size=$((size - 1))

  if command -v truncate >/dev/null 2>&1; then
    truncate -s "$new_size" "$input"
  elif command -v perl >/dev/null 2>&1; then
    perl -e 'truncate $ARGV[0], $ARGV[1] or die "truncate failed\n"' "$input" "$new_size"
  else
    echo "[!] Error: Cannot remove trailing newline without truncate or perl." >&2
    return 1
  fi
}

loaf_read_header_hash() {
  local input="$1"
  local header=""
  local hash=""

  header=$(dd if="$input" bs="$LOAF_HEADER_LEN" count=1 2>/dev/null)
  if [[ ${#header} -lt "$LOAF_HEADER_LEN" ]]; then
    echo "[!] Error: Failed to read a complete LoaF header from '$input'." >&2
    return 1
  fi

  if [[ "${header:0:${#LOAF_HEADER_PREFIX}}" != "$LOAF_HEADER_PREFIX" ]]; then
    echo "[!] Error: Invalid or missing SHA256 header format at start of '$input'." >&2
    echo "[i] Expected format like: SHA256(-)=<64_hex_chars>" >&2
    return 1
  fi

  hash="${header:${#LOAF_HEADER_PREFIX}:$LOAF_HASH_LEN}"
  if [[ ! "$hash" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "[!] Error: Invalid SHA256 hash in header for '$input'." >&2
    return 1
  fi

  if [[ "${header:$((LOAF_HEADER_LEN - 1)):1}" != " " ]]; then
    echo "[!] Error: Invalid format. Expected a space immediately after the header string in '$input'." >&2
    return 1
  fi

  printf "%s" "$hash" | tr 'A-F' 'a-f'
}

loaf_payload_stream() {
  local input="$1"
  tail -c +"$LOAF_PAYLOAD_OFFSET" -- "$input"
}

loaf_validate_archive_name() {
  local archive_name="$1"

  if [[ -z "$archive_name" || "$archive_name" == /* || "$archive_name" == "." || "$archive_name" == ".." || "$archive_name" == ../* || "$archive_name" == */../* || "$archive_name" == */.. || "$archive_name" == */ ]]; then
    echo "[!] Error: Invalid archive name '$archive_name'." >&2
    echo "[i] Archive names from stdin must be relative file paths without '..' path components." >&2
    exit 1
  fi
}

loaf_archive_to_hex_file() {
  local hex_file="$1"
  local tar_opts="-cpf"
  shift

  if [[ "$VERBOSE" == true ]]; then
    tar_opts="-cvpf"
    echo "[i] Archiving input..." >&2
    if ! tar --numeric-owner "$tar_opts" - "$@" | gzip -9 | xxd -p -c0 > "$hex_file"; then
      echo "[!] Error: Failed to create archive payload." >&2
      return 1
    fi
  else
    if ! { tar --numeric-owner "$tar_opts" - "$@" | gzip -9 | xxd -p -c0 > "$hex_file"; } 2>/dev/null; then
      echo "[!] Error: Failed to create archive payload." >&2
      return 1
    fi
  fi

  loaf_chomp_final_newline "$hex_file" || return 1
}

loaf_write_output() {
  local hex_file="$1"
  local output="$2"
  local crumb_hash=""
  local loaf_crust=""

  if [[ ! -s "$hex_file" ]]; then
    echo "[!] Warning: Generated LOAFCRUMB is empty. Resulting loaf will represent empty content." >&2
  fi

  crumb_hash=$(loaf_sha256_file "$hex_file") || exit 1
  loaf_crust="${LOAF_HEADER_PREFIX}${crumb_hash}"

  if [[ -z "$output" || "$output" == "-" ]]; then
    [[ "$VERBOSE" == true ]] && echo "[i] Writing loaf to stdout" >&2
    printf "%s " "$loaf_crust"
    cat "$hex_file"
  else
    [[ "$VERBOSE" == true ]] && echo "[i] Baking loaf to $output ..." >&2
    if ! ( set +o noclobber; { printf "%s " "$loaf_crust"; cat "$hex_file"; } > "$output" ); then
      echo "[!] Error: Failed to write output file '$output'." >&2
      exit 1
    fi

    # File Validation
    [[ "$VERBOSE" == true ]] && echo "[i] Verifying output file '$output'..." >&2
    if [[ ! -f "$output" ]]; then
      (echo && echo "[x] Error: Output file '$output' was not created (check permissions).") >&2
      exit 1
    fi
    if [[ ! -s "$output" ]]; then
      (echo && echo "[x] Error: Output file '$output' is empty.") >&2
      exit 1
    fi

    if loaf_file_ends_with_newline "$output"; then
      (echo && echo "[x] Error: Output file '$output' has an unexpected trailing newline.") >&2
      exit 1
    fi

    [[ "$VERBOSE" == true ]] && echo "[✓] Loaf baked successfully to $output" >&2
    [[ "$VERBOSE" == true ]] && ls -al "$output"
    [[ "$VERBOSE" == true ]] && file "$output"
    exit 0
  fi
}

loaf_make() {
  local input="$1"
  local output="$2"
  local archive_name=""
  local input_mode="" # 'pipe', 'file', 'interactive'
  local hex_file=""

  # 1. Determine Input Mode
  if [[ -p /dev/stdin || ! -t 0 ]]; then
    # Input is piped or redirected (not a terminal)
    # We only treat it as pipe mode if the input arg suggests stdin
    if [[ -z "$input" || "$input" == "-" || "$input" == -* ]]; then
      input_mode="pipe"
    else
      # Input is piped/redirected, but an input file path was ALSO given.
      # This is ambiguous. Prioritize the explicit file path.
      if [[ -p /dev/stdin ]]; then
        echo "[!] Warning: Input is piped, but input path '$input' also specified. Using file path." >&2
      fi
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

  hex_file=$(loaf_temp_path "loaf-hex") || exit 1

  # 2. Process Input based on Mode
  case "$input_mode" in
    pipe)
      [[ "$VERBOSE" == true ]] && echo "[i] Reading input from stdin pipe/redirect" >&2
      if [[ -n "$input" && "$input" != "-" ]]; then
        archive_name="${input#-}"
        [[ "$VERBOSE" == true ]] && echo "[i] Using archive name from argument: '$archive_name'" >&2
      else
        archive_name="-" # Default archive name is '-'
        [[ "$VERBOSE" == true ]] && echo "[i] Using default archive name: '$archive_name'" >&2
      fi
      loaf_validate_archive_name "$archive_name"

      local archive_dir archive_path archive_parent
      archive_dir=$(loaf_temp_dir "loaf-stdin") || exit 1
      archive_path="$archive_dir/$archive_name"
      archive_parent=$(dirname "$archive_path")
      mkdir -p "$archive_parent" || { echo "[!] Error creating temporary archive path." >&2; exit 1; }
      ( set +o noclobber; cat > "$archive_path" ) || { echo "[!] Error reading stdin." >&2; exit 1; }
      loaf_archive_to_hex_file "$hex_file" -C "$archive_dir" -- "$archive_name" || exit 1
      ;; # End pipe case

    interactive)
      [[ "$VERBOSE" == true ]] && echo "[i] Reading input interactively from terminal (End with Ctrl+D)" >&2
      # For interactive mode, the first arg ('-' or missing) doesn't specify archive name
      archive_name="-" # Default archive name is '-'
      [[ "$VERBOSE" == true ]] && echo "[i] Using default archive name: '$archive_name'" >&2

      loaf_validate_archive_name "$archive_name"
      local archive_dir archive_path
      archive_dir=$(loaf_temp_dir "loaf-stdin") || exit 1
      archive_path="$archive_dir/$archive_name"

      # Use 'cat' to read from terminal until EOF (Ctrl+D)
      # Redirect output to temp file, disabling noclobber
      # If user presses Ctrl+C, 'cat' will terminate, and 'set -e' will cause script exit.
      # The trap will handle cleanup.
      ( set +o noclobber; cat > "$archive_path" ) || { echo "[!] Error reading interactive input." >&2; exit 1; }

      # If we reach here, Ctrl+D was pressed and cat finished successfully
      [[ "$VERBOSE" == true ]] && echo "[i] Finished reading interactive input." >&2

      # Check if temp file is empty (user might just press Ctrl+D immediately)
      if [[ ! -s "$archive_path" ]]; then
          echo "[!] Warning: No input received from interactive session. Loaf will be empty." >&2
          # Allow creating an empty loaf, or exit if preferred:
          # exit 1
      fi

      loaf_archive_to_hex_file "$hex_file" -C "$archive_dir" -- "$archive_name" || exit 1
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
      loaf_archive_to_hex_file "$hex_file" -- "$input" || exit 1
      ;; # End file case
  esac

  # 3. Generate Header and Output
  loaf_write_output "$hex_file" "$output"
}

# Verifies the checksum of a loaf file
loaf_verify() {
  local input="$1"
  # Input validation
  if [[ -z "$input" ]]; then echo "[!] Error: No input loaf file specified." >&2; exit 1; fi
  if [[ ! -f "$input" || ! -r "$input" ]]; then echo "[!] Error: Input file '$input' not found or not readable." >&2; exit 1; fi

  local EMBED_HASH=""
  local CALC_HASH=""
  local file_size=""
  local payload_bytes=""
  local payload_file=""

  EMBED_HASH=$(loaf_read_header_hash "$input") || exit 1
  [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Embedded hash: $EMBED_HASH" >&2

  file_size=$(loaf_file_size "$input") || { echo "[!] Error: Failed to read size for '$input'." >&2; exit 1; }
  payload_bytes=$((file_size - LOAF_HEADER_LEN))

  if loaf_file_ends_with_newline "$input"; then
    payload_file=$(loaf_temp_path "loaf-payload") || exit 1
    if ! loaf_payload_stream "$input" > "$payload_file"; then
      echo "[!] Error: Failed to read payload from '$input'." >&2
      exit 1
    fi
    loaf_chomp_final_newline "$payload_file" || exit 1
    payload_bytes=$((payload_bytes - 1))
    CALC_HASH=$(loaf_sha256_file "$payload_file") || exit 1
  else
    if ! CALC_HASH=$(loaf_payload_stream "$input" | loaf_sha256_stream); then
      echo "[!] Error: Failed to read or hash payload from '$input'." >&2
      exit 1
    fi
  fi
  [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Payload bytes to hash: $payload_bytes" >&2
  [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Calculated hash: $CALC_HASH" >&2

  # Output verification status
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

# Extracts the contents of a LoaF archive
loaf_extract() {
  local input="$1"
  local output_arg="${2:-.}" # Use a different name to avoid confusion with output_dir
  local output_dir=""        # Will be set only if extracting to a directory
  local output_to_stdout=false
  local stdout_mode="raw"    # Default stdout mode ('raw' or 'delimited')
  local delimiter="␜"        # Default delimiter (Unicode U+241C)
  local temp_tar_stream_file="" # Path for temporary tar stream

  [[ "$VERBOSE" == true ]] && echo "[i] loaf_extract called with input: '$input' and output_arg: '$output_arg'" >&2

  # --- Input Validation ---
  if [[ -z "$input" ]]; then echo "[!] Error: No input loaf file specified." >&2; exit 1; fi
  if [[ ! -f "$input" || ! -r "$input" ]]; then echo "[!] Error: Input file '$input' not found or not readable." >&2; exit 1; fi

  # --- Determine Output Mode ---
  if [[ "$output_arg" == "-" ]]; then
    output_to_stdout=true
    stdout_mode="raw"
    [[ "$VERBOSE" == true ]] && echo "[i] Output mode: Raw stdout" >&2
  elif [[ "$output_arg" == --* ]]; then
    output_to_stdout=true
    stdout_mode="delimited"
    local custom_delimiter="${output_arg:2}"
    if [[ -n "$custom_delimiter" ]]; then
        delimiter="$custom_delimiter"
        [[ "$VERBOSE" == true ]] && echo "[i] Output mode: Delimited stdout with custom delimiter" >&2
    else
        [[ "$VERBOSE" == true ]] && echo "[i] Output mode: Delimited stdout with default delimiter '␜'" >&2
    fi
    [[ "$VERBOSE" == true ]] && printf "[DEBUG extract] Delimiter set to: %q\n" "$delimiter" >&2
  else
    output_to_stdout=false
    output_dir="$output_arg"
    [[ "$VERBOSE" == true ]] && echo "[i] Output mode: Directory '$output_dir'" >&2
    if [[ -e "$output_dir" && ! -d "$output_dir" ]]; then
        echo "[!] Error: Output target '$output_dir' exists but is not a directory." >&2; exit 1;
    fi
    mkdir -p "$output_dir" || { echo "[!] Error creating output directory '$output_dir'." >&2; exit 1; }
  fi

  # --- Validate Header Format ---
  local embed_hash=""
  local file_size=""
  embed_hash=$(loaf_read_header_hash "$input") || exit 1
  [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Embedded hash: $embed_hash" >&2

  # --- Handle Empty Archive ---
  file_size=$(loaf_file_size "$input") || { echo "[!] Error: Failed to read size for '$input'." >&2; exit 1; }
  if [[ "$file_size" -le "$LOAF_HEADER_LEN" ]]; then
      echo "[✓] Loaf extracted successfully (archive was empty)." >&2; exit 0;
  fi

  # --- Cleanup for temp tar stream file ---
  # Use a subshell trap to clean up this specific temp file
  cleanup_temp_tar() {
    [[ -n "$temp_tar_stream_file" && -f "$temp_tar_stream_file" ]] && rm -f "$temp_tar_stream_file"
  }

  # --- Decode, Decompress, and Extract ---
  local pipeline_exit_status=0
  (
    # Use subshell to isolate pipefail and simplify exit status capture
    set -o pipefail
    # Set trap specific to this subshell for the tar stream temp file
    trap cleanup_temp_tar EXIT INT TERM HUP

    if [[ "$output_to_stdout" == true ]]; then
      # --- STDOUT Output ---
      if [[ "$stdout_mode" == "raw" ]]; then
        # Raw concatenation using tar -O
        [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Pipeline (raw stdout): tail | xxd | gunzip | tar xOf -" >&2
        loaf_payload_stream "$input" | xxd -r -p | gunzip -c | tar xOf -

      elif [[ "$stdout_mode" == "delimited" ]]; then
        # Delimited output using a temporary file for the tar stream
        temp_tar_stream_file=$(loaf_temp_path "loaf-tar-stream") || exit 1
        [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Decoding/Decompressing tar stream to '$temp_tar_stream_file'..." >&2

        # Decode/Decompress HEX into the temporary file
        loaf_payload_stream "$input" | xxd -r -p | gunzip -c > "$temp_tar_stream_file"
        if [[ $? -ne 0 ]]; then
          echo "[!] Error during xxd/gunzip stage into temp file." >&2
          exit 1 # Exit subshell
        fi
        # Check if temp file was created and has content
        if [[ ! -s "$temp_tar_stream_file" ]]; then
          echo "[!] Error: Decoded/decompressed tar stream is empty." >&2
          exit 1
        fi

        [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Iterating through tar stream from '$temp_tar_stream_file' for delimited output..." >&2
        local first_file=true # Flag to handle delimiter placement

        # List files using the temp file, then loop
        while IFS= read -r filename; do
          # Skip directories explicitly
          if [[ "$filename" == */ ]]; then
            [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Skipping directory: $filename" >&2
            continue
          fi

          # Print delimiter *before* the file content, except for the first file
          if [[ "$first_file" == false ]]; then
            printf "%s" "$delimiter"
          else
            first_file=false # Mark that the first file is being processed
          fi

          # Extract the specific file's content to stdout, reading from the temp file
          [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Extracting to stdout: $filename" >&2
          # Use < redirection from the temp file
          tar xOf - "$filename" < "$temp_tar_stream_file" || {
            echo "[!] Error extracting content for '$filename' during delimited output." >&2
            # Decide whether to continue or exit on error
            continue # Skip to next file on error
          }

        # Read file list from the temp file
        done < <(tar tf - < "$temp_tar_stream_file")
        [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Finished iterating tar stream." >&2
        # Temp file will be removed by the subshell's EXIT trap
      fi

    else
      # --- Directory Output ---
      local tar_opts=""
      if [[ "$VERBOSE" == true ]]; then tar_opts="xvpf -"; else tar_opts="xpf -"; fi
      local tar_cmd=("tar" $tar_opts "-C" "$output_dir")
      [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Pipeline (directory): tail | xxd | gunzip | ${tar_cmd[*]}" >&2
      loaf_payload_stream "$input" | xxd -r -p | gunzip -c | "${tar_cmd[@]}"
    fi

  ) || pipeline_exit_status=$? # Capture exit status of the subshell

  # --- Check Pipeline Exit Status ---
  if [[ "$pipeline_exit_status" -ne 0 ]]; then
    local error_msg="[✗] Error during extraction pipeline (exit status: $pipeline_exit_status)."
    local is_error=false
    # Add more specific checks based on common exit codes
    if [[ "$pipeline_exit_status" -eq 1 && "$stdout_mode" != "delimited" ]]; then is_error=true; error_msg+=" Possible xxd/gzip/tar format error or permissions issue."; fi
    if [[ "$pipeline_exit_status" -eq 2 && "$output_to_stdout" == false ]]; then is_error=true; error_msg+=" Possible tar error (e.g., file exists, permissions)."; fi
    if [[ "$pipeline_exit_status" -eq 2 && "$stdout_mode" == "delimited" ]]; then is_error=true; error_msg+=" Possible tar error reading temp stream or extracting file."; fi # Tar exit code 2 common for fatal errors
    if [[ "$pipeline_exit_status" -gt 128 && "$output_to_stdout" == false ]]; then is_error=true; error_msg+=" Command might have been terminated by a signal."; fi

    if [[ "$is_error" == true ]]; then
      # Check if the error was due to a missing command
      if [[ "$pipeline_exit_status" -eq 127 ]]; then
        error_msg+=" Required command not found (xxd, gunzip, tar)."
      else
        error_msg+=" Check archive integrity, permissions, and tool availability (xxd, gunzip, tar)."
      fi

      # Print the error message
      echo "$error_msg" >&2
    fi

    exit $pipeline_exit_status
  fi

  # --- Success Message ---
  if [[ "$output_to_stdout" == false ]]; then
    echo "[✓] Loaf extracted successfully to '$output_dir'" >&2
  fi
  exit 0
}

print_usage() {
  # Using cat with heredoc for cleaner multiline echo
  cat << EOF
Usage:
  $0 [-v] c|create|make|new [<input>] [<output>] - Make a new LoaF archive
  $0 [-v] verify <input.loaf> - Verify a LoaF archive
  $0 [-v] x|extract <input.loaf> [<target>] - Extract contents of a LoaF archive

Make Options:
  <input>: File/folder path, or '-' for stdin, or '-name.txt' for named stdin.
           If omitted and stdin is piped, reads stdin (named '-').
           If omitted and stdin is terminal, reads interactively (End with Ctrl+D).
  <output>: Output file path. If omitted or '-', writes to stdout.

Extract Options:
  <target>: Optional target. Defaults to current directory ('.').
            - A directory path (e.g., ./out_dir) to extract files into.
            - '-' to extract raw concatenated content to stdout.
            - '--<DELIM>' to extract content to stdout, separated by <DELIM>.
              If <DELIM> is omitted (i.e., '--'), uses '␜' (U+241C) as delimiter.
              Quote the <DELIM> part if it contains spaces or shell metacharacters
              (e.g., --"foo bar", --'foo bar', --\$foo).

Examples:
  cat file.txt | $0 make - out.loaf   # Stdin (root name) -> out.loaf
  cat file.txt | $0 make -data.bin    # Stdin (named data.bin) -> stdout
  $0 make my_folder my_folder.loaf    # Folder -> my_folder.loaf
  $0 make                             # Read interactively -> stdout
  $0 make - my_interactive.loaf       # Read interactively -> my_interactive.loaf
  $0 verify my_folder.loaf
  $0 extract my_folder.loaf            # Extract to current directory
  $0 extract my_folder.loaf -          # Extract raw content to stdout
  $0 extract my_folder.loaf --         # Extract content to stdout delimited by '␜'
  $0 extract my_folder.loaf --\\n       # Extract content to stdout delimited by newline
  $0 extract my_folder.loaf --"--== ==--" # Extract content to stdout delimited by "--== ==--"
  $0 extract my_folder.loaf ./out_dir  # Extract to ./out_dir directory
EOF
}

# --- Option Parsing ---
OPTIND=1
while getopts ":v" opt; do
  case $opt in
    v) VERBOSE=true ;;
    \?) print_usage; exit 1 ;;
  esac
done
shift $((OPTIND-1))

# --- Main Command Dispatch ---
COMMAND="${1:-}"
if [[ "$VERBOSE" == true ]]; then
  echo "[i] Command: '$COMMAND'" >&2
  echo "[i] Arguments: $*" >&2
fi

if [[ "$COMMAND" == "make" || "$COMMAND" == "c" || "$COMMAND" == "create" || "$COMMAND" == "new" || "$COMMAND" == "loaf" || "$COMMAND" == "bake" || "$COMMAND" == "knead" || "$COMMAND" == "prepare" || "$COMMAND" == "cook" || "$COMMAND" == "spawn" || "$COMMAND" == "generate" || "$COMMAND" == "mix" || "$COMMAND" == "do" || "$COMMAND" == "cause" || "$COMMAND" == "be" || "$COMMAND" == "conjure" || "$COMMAND" == "press" || "$COMMAND" == "burn" || "$COMMAND" == "stir" || "$COMMAND" == "whip" || "$COMMAND" == "fold" || "$COMMAND" == "build" || "$COMMAND" == "embue" || "$COMMAND" == "form" || "$COMMAND" == "shape" || "$COMMAND" == "roll" ]]; then
  loaf_make "${2:-}" "${3:-}"
elif [[ "$COMMAND" == "verify" ]]; then
  if [[ "$#" -ne 2 ]]; then echo "[!] Error: 'verify' requires <input.loaf>" >&2; print_usage; exit 1; fi
  loaf_verify "$2"
elif [[ "$COMMAND" == "x" || "$COMMAND" == "extract" ]]; then
  if [[ "$#" -lt 2 || "$#" -gt 3 ]]; then
    echo "[!] Error: 'extract' requires <input.loaf> and optionally <target>" >&2
    print_usage
    exit 1
  fi
  # Pass the potential target argument (dir, -, --DELIM)
  loaf_extract "$2" "${3:-.}"
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
