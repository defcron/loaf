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

#!/bin/bash

# loaf.sh - Reference implementation of LoaF (Linear Object Archive Format) 🍞

# --- Shell Options ---
set -o pipefail
set -o posix
# set -e
# set -u
# set -o noclobber
# set -o errtrace
# set -o functrace

# --- Global Variables ---
VERBOSE=false
TMPFILE_PATH=""

# --- Cleanup Function ---
cleanup() {
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

  # Read the first line (or the whole file if no newline)
  local line_content read_status
  read -r line_content < "$input"
  read_status=$? # Capture read's exit status IMMEDIATELY

  # Check for read errors *other* than EOF before newline (status 1)
  # Also check if line_content is empty (e.g., empty file)
  # Status 0 (success) or 1 (EOF before newline) are acceptable if content was read.
  if [[ "$read_status" -gt 1 ]] || [[ -z "$line_content" ]]; then
      echo "[!] Error: Failed to read content from '$input' (read exit status: $read_status). File might be empty or corrupted." >&2
      exit 1
  fi
  [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Read status: $read_status. Content read (first 100 chars): ${line_content:0:100}" >&2

  # Check if the beginning of the line matches the header format
  local header_regex='^SHA256\(-\)=([0-9a-f]{64})'
  if [[ ! "$line_content" =~ $header_regex ]]; then
      echo "[!] Error: Invalid or missing SHA256 header format at start of '$input'." >&2
      echo "[i] Expected format like: SHA256(-)=<64_hex_chars>" >&2
      echo "[i] Start of file was: '${line_content:0:80}'..." >&2 # Show beginning
      exit 1
  fi
  [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Header regex matched successfully." >&2

  # Extract embedded hash and calculate actual header length from the match
  local EMBED_HASH="${BASH_REMATCH[1]}"
  local actual_header_len=${#BASH_REMATCH[0]} # Length of the matched header string "SHA256(-)=..."
  [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Embedded hash: $EMBED_HASH" >&2
  [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Matched header length: $actual_header_len" >&2

  # Calculate where hex data should start (position after header + space)
  # Spec: Header Space HexData
  local hex_start_index=$((actual_header_len + 1)) # Index is 0-based

  # Check if there is a space after the header in the read content
  if [[ "${line_content:$actual_header_len:1}" != " " ]]; then
      # Check if the file *only* contained the header (no space, no data)
      local file_size
      file_size=$(stat -c%s "$input" 2>/dev/null || stat -f%z "$input")
      if [[ "$file_size" -eq "$actual_header_len" ]]; then
          # This violates the "Header Space HexData" format, even for empty data.
          echo "[!] Error: File contains only the header string, missing the required space separator." >&2
      else
          # Header is present, but the character immediately after isn't a space.
          echo "[!] Error: Invalid format. Expected a space immediately after the header string in '$input'." >&2
          echo "[i] Character found at index $actual_header_len: '$(printf "%q" "${line_content:$actual_header_len:1}")'" >&2
      fi
      exit 1
  fi
  [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Space separator found after header." >&2

  # Extract hex data (everything after the header and the space)
  # Use substring extraction from the read line_content
  local HEX="${line_content:$hex_start_index}"
  [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Extracted HEX data length: ${#HEX}" >&2

  # Compare Hashes
  local CALC_HASH=""

  # Calculate hash
  if [[ -n "$HEX" ]]; then
      [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Calculating checksum for non-empty hex data..." >&2
      if [[ "$VERBOSE" == false ]]; then
          CALC_HASH=$( { printf "%s" "$HEX" | sha256sum --tag | awk '{print $4}'; } 2>/dev/null )
      else
          CALC_HASH=$(printf "%s" "$HEX" | sha256sum --tag | awk '{print $4}')
      fi
  else
      # If HEX is empty (meaning file ended exactly after "Header Space")
       [[ "$VERBOSE" == true ]] && echo "[DEBUG verify] Calculating checksum for empty data..." >&2
       if [[ "$VERBOSE" == false ]]; then
           CALC_HASH=$( { printf "" | sha256sum --tag | awk '{print $4}'; } 2>/dev/null )
       else
           CALC_HASH=$(printf "" | sha256sum --tag | awk '{print $4}')
       fi
  fi

  # Check if sha256sum failed
  if [[ -z "$CALC_HASH" ]]; then
      echo "[!] Error: Failed to calculate checksum. sha256sum might be missing or failed." >&2
      # Attempt to capture sha256sum error if verbose
      if [[ "$VERBOSE" == true ]]; then
          echo "[DEBUG verify] Running sha256sum again to capture error:" >&2
          if [[ -n "$HEX" ]]; then
              printf "%s" "$HEX" | sha256sum --tag || true # Allow failure to see error
          else
              printf "" | sha256sum --tag || true # Allow failure to see error
          fi
      fi
      exit 1
  fi
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

  # --- Read Loaf File Header ---
  local line_content read_status
  read -r line_content < "$input"
  read_status=$?
  if [[ "$read_status" -gt 1 ]] || [[ -z "$line_content" ]]; then
      echo "[!] Error: Failed to read content from '$input' (read exit status: $read_status)." >&2; exit 1;
  fi
  [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Read status: $read_status. Content read (first 100 chars): ${line_content:0:100}" >&2

  # --- Validate Header Format ---
  local header_regex='^SHA256\(-\)=([0-9a-f]{64})'
  if [[ ! "$line_content" =~ $header_regex ]]; then
    echo "[!] Error: Invalid or missing SHA256 header format at start of '$input'." >&2; exit 1;
  fi
  [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Header regex matched successfully." >&2

  # --- Extract Hex Data ---
  local actual_header_len=${#BASH_REMATCH[0]}
  local hex_start_index=$((actual_header_len + 1))
  if [[ "${line_content:$actual_header_len:1}" != " " ]]; then
      echo "[!] Error: Invalid format. Expected a space immediately after the header string." >&2; exit 1;
  fi
  [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Space separator found after header." >&2
  local HEX="${line_content:$hex_start_index}"
  [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Extracted HEX data length: ${#HEX}" >&2

  # --- Handle Empty Archive ---
  if [[ -z "$HEX" ]]; then
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
            [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Pipeline (raw stdout): printf | xxd | gunzip | tar xOf -" >&2
            printf "%s" "$HEX" | xxd -r -p | gunzip -c | tar xOf -

        elif [[ "$stdout_mode" == "delimited" ]]; then
            # Delimited output using a temporary file for the tar stream
            temp_tar_stream_file=$(mktemp /tmp/loaf-tar-stream.XXXXXX)
            [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Decoding/Decompressing tar stream to '$temp_tar_stream_file'..." >&2

            # Decode/Decompress HEX into the temporary file
            printf "%s" "$HEX" | xxd -r -p | gunzip -c > "$temp_tar_stream_file"
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
        [[ "$VERBOSE" == true ]] && echo "[DEBUG extract] Pipeline (directory): printf | xxd | gunzip | ${tar_cmd[*]}" >&2
        printf "%s" "$HEX" | xxd -r -p | gunzip -c | "${tar_cmd[@]}"
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
