#!/bin/bash
#
# AWS Key Finder - An optimized script to scan websites for exposed AWS credentials
# 

# Terminal colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --------- Configuration ---------
HTTPX_THREADS=300
MAX_PARALLEL_JOBS=4
TEMP_BASE="/tmp/aws_key_finder_$$"
LOG_FILE="key_finder.log"
KEYS_FOUND_FILE="aws_keys_found.txt"
SENDGRID_KEYS_FILE="sendgrid_keys_found.txt"

# --------- Initialization ---------
initialize() {
    echo -e "${BLUE}[+] Initializing AWS Key Finder${NC}"
    
    # Create base temp directory
    mkdir -p "$TEMP_BASE" || { echo -e "${RED}[!] Failed to create temp directory${NC}"; exit 1; }
    
    # Initialize log file
    echo "[$(date)] AWS Key Finder started" > "$LOG_FILE"
    
    # Initialize results files
    > "$KEYS_FOUND_FILE"
    > "$SENDGRID_KEYS_FILE"
    
    # Check for required dependencies
    check_dependencies
}

check_dependencies() {
    echo -e "${BLUE}[+] Checking dependencies${NC}"
    
    # Check for httpx
    if ! command -v httpx &> /dev/null; then
        if [[ -f "$HOME/go/bin/httpx" ]]; then
            echo -e "${YELLOW}[!] Using httpx from $HOME/go/bin/httpx${NC}"
            HTTPX="$HOME/go/bin/httpx"
        else
            echo -e "${RED}[!] httpx not found. Please install it with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest${NC}"
            exit 1
        fi
    else
        HTTPX="httpx"
    fi
    
    # Check for other dependencies
    for cmd in grep sed split mktemp parallel; do
        if ! command -v $cmd &> /dev/null; then
            echo -e "${RED}[!] Required command '$cmd' not found${NC}"
            exit 1
        fi
    done
}

# --------- Core Functions ---------
process_file() {
    local input_file="$1"
    local job_id="$2"
    local output_dir="$TEMP_BASE/job_$job_id"
    
    # Create job directory
    mkdir -p "$output_dir"
    
    # Count total URLs
    local total=$(wc -l < "$input_file")
    echo -e "${GREEN}[+] Job $job_id: Processing $total URLs from $input_file${NC}"
    
    # Split input into chunks of 500 URLs
    split -l 500 "$input_file" "$output_dir/chunk_"
    
    local chunks=$(ls "$output_dir/chunk_"* | wc -l)
    local current_chunk=0
    
    # Process each chunk
    for chunk_file in "$output_dir/chunk_"*; do
        current_chunk=$((current_chunk + 1))
        local chunk_name=$(basename "$chunk_file")
        local chunk_id="${job_id}_${chunk_name}"
        
        echo -e "${CYAN}[+] Job $job_id: Processing chunk $current_chunk/$chunks${NC}"
        
        # Create unique directory for this chunk
        local js_dir="$output_dir/js_$chunk_id"
        mkdir -p "$js_dir"
        
        # Extract JavaScript URLs
        echo -e "${BLUE}[*] Scanning websites and extracting JavaScript files...${NC}"
        $HTTPX -silent -sr -srd "$js_dir" -t $HTTPX_THREADS -l "$chunk_file" > "$output_dir/httpx_output_$chunk_id"
        
        # Extract JavaScript URLs from response data
        find "$js_dir" -type f -exec grep -l -E "\.js" {} \; | while read -r file; do
            grep -o -E "/[a-zA-Z0-9./?=_-]*\.(js)" "$file" >> "$output_dir/js_urls_$chunk_id"
        done
        
        # Clean extracted URLs
        if [[ -f "$output_dir/js_urls_$chunk_id" ]]; then
            sed 's/\[slash\]/\//g' "$output_dir/js_urls_$chunk_id" > "$output_dir/clean_js_urls_$chunk_id"
            
            # Fetch JavaScript files and scan for AWS keys
            echo -e "${BLUE}[*] Scanning JavaScript files for AWS keys...${NC}"
            $HTTPX -silent -l "$output_dir/clean_js_urls_$chunk_id" -t $HTTPX_THREADS -mr "AKIA[A-Z0-9]{16}" > "$output_dir/aws_hits_$chunk_id"
            
            if [[ -s "$output_dir/aws_hits_$chunk_id" ]]; then
                echo -e "${GREEN}[+] Found potential AWS keys in chunk $chunk_id${NC}"
                
                # Retrieve and save the content containing AWS keys
                $HTTPX -silent -sr -srd "$output_dir/aws_content_$chunk_id" -l "$output_dir/aws_hits_$chunk_id"
                
                # Extract actual keys
                find "$output_dir/aws_content_$chunk_id" -type f -exec grep -l "AKIA" {} \; | while read -r file; do
                    grep -o -E "AKIA[A-Z0-9]{16}" "$file" >> "$KEYS_FOUND_FILE"
                    echo "Source: $(grep -A 1 -B 1 "AKIA" "$file" | tr '\n' ' ')" >> "$KEYS_FOUND_FILE"
                    echo "URL: $(basename "$file" | sed 's/\.txt$//')" >> "$KEYS_FOUND_FILE"
                    echo "----------------------------------------" >> "$KEYS_FOUND_FILE"
                done
            fi
            
            # Look for SendGrid keys as well
            echo -e "${BLUE}[*] Scanning for SendGrid keys...${NC}"
            $HTTPX -silent -l "$output_dir/clean_js_urls_$chunk_id" -t $HTTPX_THREADS -mr "SG\.[0-9A-Za-z-_]{22}\.[0-9A-Za-z-_]{43}" > "$output_dir/sendgrid_hits_$chunk_id"
            
            if [[ -s "$output_dir/sendgrid_hits_$chunk_id" ]]; then
                echo -e "${GREEN}[+] Found potential SendGrid keys in chunk $chunk_id${NC}"
                
                # Retrieve and save content containing SendGrid keys
                $HTTPX -silent -sr -srd "$output_dir/sendgrid_content_$chunk_id" -l "$output_dir/sendgrid_hits_$chunk_id"
                
                # Extract actual keys
                find "$output_dir/sendgrid_content_$chunk_id" -type f -exec grep -l "SG\." {} \; | while read -r file; do
                    grep -o -E "SG\.[0-9A-Za-z-_]{22}\.[0-9A-Za-z-_]{43}" "$file" >> "$SENDGRID_KEYS_FILE"
                    echo "Source: $(grep -A 1 -B 1 "SG\." "$file" | tr '\n' ' ')" >> "$SENDGRID_KEYS_FILE"
                    echo "URL: $(basename "$file" | sed 's/\.txt$//')" >> "$SENDGRID_KEYS_FILE"
                    echo "----------------------------------------" >> "$SENDGRID_KEYS_FILE"
                done
            fi
        fi
        
        # Progress update
        local progress=$((current_chunk * 100 / chunks))
        echo -e "${GREEN}[+] Job $job_id: Completed chunk $current_chunk/$chunks ($progress%)${NC}"
        
        # Log completion
        echo "[$(date)] Job $job_id: Completed chunk $current_chunk/$chunks" >> "$LOG_FILE"
    done
    
    echo -e "${GREEN}[+] Job $job_id: Completed processing all chunks${NC}"
}

# Run in parallel mode with specified number of segments
run_parallel_mode() {
    local input_file="$1"
    local segments="$2"
    
    echo -e "${BLUE}[+] Running in parallel mode with $segments segments${NC}"
    
    # Validate segments
    if [[ ! "$segments" =~ ^[0-9]+$ ]] || [[ "$segments" -le 0 ]]; then
        echo -e "${RED}[!] Invalid number of segments. Must be a positive integer.${NC}"
        exit 1
    fi
    
    # Create temp directory for segments
    local segments_dir="$TEMP_BASE/segments"
    mkdir -p "$segments_dir"
    
    # Count total URLs
    local total=$(wc -l < "$input_file")
    echo -e "${GREEN}[+] Processing $total URLs from $input_file${NC}"
    
    # Split input file into specified number of segments
    local lines_per_segment=$(( (total + segments - 1) / segments ))
    split -l "$lines_per_segment" "$input_file" "$segments_dir/segment_"
    
    # Process each segment in parallel with a limit on max parallel jobs
    local segment_files=("$segments_dir"/segment_*)
    local segment_count=${#segment_files[@]}
    
    echo -e "${GREEN}[+] Split input into $segment_count segments${NC}"
    
    # Determine optimal parallelism
    local num_cpus=$(nproc 2>/dev/null || echo 4)
    local parallel_jobs=$(( segments < num_cpus ? segments : num_cpus ))
    parallel_jobs=$(( parallel_jobs > MAX_PARALLEL_JOBS ? MAX_PARALLEL_JOBS : parallel_jobs ))
    
    echo -e "${BLUE}[+] Using $parallel_jobs parallel jobs${NC}"
    
    # Use parallel to process segments
    parallel -j "$parallel_jobs" --bar "process_file {} {#}" ::: "${segment_files[@]}"
    
    echo -e "${GREEN}[+] All segments processed successfully${NC}"
}

# Run in single process mode
run_single_mode() {
    local input_file="$1"
    process_file "$input_file" "single"
}

# Cleanup function
cleanup() {
    echo -e "${BLUE}[+] Cleaning up temporary files${NC}"
    rm -rf "$TEMP_BASE"
    echo -e "${GREEN}[+] Cleanup complete${NC}"
}

# Display results
show_results() {
    echo -e "\n${PURPLE}======== SCAN RESULTS ========${NC}"
    
    if [[ -s "$KEYS_FOUND_FILE" ]]; then
        local key_count=$(grep -c "AKIA" "$KEYS_FOUND_FILE")
        echo -e "${GREEN}[+] Found $key_count AWS keys. Details saved to $KEYS_FOUND_FILE${NC}"
    else
        echo -e "${YELLOW}[!] No AWS keys found${NC}"
    fi
    
    if [[ -s "$SENDGRID_KEYS_FILE" ]]; then
        local sg_count=$(grep -c "SG\." "$SENDGRID_KEYS_FILE")
        echo -e "${GREEN}[+] Found $sg_count SendGrid keys. Details saved to $SENDGRID_KEYS_FILE${NC}"
    else
        echo -e "${YELLOW}[!] No SendGrid keys found${NC}"
    fi
    
    echo -e "${PURPLE}===============================${NC}"
}

# Print usage information
show_usage() {
    echo "AWS Key Finder - Scan websites for exposed AWS credentials"
    echo
    echo "Usage:"
    echo "  $0 <file_with_urls>                  # Process a single file in one job"
    echo "  $0 -s <segments> <file_with_urls>    # Process in parallel with specified segments"
    echo
    echo "Options:"
    echo "  -s <segments>    Split the input file into <segments> parts and process in parallel"
    echo "  -h               Show this help message"
    echo
    echo "Example:"
    echo "  $0 urls.txt"
    echo "  $0 -s 8 large_url_list.txt"
}

# --------- Main Script ---------
main() {
    # Check for help flag
    if [[ "$1" == "-h" ]]; then
        show_usage
        exit 0
    fi
    
    # Check for required arguments
    if [[ "$#" -lt 1 ]]; then
        echo -e "${RED}[!] Error: Missing required arguments${NC}"
        show_usage
        exit 1
    fi
    
    # Initialize environment
    initialize
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    # Check for parallel mode
    if [[ "$1" == "-s" ]]; then
        if [[ "$#" -lt 3 ]]; then
            echo -e "${RED}[!] Error: Missing required arguments for parallel mode${NC}"
            show_usage
            exit 1
        fi
        run_parallel_mode "$3" "$2"
    else
        run_single_mode "$1"
    fi
    
    # Display results
    show_results
    
    echo -e "${GREEN}[+] Scan completed successfully${NC}"
    echo "[$(date)] AWS Key Finder completed" >> "$LOG_FILE"
}

# Execute main function
main "$@"