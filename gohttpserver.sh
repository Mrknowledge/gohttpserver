#!/bin/bash

set -e

# Configuration
PROGRAM="gohttpserver"

# Detect OS and architecture
detect_binary() {
    local os=""
    local arch=""
    local binary_name=""
    
    # Detect OS
    case "$(uname -s)" in
        Linux*)
            os="linux"
            ;;
        Darwin*)
            os="darwin"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            os="windows"
            ;;
        *)
            log_error "Unsupported OS: $(uname -s)"
            exit 1
            ;;
    esac
    
    # Detect architecture
    case "$(uname -m)" in
        x86_64|amd64)
            arch="amd64"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        armv7l|arm)
            arch="armv7"
            ;;
        i386|i686)
            arch="386"
            ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
    
    # Build binary name
    if [ "$os" = "windows" ]; then
        binary_name="gohttpserver-${os}-${arch}.exe"
    else
        binary_name="gohttpserver-${os}-${arch}"
    fi
    
    BINARY_PATH="./dist/${binary_name}"
    
    log_info "Detected OS: $os, Architecture: $arch"
    log_info "Binary: $BINARY_PATH"
}

# Configuration
LOG_FILE="${PROGRAM}.log"
PID_FILE="${PROGRAM}.pid"

# Server configuration
TITLE="XX File Server"
PREFIX="/foo"
ADDR=":8000"
XHEADERS="--xheaders"
AUTH_TYPE="http"
UPLOAD="--upload"
DELETE="--delete"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check if binary exists
check_binary() {
    detect_binary
    
    if [ ! -f "$BINARY_PATH" ]; then
        log_error "Binary not found: $BINARY_PATH"
        log_error "Please make sure to build the binary for your system:"
        log_error "  go build -o dist/gohttpserver-linux-amd64 ."
        exit 1
    fi
}

# Get PID
get_pid() {
    if [ -f "$PID_FILE" ]; then
        cat "$PID_FILE"
    else
        echo ""
    fi
}

# Check if process is running
is_running() {
    local pid=$(get_pid)
    if [ -z "$pid" ]; then
        return 1
    fi
    kill -0 "$pid" 2>/dev/null
}

# Start service
start_service() {
    log_info "Starting $PROGRAM..."
    
    if is_running; then
        pid=$(get_pid)
        log_warn "$PROGRAM is already running (PID: $pid)"
        return 0
    fi
    
    check_binary
    
    # Start in background with nohup
    nohup "$BINARY_PATH" \
        --title "$TITLE" \
        --prefix "$PREFIX" \
        --addr "$ADDR" \
        $XHEADERS \
        --auth-type "$AUTH_TYPE" \
        $UPLOAD \
        $DELETE \
        >> "$LOG_FILE" 2>&1 &
    
    local pid=$!
    echo $pid > "$PID_FILE"
    
    # Wait a moment for process to start
    sleep 1
    
    if is_running; then
        log_info "$PROGRAM started successfully (PID: $pid)"
        return 0
    else
        log_error "$PROGRAM failed to start"
        rm -f "$PID_FILE"
        return 1
    fi
}

# Stop service
stop_service() {
    log_info "Stopping $PROGRAM..."
    
    if ! is_running; then
        log_warn "$PROGRAM is not running"
        rm -f "$PID_FILE"
        return 0
    fi
    
    pid=$(get_pid)
    log_info "Sending SIGTERM to process $pid..."
    
    kill -TERM "$pid" 2>/dev/null || true
    
    # Wait for graceful shutdown (max 10 seconds)
    local count=0
    while is_running && [ $count -lt 10 ]; do
        sleep 1
        count=$((count + 1))
    done
    
    if is_running; then
        log_warn "Graceful shutdown timeout, sending SIGKILL..."
        kill -9 "$pid" 2>/dev/null || true
    fi
    
    rm -f "$PID_FILE"
    log_info "$PROGRAM stopped successfully"
    return 0
}

# Restart service
restart_service() {
    log_info "Restarting $PROGRAM..."
    stop_service
    sleep 1
    start_service
}

# Get status
status_service() {
    if is_running; then
        pid=$(get_pid)
        log_info "$PROGRAM is running (PID: $pid)"
        
        # Show process info
        if command -v ps &> /dev/null; then
            ps aux | grep "$BINARY_PATH" | grep -v grep || true
        fi
        return 0
    else
        log_warn "$PROGRAM is not running"
        return 1
    fi
}

# Show logs
show_logs() {
    local lines=${1:-50}
    
    if [ ! -f "$LOG_FILE" ]; then
        log_warn "Log file not found: $LOG_FILE"
        return 1
    fi
    
    log_info "Showing last $lines lines of $LOG_FILE:"
    echo "---"
    tail -n "$lines" "$LOG_FILE"
    echo "---"
}

# Follow logs
follow_logs() {
    if [ ! -f "$LOG_FILE" ]; then
        log_warn "Log file not found: $LOG_FILE"
        return 1
    fi
    
    log_info "Following logs (press Ctrl+C to exit)..."
    tail -f "$LOG_FILE"
}

# Show help
show_help() {
    cat << EOF
${GREEN}GoHTTPServer Service Manager${NC}

Usage: $0 <command> [options]

Commands:
    start               Start the service
    stop                Stop the service
    restart             Restart the service
    status              Show service status
    log [lines]         Show last N lines of log (default: 50)
    follow              Follow logs in real-time
    help                Show this help message

Examples:
    $0 start
    $0 stop
    $0 restart
    $0 status
    $0 log 100
    $0 follow
    $0 help

Configuration:
    Log file:           $LOG_FILE
    PID file:           $PID_FILE
    
    Server settings:
    - Title:            $TITLE
    - Prefix:           $PREFIX
    - Address:          $ADDR
    - Auth type:        $AUTH_TYPE

Supported Systems:
    OS:         Linux, macOS (Darwin), Windows
    Arch:       x86_64 (amd64), aarch64 (arm64), armv7, i386

Build for your system:
    go build -o dist/gohttpserver-\$(go env GOOS)-\$(go env GOARCH) .

EOF
}

# Main command dispatcher
case "${1:-help}" in
    start)
        check_binary
        start_service
        ;;
    stop)
        stop_service
        ;;
    restart)
        check_binary
        restart_service
        ;;
    status)
        status_service
        ;;
    log)
        show_logs "${2:-50}"
        ;;
    follow)
        follow_logs
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac

exit $?
