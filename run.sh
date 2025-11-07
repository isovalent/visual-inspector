#!/bin/bash

# Visual Inspector Runner Script
# Usage: ./run.sh [install|start|restart|stop]

set -e

# Configuration
KUBECONFIG_PATH="${KUBECONFIG_PATH:-$HOME/.kube/config}"
SERVER_PID_FILE=".server.pid"
DEV_PID_FILE=".dev.pid"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if npm is installed
check_npm() {
    if ! command -v npm &> /dev/null; then
        log_error "npm is not installed. Please install Node.js and npm first."
        exit 1
    fi
}

# Install dependencies
install_deps() {
    log_info "Installing dependencies..."
    cd "$SCRIPT_DIR"
    npm install
    log_success "Dependencies installed successfully"
}

# Stop running processes
stop_processes() {
    log_info "Stopping running processes..."
    
    # Stop server
    if [ -f "$SERVER_PID_FILE" ]; then
        SERVER_PID=$(cat "$SERVER_PID_FILE")
        if ps -p "$SERVER_PID" > /dev/null 2>&1; then
            log_info "Stopping server (PID: $SERVER_PID)..."
            kill "$SERVER_PID" 2>/dev/null || true
            sleep 1
            # Force kill if still running
            if ps -p "$SERVER_PID" > /dev/null 2>&1; then
                kill -9 "$SERVER_PID" 2>/dev/null || true
            fi
        fi
        rm -f "$SERVER_PID_FILE"
    fi
    
    # Stop dev server
    if [ -f "$DEV_PID_FILE" ]; then
        DEV_PID=$(cat "$DEV_PID_FILE")
        if ps -p "$DEV_PID" > /dev/null 2>&1; then
            log_info "Stopping dev server (PID: $DEV_PID)..."
            kill "$DEV_PID" 2>/dev/null || true
            sleep 1
            # Force kill if still running
            if ps -p "$DEV_PID" > /dev/null 2>&1; then
                kill -9 "$DEV_PID" 2>/dev/null || true
            fi
        fi
        rm -f "$DEV_PID_FILE"
    fi
    
    # Also kill any remaining node processes for this project
    pkill -f "node.*server.js" 2>/dev/null || true
    pkill -f "vite.*visual-inspector" 2>/dev/null || true
    
    log_success "Processes stopped"
}

# Start the application
start_app() {
    log_info "Starting Visual Inspector..."
    cd "$SCRIPT_DIR"
    
    # Check if kubeconfig exists
    if [ ! -f "$KUBECONFIG_PATH" ]; then
        log_warn "Kubeconfig not found at: $KUBECONFIG_PATH"
        log_warn "You can set KUBECONFIG_PATH environment variable to specify a different location"
        log_warn "Example: export KUBECONFIG_PATH=/path/to/kubeconfig"
    else
        log_info "Using kubeconfig: $KUBECONFIG_PATH"
        export KUBECONFIG="$KUBECONFIG_PATH"
    fi
    
    # Start server in background
    log_info "Starting backend server..."
    npm run server > server.log 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$SERVER_PID_FILE"
    log_success "Backend server started (PID: $SERVER_PID)"
    
    # Wait a bit for server to start
    sleep 2
    
    # Start dev server in background
    log_info "Starting frontend dev server..."
    npm run dev > dev.log 2>&1 &
    DEV_PID=$!
    echo "$DEV_PID" > "$DEV_PID_FILE"
    log_success "Frontend dev server started (PID: $DEV_PID)"
    
    # Wait a bit for dev server to start
    sleep 3
    
    log_success "Visual Inspector is running!"
    log_info "Backend logs: tail -f $SCRIPT_DIR/server.log"
    log_info "Frontend logs: tail -f $SCRIPT_DIR/dev.log"
    log_info ""
    log_info "Access the application at: http://localhost:5174"
    log_info ""
    log_info "To stop: ./run.sh stop"
    log_info "To restart: ./run.sh restart"
}

# Show status
show_status() {
    log_info "Checking Visual Inspector status..."
    
    local running=false
    
    if [ -f "$SERVER_PID_FILE" ]; then
        SERVER_PID=$(cat "$SERVER_PID_FILE")
        if ps -p "$SERVER_PID" > /dev/null 2>&1; then
            log_success "Backend server is running (PID: $SERVER_PID)"
            running=true
        else
            log_warn "Backend server PID file exists but process is not running"
        fi
    else
        log_warn "Backend server is not running"
    fi
    
    if [ -f "$DEV_PID_FILE" ]; then
        DEV_PID=$(cat "$DEV_PID_FILE")
        if ps -p "$DEV_PID" > /dev/null 2>&1; then
            log_success "Frontend dev server is running (PID: $DEV_PID)"
            running=true
        else
            log_warn "Frontend dev server PID file exists but process is not running"
        fi
    else
        log_warn "Frontend dev server is not running"
    fi
    
    if [ "$running" = true ]; then
        log_info "Application URL: http://localhost:5174"
    fi
}

# Main script logic
case "${1:-start}" in
    install)
        check_npm
        install_deps
        ;;
    
    start)
        check_npm
        if [ ! -d "node_modules" ]; then
            log_warn "Dependencies not installed. Running install first..."
            install_deps
        fi
        start_app
        ;;
    
    stop)
        stop_processes
        ;;
    
    restart)
        log_info "Restarting Visual Inspector..."
        stop_processes
        sleep 1
        start_app
        ;;
    
    status)
        show_status
        ;;
    
    logs)
        log_info "Showing logs (Ctrl+C to exit)..."
        tail -f server.log dev.log 2>/dev/null || log_error "No log files found. Is the application running?"
        ;;
    
    *)
        echo "Visual Inspector Runner"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  install   - Install dependencies"
        echo "  start     - Start the application (default)"
        echo "  stop      - Stop the application"
        echo "  restart   - Restart the application (useful after code changes)"
        echo "  status    - Show application status"
        echo "  logs      - Show application logs"
        echo ""
        echo "Environment Variables:"
        echo "  KUBECONFIG_PATH - Path to kubeconfig file (default: ~/.kube/config)"
        echo ""
        echo "Examples:"
        echo "  $0 install"
        echo "  $0 start"
        echo "  KUBECONFIG_PATH=/path/to/config $0 start"
        echo "  $0 restart"
        exit 1
        ;;
esac
