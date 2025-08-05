#!/bin/bash

# Security Analysis Helper Script for cyrus-sasl-oauth2-oidc
# This script builds and runs the security analysis Docker container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="cyrus-sasl-oauth2-security"
REPORTS_DIR="$SCRIPT_DIR/security-reports"

show_help() {
    cat << EOF
Security Analysis Helper for cyrus-sasl-oauth2-oidc

Usage: $0 [COMMAND] [OPTIONS]

Commands:
  build           Build the security analysis Docker image
  analyze         Run comprehensive security analysis
  quick           Run quick security analysis  
  bash            Open interactive shell in container
  clean           Remove analysis reports and Docker image
  view            View analysis reports summary

Options:
  --no-cache      Build Docker image without cache
  --help, -h      Show this help message

Examples:
  $0 build                    # Build the analysis image
  $0 analyze                  # Run full security analysis
  $0 quick                    # Run quick analysis (faster)
  $0 bash                     # Interactive shell for manual analysis
  $0 view                     # View summary of existing reports

Reports will be saved to: $REPORTS_DIR
EOF
}

build_image() {
    local BUILD_ARGS=""
    if [[ "$1" == "--no-cache" ]]; then
        BUILD_ARGS="--no-cache"
    fi
    
    echo "🔨 Building security analysis Docker image..."
    docker build $BUILD_ARGS -f "$SCRIPT_DIR/Dockerfile.security-analysis" -t "$IMAGE_NAME" "$SCRIPT_DIR"
    echo "✅ Docker image built successfully: $IMAGE_NAME"
}

run_analysis() {
    local ANALYSIS_TYPE="$1"
    
    # Ensure reports directory exists
    mkdir -p "$REPORTS_DIR"
    
    echo "🔍 Running $ANALYSIS_TYPE security analysis..."
    echo "📁 Source: $SCRIPT_DIR"
    echo "📊 Reports: $REPORTS_DIR"
    echo
    
    docker run --rm \
        -v "$SCRIPT_DIR:/workspace:ro" \
        -v "$REPORTS_DIR:/opt/security-analysis/reports" \
        "$IMAGE_NAME" "$ANALYSIS_TYPE"
    
    echo
    echo "✅ Analysis complete!"
    echo "📊 Reports saved to: $REPORTS_DIR"
    
    # Show quick summary
    if [ -f "$REPORTS_DIR/ANALYSIS_SUMMARY.md" ]; then
        echo
        echo "📋 Analysis Summary:"
        head -20 "$REPORTS_DIR/ANALYSIS_SUMMARY.md"
    fi
}

open_shell() {
    echo "🐚 Opening interactive shell in security analysis container..."
    echo "💡 Your source code is mounted at /workspace"
    echo "💡 Reports will be saved to /opt/security-analysis/reports"
    echo
    
    mkdir -p "$REPORTS_DIR"
    
    docker run --rm -it \
        -v "$SCRIPT_DIR:/workspace" \
        -v "$REPORTS_DIR:/opt/security-analysis/reports" \
        "$IMAGE_NAME" bash
}

clean_all() {
    echo "🧹 Cleaning up..."
    
    # Remove reports
    if [ -d "$REPORTS_DIR" ]; then
        echo "🗑️  Removing reports directory: $REPORTS_DIR"
        rm -rf "$REPORTS_DIR"
    fi
    
    # Remove Docker image
    if docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        echo "🗑️  Removing Docker image: $IMAGE_NAME"
        docker rmi "$IMAGE_NAME"
    fi
    
    echo "✅ Cleanup complete"
}

view_reports() {
    if [ ! -d "$REPORTS_DIR" ]; then
        echo "❌ No reports found. Run analysis first with: $0 analyze"
        exit 1
    fi
    
    echo "📊 Security Analysis Reports Summary"
    echo "=================================="
    echo "📁 Reports directory: $REPORTS_DIR"
    echo
    
    # Show summary if available
    if [ -f "$REPORTS_DIR/ANALYSIS_SUMMARY.md" ]; then
        echo "📋 Analysis Summary:"
        cat "$REPORTS_DIR/ANALYSIS_SUMMARY.md"
        echo
    fi
    
    echo "📁 Available report files:"
    ls -la "$REPORTS_DIR" 2>/dev/null || echo "No reports found"
    echo
    
    echo "🔍 Quick view commands:"
    echo "  Text reports:    cat $REPORTS_DIR/*.txt"
    echo "  HTML reports:    open $REPORTS_DIR/*.html"
    echo "  XML reports:     less $REPORTS_DIR/*.xml"
    echo
    
    # Show quick stats from main reports
    echo "📈 Quick Statistics:"
    
    if [ -f "$REPORTS_DIR/cppcheck-report.txt" ]; then
        local issues=$(grep -c ":" "$REPORTS_DIR/cppcheck-report.txt" 2>/dev/null || echo "0")
        echo "  Cppcheck issues: $issues"
    fi
    
    if [ -f "$REPORTS_DIR/splint-report.txt" ]; then
        local issues=$(wc -l < "$REPORTS_DIR/splint-report.txt" 2>/dev/null || echo "0")  
        echo "  Splint warnings: $issues"
    fi
    
    if [ -f "$REPORTS_DIR/flawfinder-report.txt" ]; then
        local issues=$(grep -c "Hits = " "$REPORTS_DIR/flawfinder-report.txt" 2>/dev/null || echo "0")
        echo "  Flawfinder hits: $issues"
    fi
    
    if [ -f "$REPORTS_DIR/cpd-report.txt" ]; then
        local duplications=$(grep -c "Found a" "$REPORTS_DIR/cpd-report.txt" 2>/dev/null || echo "0")
        echo "  Code duplications: $duplications"
    fi
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker is not installed or not in PATH"
        echo "Please install Docker first: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        echo "❌ Docker daemon is not running"
        echo "Please start Docker daemon first"
        exit 1
    fi
}

# Main script logic
case "$1" in
    "build")
        check_docker
        build_image "$2"
        ;;
    "analyze")
        check_docker
        if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
            echo "🔨 Image not found, building first..."
            build_image
        fi
        run_analysis "analyze"
        ;;
    "quick")
        check_docker
        if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
            echo "🔨 Image not found, building first..."
            build_image
        fi
        run_analysis "quick"
        ;;
    "bash")
        check_docker
        if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
            echo "🔨 Image not found, building first..."
            build_image
        fi
        open_shell
        ;;
    "clean")
        check_docker
        clean_all
        ;;
    "view")
        view_reports
        ;;
    "--help"|"-h"|"help")
        show_help
        ;;
    "")
        echo "❌ No command specified"
        echo
        show_help
        exit 1
        ;;
    *)
        echo "❌ Unknown command: $1"
        echo
        show_help
        exit 1
        ;;
esac