#!/bin/bash
# OAuth2 SASL Plugin Test Runner
# Runs both unit tests and E2E tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "OAuth2 SASL Plugin Test Suite"
echo "============================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to run unit tests
run_unit_tests() {
    print_status $YELLOW "Running Unit Tests..."
    echo "====================="
    
    cd "$SCRIPT_DIR/unit"
    
    # Check if we can compile
    if ! command -v gcc &> /dev/null; then
        print_status $RED "ERROR: gcc not found. Please install build tools."
        return 1
    fi
    
    # Install dependencies if needed
    if [ "$1" = "--install-deps" ]; then
        print_status $YELLOW "Installing unit test dependencies..."
        make -f Makefile.tests install-deps
    fi
    
    # Build and run tests
    if make -f Makefile.tests test; then
        print_status $GREEN "✓ Unit tests passed"
        return 0
    else
        print_status $RED "✗ Unit tests failed"
        return 1
    fi
}

# Function to run E2E tests
run_e2e_tests() {
    print_status $YELLOW "Running E2E Tests..."
    echo "===================="
    
    cd "$SCRIPT_DIR/e2e"
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_status $RED "ERROR: Docker not found. Please install Docker."
        return 1
    fi
    
    # Check if Docker Compose is available
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_status $RED "ERROR: Docker Compose not found. Please install Docker Compose."
        return 1
    fi
    
    # Use docker-compose or docker compose based on availability
    DOCKER_COMPOSE_CMD="docker-compose"
    if ! command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE_CMD="docker compose"
    fi
    
    # Run E2E tests with Docker Compose
    print_status $YELLOW "Starting test environment..."
    
    # Clean up any existing containers
    $DOCKER_COMPOSE_CMD -f docker-compose.test.yml down -v 2>/dev/null || true
    
    # Build and run tests
    if $DOCKER_COMPOSE_CMD -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner; then
        print_status $GREEN "✓ E2E tests passed"
        RESULT=0
    else
        print_status $RED "✗ E2E tests failed"
        RESULT=1
    fi
    
    # Clean up
    $DOCKER_COMPOSE_CMD -f docker-compose.test.yml down -v
    
    return $RESULT
}

# Function to run tests locally (without Docker)
run_e2e_local() {
    print_status $YELLOW "Running E2E Tests Locally..."
    echo "============================"
    
    cd "$SCRIPT_DIR/e2e"
    
    # Check if Python is available
    if ! command -v python3 &> /dev/null; then
        print_status $RED "ERROR: Python 3 not found. Please install Python 3."
        return 1
    fi
    
    # Install Python dependencies
    if [ ! -d "venv" ]; then
        print_status $YELLOW "Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    pip install -r requirements.txt
    
    # Start mock OAuth2 server in background
    print_status $YELLOW "Starting mock OAuth2 server..."
    python3 mock_oauth2_server.py &
    MOCK_SERVER_PID=$!
    
    # Wait for server to start
    sleep 3
    
    # Run tests
    if python3 test_e2e.py; then
        print_status $GREEN "✓ E2E tests passed"
        RESULT=0
    else
        print_status $RED "✗ E2E tests failed"
        RESULT=1
    fi
    
    # Clean up
    kill $MOCK_SERVER_PID 2>/dev/null || true
    deactivate
    
    return $RESULT
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_TYPE]"
    echo ""
    echo "TEST_TYPE:"
    echo "  unit      Run only unit tests"
    echo "  e2e       Run only E2E tests (Docker)"
    echo "  e2e-local Run only E2E tests (local)"
    echo "  all       Run all tests (default)"
    echo ""
    echo "OPTIONS:"
    echo "  --install-deps  Install test dependencies"
    echo "  --help         Show this help message"
    echo ""
    echo "Environment Variables for E2E tests:"
    echo "  TEST_IMAP_HOST          IMAP server host"
    echo "  TEST_OAUTH2_ISSUER      OAuth2 issuer URL"
    echo "  TEST_OAUTH2_CLIENT_ID   OAuth2 client ID"
    echo "  TEST_OAUTH2_AUDIENCE    OAuth2 audience"
    echo "  AUTHENTIK_URL           Authentik server URL (optional)"
}

# Parse command line arguments
INSTALL_DEPS=false
TEST_TYPE="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        --install-deps)
            INSTALL_DEPS=true
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        unit|e2e|e2e-local|all)
            TEST_TYPE=$1
            shift
            ;;
        *)
            print_status $RED "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
UNIT_RESULT=0
E2E_RESULT=0

case $TEST_TYPE in
    unit)
        if $INSTALL_DEPS; then
            run_unit_tests --install-deps
        else
            run_unit_tests
        fi
        exit $?
        ;;
    e2e)
        run_e2e_tests
        exit $?
        ;;
    e2e-local)
        run_e2e_local
        exit $?
        ;;
    all)
        print_status $YELLOW "Running complete test suite..."
        echo ""
        
        # Run unit tests
        if $INSTALL_DEPS; then
            run_unit_tests --install-deps || UNIT_RESULT=$?
        else
            run_unit_tests || UNIT_RESULT=$?
        fi
        
        echo ""
        
        # Run E2E tests
        run_e2e_tests || E2E_RESULT=$?
        
        echo ""
        print_status $YELLOW "Test Summary:"
        echo "============="
        
        if [ $UNIT_RESULT -eq 0 ]; then
            print_status $GREEN "✓ Unit tests: PASSED"
        else
            print_status $RED "✗ Unit tests: FAILED"
        fi
        
        if [ $E2E_RESULT -eq 0 ]; then
            print_status $GREEN "✓ E2E tests: PASSED"
        else
            print_status $RED "✗ E2E tests: FAILED"
        fi
        
        if [ $UNIT_RESULT -eq 0 ] && [ $E2E_RESULT -eq 0 ]; then
            print_status $GREEN "🎉 All tests passed!"
            exit 0
        else
            print_status $RED "❌ Some tests failed"
            exit 1
        fi
        ;;
esac
