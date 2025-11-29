#!/bin/bash

################################################################################
# CodeRED Defense Matrix - Launch Script
# Quick deployment options for different scenarios
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         CodeRED Defense Matrix - Launch Control           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to check dependencies
check_dependencies() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}"

    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[!] Python 3 is not installed${NC}"
        exit 1
    fi

    # Check Docker (optional)
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}[✓] Docker found${NC}"
        DOCKER_AVAILABLE=1
    else
        echo -e "${YELLOW}[!] Docker not found (optional)${NC}"
        DOCKER_AVAILABLE=0
    fi

    # Check root privileges for immediate protection
    if [ "$EUID" -eq 0 ]; then
        echo -e "${GREEN}[✓] Root privileges available${NC}"
        ROOT_AVAILABLE=1
    else
        echo -e "${YELLOW}[!] Not running as root (some features limited)${NC}"
        ROOT_AVAILABLE=0
    fi
}

# Function to show menu
show_menu() {
    echo ""
    echo "Select deployment option:"
    echo ""
    echo "  1) 🚨 EMERGENCY - Immediate Protection (No dependencies, $0 cost)"
    echo "  2) 🛡️  Quick Defense - Python-based deployment"
    echo "  3) 🐳 Docker Deploy - Containerized deployment"
    echo "  4) 🌐 Full Stack - Complete system with monitoring"
    echo "  5) 🧪 Test Mode - Validate all components"
    echo "  6) 📖 Documentation - View README"
    echo "  7) ❌ Exit"
    echo ""
}

# Function for emergency deployment
emergency_deploy() {
    echo -e "${RED}[!] EMERGENCY DEPLOYMENT INITIATED${NC}"

    if [ "$ROOT_AVAILABLE" -eq 0 ]; then
        echo -e "${YELLOW}[!] Requesting root privileges...${NC}"
        sudo deployment/scripts/immediate-protection.sh
    else
        deployment/scripts/immediate-protection.sh
    fi
}

# Function for Python deployment
python_deploy() {
    echo -e "${BLUE}[*] Starting Python-based deployment...${NC}"

    # Create virtual environment if not exists
    if [ ! -d "venv" ]; then
        echo "[*] Creating virtual environment..."
        python3 -m venv venv
    fi

    # Activate virtual environment
    source venv/bin/activate

    # Install requirements
    echo "[*] Installing requirements..."
    pip install -q -r requirements.txt

    # Launch defense system
    echo -e "${GREEN}[*] Launching CodeRED Defense System...${NC}"
    echo ""
    echo "Select mode:"
    echo "  1) Patrol - Normal monitoring"
    echo "  2) Defense - Active defense"
    echo "  3) Test - System validation"
    read -p "Mode (1-3): " mode_choice

    case $mode_choice in
        1) MODE="patrol" ;;
        2) MODE="defense" ;;
        3) MODE="test" ;;
        *) MODE="patrol" ;;
    esac

    echo "Select intensity:"
    echo "  1) Low - Minimal resources"
    echo "  2) Medium - Balanced"
    echo "  3) High - Maximum protection"
    read -p "Intensity (1-3): " intensity_choice

    case $intensity_choice in
        1) INTENSITY="low" ;;
        2) INTENSITY="medium" ;;
        3) INTENSITY="high" ;;
        *) INTENSITY="medium" ;;
    esac

    python src/swarm/quick_deploy.py --mode $MODE --intensity $INTENSITY
}

# Function for Docker deployment
docker_deploy() {
    if [ "$DOCKER_AVAILABLE" -eq 0 ]; then
        echo -e "${RED}[!] Docker is not installed${NC}"
        echo "Please install Docker first: https://docs.docker.com/get-docker/"
        exit 1
    fi

    echo -e "${BLUE}[*] Starting Docker deployment...${NC}"

    # Build images
    echo "[*] Building Docker images..."
    docker-compose build

    # Start services
    echo "[*] Starting services..."
    docker-compose up -d

    echo -e "${GREEN}[✓] Services started${NC}"
    echo ""
    echo "Access points:"
    echo "  - API: http://localhost:3000"
    echo "  - WebSocket: ws://localhost:6789"
    echo "  - Grafana: http://localhost:3001 (admin/codered)"
    echo "  - Prometheus: http://localhost:9090"
    echo ""
    echo "View logs: docker-compose logs -f"
    echo "Stop services: docker-compose down"
}

# Function for full stack deployment
full_stack_deploy() {
    echo -e "${BLUE}[*] Full stack deployment...${NC}"

    # Run immediate protection first
    if [ "$ROOT_AVAILABLE" -eq 1 ]; then
        echo "[*] Applying immediate protection..."
        deployment/scripts/immediate-protection.sh
    fi

    # Deploy Docker stack if available
    if [ "$DOCKER_AVAILABLE" -eq 1 ]; then
        docker_deploy
    else
        python_deploy
    fi

    echo -e "${GREEN}[✓] Full stack deployed${NC}"
}

# Function for test mode
test_mode() {
    echo -e "${BLUE}[*] Running system tests...${NC}"

    # Activate virtual environment
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi

    # Install test requirements
    pip install -q pytest pytest-asyncio

    # Run tests
    echo "[*] Running unit tests..."
    python -m pytest tests/unit/ -v

    echo "[*] Running integration tests..."
    python -m pytest tests/integration/ -v

    echo "[*] Running component validation..."
    python src/swarm/quick_deploy.py --mode test --intensity low

    echo -e "${GREEN}[✓] Tests completed${NC}"
}

# Main execution
check_dependencies

while true; do
    show_menu
    read -p "Enter choice (1-7): " choice

    case $choice in
        1)
            emergency_deploy
            ;;
        2)
            python_deploy
            ;;
        3)
            docker_deploy
            ;;
        4)
            full_stack_deploy
            ;;
        5)
            test_mode
            ;;
        6)
            less README.md
            ;;
        7)
            echo -e "${GREEN}[*] Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Invalid choice${NC}"
            ;;
    esac

    echo ""
    read -p "Press Enter to continue..."
done