#!/bin/bash

# IPSwamp Honeypot Installation Script
# Usage: ./install.sh [API_KEY] [HONEYPOT_ID]
# If arguments are provided, the script runs in non-interactive mode
# If no arguments are provided, the script runs in interactive mode

set -e

# Text formatting
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

# Default values
INSTALL_DIR="$(pwd)"
LOG_FILE="$INSTALL_DIR/install_log.txt"

# Function to log messages
log() {
    echo -e "$1"
    echo -e "$(date): $1" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to display a menu and get user selection
show_menu() {
    local prompt="$1"
    shift
    local options=("$@")
    local count=${#options[@]}
    
    echo -e "${BLUE}${BOLD}$prompt${RESET}"
    for ((i=0; i<count; i++)); do
        echo -e "  ${BOLD}$((i+1))${RESET}. ${options[$i]}"
    done
    
    local choice
    while true; do
        read -p "Please select an option (1-$count): " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $count ]; then
            return $choice
        else
            echo -e "${RED}Invalid selection. Please choose a number between 1 and $count.${RESET}"
        fi
    done
}

# Function to get user input with a default value
get_input() {
    local prompt="$1"
    local default="$2"
    local input
    
    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " input
        echo "${input:-$default}"
    else
        read -p "$prompt: " input
        echo "$input"
    fi
}

# Function to get hidden input (for API key)
get_hidden_input() {
    local prompt="$1"
    local input
    
    read -s -p "$prompt: " input
    echo ""  # Add a newline after hidden input
    echo "$input"
}

# Initialize variables
API_KEY=""
HONEYPOT_ID=""
INSTALLATION_METHOD=""
DOCKER_INSTALLED=false
COMPOSE_INSTALLED=false
INTERACTIVE_MODE=true

# Clear the screen for a better user experience
clear

log "${BLUE}${BOLD}=== IPSwamp Honeypot Installation ===${RESET}"
log "Installation directory: $INSTALL_DIR"

# Create necessary directories
mkdir -p logs ftp mail mysql

# Parse command line arguments if provided
if [ $# -ge 1 ]; then
    API_KEY="$1"
    log "API Key provided via command line argument"
    INTERACTIVE_MODE=false
fi

if [ $# -ge 2 ]; then
    HONEYPOT_ID="$2"
    log "Honeypot ID provided via command line argument: $HONEYPOT_ID"
fi

# Detect OS
log "${BLUE}Detecting operating system...${RESET}"
OS=""
if [ "$(uname)" == "Darwin" ]; then
    OS="macos"
    log "Detected macOS"
elif [ "$(uname)" == "Linux" ]; then
    OS="linux"
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
        log "Detected Debian/Ubuntu Linux"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="redhat"
        log "Detected RHEL/CentOS/Fedora Linux"
    elif [ -f /etc/alpine-release ]; then
        DISTRO="alpine"
        log "Detected Alpine Linux"
    else
        DISTRO="unknown"
        log "Detected unknown Linux distribution"
    fi
else
    log "${RED}${BOLD}Unsupported operating system: $(uname)${RESET}"
    exit 1
fi

# Check for Docker installation
if command_exists docker; then
    DOCKER_INSTALLED=true
    log "${GREEN}Docker is already installed${RESET}"
    docker --version | while read line; do log "$line"; done
else
    log "${YELLOW}Docker is not installed${RESET}"
fi

# Check for Docker Compose installation
if docker compose version >/dev/null 2>&1; then
    COMPOSE_INSTALLED=true
    log "${GREEN}Docker Compose plugin is installed${RESET}"
    docker compose version | while read line; do log "$line"; done
elif command_exists docker-compose; then
    COMPOSE_INSTALLED=true
    log "${YELLOW}Legacy docker-compose is installed${RESET}"
    docker-compose --version | while read line; do log "$line"; done
else
    log "${YELLOW}Docker Compose is not installed${RESET}"
fi

# Function to install Docker
install_docker() {
    log "Installing Docker..."
    case $OS in
        macos)
            echo "Please install Docker Desktop for Mac from https://www.docker.com/products/docker-desktop"
            echo "After installation, press Enter to continue..."
            read -r
            ;;
        linux)
            case $DISTRO in
                debian)
                    sudo apt-get update
                    sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
                    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
                    sudo apt-get update
                    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
                    ;;
                redhat)
                    sudo yum install -y yum-utils
                    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                    sudo yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
                    sudo systemctl start docker
                    sudo systemctl enable docker
                    ;;
                alpine)
                    sudo apk add --update docker docker-compose
                    sudo service docker start
                    sudo rc-update add docker default
                    ;;
                *)
                    echo -e "${RED}${BOLD}Automatic Docker installation is not supported for this Linux distribution${RESET}"
                    echo "Please install Docker manually according to https://docs.docker.com/engine/install/"
                    echo "After installation, press Enter to continue..."
                    read -r
                    ;;
            esac
            
            # Add current user to docker group to avoid using sudo
            if id -nG "$USER" | grep -qw "docker"; then
                log "${GREEN}User is already in the Docker group${RESET}"
            else
                log "${YELLOW}Adding user to the Docker group...${RESET}"
                sudo usermod -aG docker "$USER"
                log "${YELLOW}Please log out and log back in for the changes to take effect${RESET}"
                echo -e "${YELLOW}${BOLD}Note: You need to log out and log back in for Docker permissions to take effect.${RESET}"
                echo "Do you want to continue anyway? (y/n)"
                read -r proceed
                if [[ "$proceed" != "j" && "$proceed" != "J" && "$proceed" != "y" && "$proceed" != "Y" ]]; then
                    log "User chose to abort installation to log out and log back in"
                    echo -e "${YELLOW}Installation aborted. Run the script again after logging back in.${RESET}"
                    exit 0
                fi
            fi
            ;;
    esac
}

# Function to install Docker Compose
install_docker_compose() {
    log "Installing Docker Compose..."
    case $OS in
        linux)
            case $DISTRO in
                debian)
                    sudo apt-get update
                    sudo apt-get install -y docker-compose-plugin
                    ;;
                redhat)
                    sudo yum install -y docker-compose-plugin
                    ;;
                alpine)
                    sudo apk add --update docker-compose
                    ;;
                *)
                    log "Installing Docker Compose plugin manually..."
                    DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}
                    mkdir -p $DOCKER_CONFIG/cli-plugins
                    LATEST_COMPOSE=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
                    COMPOSE_VERSION=${LATEST_COMPOSE:-v2.23.0}
                    sudo curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/libexec/docker/cli-plugins/docker-compose
                    sudo chmod +x /usr/local/libexec/docker/cli-plugins/docker-compose
                    ;;
            esac
            ;;
        macos)
            echo -e "${YELLOW}Docker Compose should be included with Docker Desktop for Mac.${RESET}"
            echo "If not, please reinstall Docker Desktop."
            ;;
    esac
}

# Function to deploy with Docker Run
deploy_with_docker_run() {
    log "Deploying with Docker Run..."
    
    # Pull the image
    docker pull ghcr.io/haupt-pascal/ipswamp-honeypot:latest
    
    # Run the container
    docker run -d --name honeypot \
      -e HONEYPOT_ID="$HONEYPOT_ID" \
      -e API_KEY="$API_KEY" \
      -e API_ENDPOINT="https://api.ipswamp.com/api" \
      -e ENABLE_HTTP=true \
      -e ENABLE_HTTPS=true \
      -e ENABLE_SSH=true \
      -e ENABLE_FTP=true \
      -e ENABLE_MAIL=true \
      -e ENABLE_MYSQL=true \
      -p 8080:8080 \
      -p 8443:8443 \
      -p 2222:2222 \
      -p 21:21 \
      -p 25:25 \
      -p 587:587 \
      -p 110:110 \
      -p 143:143 \
      -p 3306:3306 \
      -p 1025-1050:1025-1050 \
      -v "$(pwd)/logs:/app/logs" \
      -v "$(pwd)/ftp:/app/ftp" \
      -v "$(pwd)/mail:/app/mail" \
      -v "$(pwd)/mysql:/app/mysql" \
      --restart unless-stopped \
      ghcr.io/haupt-pascal/ipswamp-honeypot:latest
}

# Function to deploy with Docker Compose
deploy_with_docker_compose() {
    log "Deploying with Docker Compose..."
    
    # Make sure docker-compose.yaml exists
    if [ ! -f "docker-compose.yaml" ] && [ -f "docker-compose.yml" ]; then
        COMPOSE_FILE="docker-compose.yml"
    else
        COMPOSE_FILE="docker-compose.yaml"
    fi
    
    # Start the container using docker compose v2 or legacy
    if docker compose version >/dev/null 2>&1; then
        docker compose -f "$COMPOSE_FILE" up -d
    else
        docker-compose -f "$COMPOSE_FILE" up -d
    fi
}

# Function to create environment file
create_env_file() {
    # Configure environment variables 
    log "Configuring environment variables..."
    ENV_FILE=".env"

    cat > "$ENV_FILE" << EOF
# IPSwamp Honeypot Configuration
HONEYPOT_ID=$HONEYPOT_ID
API_KEY=$API_KEY
API_ENDPOINT=https://api.ipswamp.com/api

# Enable all honeypot modules by default
ENABLE_HTTP=true
ENABLE_HTTPS=true
ENABLE_SSH=true
ENABLE_FTP=true
ENABLE_MAIL=true
ENABLE_MYSQL=true
EOF

    log "Environment configuration saved to $ENV_FILE"
}

# Function to verify deployment
verify_deployment() {
    if [ "$(docker ps -q -f name=honeypot)" ]; then
        echo -e "\n${GREEN}${BOLD}IPSwamp Honeypot was successfully started!${RESET}"
        echo -e "${GREEN}Honeypot ID: $HONEYPOT_ID${RESET}"
        echo -e "${GREEN}API Key: ********${RESET}"
        
        echo -e "\n${BLUE}${BOLD}Deployed Honeypot Services:${RESET}"
        echo "HTTP: Port 8080"
        echo "HTTPS: Port 8443"
        echo "SSH: Port 2222"
        echo "FTP: Port 21"
        echo "SMTP: Port 25, 587"
        echo "POP3: Port 110"
        echo "IMAP: Port 143"
        echo "MySQL: Port 3306"
        
        echo -e "\n${YELLOW}${BOLD}Important:${RESET}"
        echo "1. The honeypot is now running and sending data to the IPSwamp API."
        echo "2. Check logs: docker logs honeypot"
        
        if [ "$INSTALLATION_METHOD" = "compose" ]; then
            if docker compose version >/dev/null 2>&1; then
                echo "3. To stop: docker compose down"
            else
                echo "3. To stop: docker-compose down"
            fi
        else
            echo "3. To stop: docker stop honeypot && docker rm honeypot"
        fi
        
        echo "4. Configuration stored in: $ENV_FILE"
        return 0
    else
        echo -e "\n${RED}${BOLD}Error: IPSwamp Honeypot could not be started.${RESET}"
        echo "Check the logs with: docker logs honeypot"
        return 1
    fi
}

# Main execution logic based on mode
if [ "$INTERACTIVE_MODE" = true ]; then
    # Interactive installation mode
    log "Starting interactive installation process..."
    
    # Welcome message
    echo -e "${BOLD}${GREEN}"
    echo "  ___ ____  ______        ___    __  __ ____  "
    echo " |_ _|  _ \/ ___\ \      / / \  |  \/  |  _ \ "
    echo "  | || |_) \___ \\ \ /\ / / _ \ | |\/| | |_) |"
    echo "  | ||  __/ ___) |\ V  V / ___ \| |  | |  __/ "
    echo " |___|_|   |____/  \_/\_/_/   \_\_|  |_|_|    "
    echo -e "${RESET}"
    echo -e "${BOLD}Welcome to the interactive IPSwamp Honeypot Installation Assistant!${RESET}"
    echo ""
    
    # Step 1: Docker Configuration
    echo -e "${BLUE}${BOLD}Step 1: Docker Configuration${RESET}"

    if [ "$DOCKER_INSTALLED" = false ]; then
        show_menu "Docker is not installed. How would you like to proceed?" \
            "Install Docker automatically" \
            "Install Docker manually" \
            "Cancel installation"
        
        case $? in
            1)
                log "User chose to install Docker automatically"
                install_docker
                ;;
            2)
                log "User chose to install Docker manually"
                echo -e "${YELLOW}Please install Docker manually according to the instructions at:${RESET}"
                echo "https://docs.docker.com/engine/install/"
                
                if [ "$OS" = "linux" ]; then
                    echo -e "${YELLOW}After installation, run the following commands to use Docker without sudo:${RESET}"
                    echo "sudo usermod -aG docker \$USER"
                    echo "Then log out and log back in"
                fi
                
                echo "Press Enter when you have installed Docker and want to continue..."
                read -r
                ;;
            3)
                log "User chose to abort installation"
                echo -e "${RED}Installation aborted.${RESET}"
                exit 0
                ;;
        esac
    else
        log "Docker is already installed, proceeding with configuration"
    fi

    # Verify Docker installation again
    if ! command_exists docker; then
        log "${RED}${BOLD}Docker was not installed correctly. Please check the installation.${RESET}"
        echo -e "${RED}${BOLD}Docker was not installed correctly. Please check the installation.${RESET}"
        exit 1
    fi

    # Check for Docker Compose installation again
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_INSTALLED=true
    elif command_exists docker-compose; then
        COMPOSE_INSTALLED=true
    else
        # Try to install Docker Compose plugin
        log "Attempting to install Docker Compose plugin..."
        install_docker_compose

        # Check if Docker Compose was installed
        if docker compose version >/dev/null 2>&1 || command_exists docker-compose; then
            COMPOSE_INSTALLED=true
            log "${GREEN}Docker Compose was successfully installed${RESET}"
        else
            log "${RED}${BOLD}Docker Compose could not be installed${RESET}"
            echo -e "${RED}${BOLD}Docker Compose could not be installed. Continuing with Docker Run.${RESET}"
        fi
    fi

    # Step 2: Installation method selection
    echo -e "\n${BLUE}${BOLD}Step 2: Select Installation Method${RESET}"

    if [ "$COMPOSE_INSTALLED" = true ]; then
        installation_options=("Docker Compose (recommended)" "Docker Run" "Cancel installation")
    else
        installation_options=("Docker Run" "Cancel installation")
    fi

    show_menu "How would you like to install the honeypot?" "${installation_options[@]}"
    method_choice=$?

    case $method_choice in
        1)
            if [ "$COMPOSE_INSTALLED" = true ]; then
                INSTALLATION_METHOD="compose"
                log "User chose Docker Compose installation method"
            else
                INSTALLATION_METHOD="run"
                log "User chose Docker Run installation method"
            fi
            ;;
        2)
            if [ "$COMPOSE_INSTALLED" = true ]; then
                INSTALLATION_METHOD="run"
                log "User chose Docker Run installation method"
            else
                log "User chose to abort installation"
                echo -e "${RED}Installation aborted.${RESET}"
                exit 0
            fi
            ;;
        3)
            log "User chose to abort installation"
            echo -e "${RED}Installation aborted.${RESET}"
            exit 0
            ;;
    esac

    # Step 3: API Configuration
    echo -e "\n${BLUE}${BOLD}Step 3: API Configuration${RESET}"

    # Ask for API Key if not provided
    if [ -z "$API_KEY" ]; then
        API_KEY=$(get_hidden_input "Please enter your IPSwamp API key")
        while [ -z "$API_KEY" ]; do
            echo -e "${RED}API key cannot be empty.${RESET}"
            API_KEY=$(get_hidden_input "Please enter your IPSwamp API key")
        done
        log "API Key provided via interactive prompt"
    fi

    # Ask user if they want to customize the Honeypot ID
    echo -e "\nWould you like to use a custom Honeypot ID? (Default: $HONEYPOT_ID)"
    echo -e "  ${BOLD}1${RESET}. Use default ID ($HONEYPOT_ID)"
    echo -e "  ${BOLD}2${RESET}. Enter a custom ID"
    read -p "Please select an option (1-2): " id_choice

    if [ "$id_choice" = "2" ]; then
        custom_id=$(get_input "Please enter your custom Honeypot ID")
        if [ -n "$custom_id" ]; then
            HONEYPOT_ID="$custom_id"
            log "User provided custom Honeypot ID: $HONEYPOT_ID"
        else
            log "User kept default Honeypot ID: $HONEYPOT_ID"
        fi
    else
        log "User kept default Honeypot ID: $HONEYPOT_ID"
    fi

else
    # Non-interactive mode (using command-line arguments)
    log "Running in non-interactive mode with provided arguments"
    
    # Check for Docker
    if [ "$DOCKER_INSTALLED" = false ]; then
        log "${RED}${BOLD}Docker is not installed. Cannot proceed in non-interactive mode.${RESET}"
        echo -e "${RED}${BOLD}Docker is not installed. Please install Docker first or run the script in interactive mode.${RESET}"
        exit 1
    fi
    
    # Check for Docker Compose
    if docker compose version >/dev/null 2>&1 || command_exists docker-compose; then
        COMPOSE_INSTALLED=true
        INSTALLATION_METHOD="compose"
        log "Using Docker Compose installation method in non-interactive mode"
    else
        INSTALLATION_METHOD="run"
        log "Using Docker Run installation method in non-interactive mode"
    fi
fi

# Step 4: Configure and deploy
echo -e "\n${BLUE}${BOLD}Step 4: Configuration and Deployment${RESET}"

# Create environment file
create_env_file

# Deploy based on selected installation method
log "Deploying honeypot using $INSTALLATION_METHOD method..."

if [ "$INSTALLATION_METHOD" = "compose" ]; then
    echo -e "${GREEN}Starting Honeypot with Docker Compose...${RESET}"
    deploy_with_docker_compose
else
    echo -e "${GREEN}Starting Honeypot with Docker Run...${RESET}"
    deploy_with_docker_run
fi

# Verify deployment
verify_deployment
if [ $? -ne 0 ]; then
    exit 1
fi

log "${BLUE}${BOLD}=== Installation Complete ===${RESET}"
echo -e "\n${BLUE}${BOLD}=== Installation Complete ===${RESET}"
