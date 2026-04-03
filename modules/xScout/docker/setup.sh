#!/bin/bash
# Script to build Docker images and set up the environment for xScout firmware analysis

# Set script to exit on error
set -e

# Change to the script's directory
cd "$(dirname "$0")"

# Define color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Setting up xScout Docker environment...${NC}"

# Check if Docker is installed and running
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}Docker is not running. Please start Docker daemon first.${NC}"
    exit 1
fi

# Check if docker compose is installed
if ! command -v docker compose &> /dev/null; then
    echo -e "${RED}docker compose is not installed. Please install docker compose first.${NC}"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file with default settings...${NC}"
    cat > .env << EOF
# MongoDB settings
MONGO_USERNAME=admin
MONGO_PASSWORD=$(openssl rand -base64 12)
MONGO_PORT=27017
EOF
    echo -e "${GREEN}Created .env file with random password.${NC}"
else
    echo -e "${GREEN}.env file already exists.${NC}"
fi

# Build the Docker images
echo -e "${YELLOW}Building Docker images...${NC}"
docker compose build firmware-analysis

echo -e "${GREEN}Docker images built successfully.${NC}"

# Setup MongoDB
echo -e "${YELLOW}Setting up MongoDB...${NC}"
docker compose up -d mongodb

echo -e "${GREEN}MongoDB is now running.${NC}"

# Print connection information
echo -e "\n${YELLOW}Connection Information:${NC}"
source .env
echo -e "MongoDB: mongodb://$MONGO_USERNAME:******@localhost:$MONGO_PORT/"
echo -e "\n${GREEN}Setup completed successfully!${NC}"
echo -e "You can now use the xScout firmware analysis functionality."
echo -e "Run '${YELLOW}docker compose down${NC}' to stop the MongoDB service when not needed." 