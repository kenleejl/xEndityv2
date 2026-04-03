# xScout Docker Containerization

This directory contains Docker configuration files for containerizing the firmware analysis functionality of the xScout module.

## Architecture

The containerized setup consists of:

1. **MongoDB Container**: Persistent database for storing analysis results
2. **Firmware Analysis Container**: On-demand container that performs the actual analysis

## Setup Instructions

### Prerequisites

- Docker (19.03+)
- Docker Compose (built into Docker Desktop or Docker Engine 23.0+)

### Quick Setup

Run the setup script to build the containers and start MongoDB:

```bash
# Make script executable
chmod +x setup.sh

# Run setup script
./setup.sh
```

This will:
- Create a .env file with default settings (if not exists)
- Build the Docker images
- Start the MongoDB container

### Manual Setup

If you prefer to set up manually:

1. Create a `.env` file with MongoDB credentials:
   ```
   MONGO_USERNAME=admin
   MONGO_PASSWORD=your_secure_password
   MONGO_PORT=27017
   ```

2. Build the Docker image:
   ```bash
   docker compose build firmware-analysis
   ```

3. Start MongoDB:
   ```bash
   docker compose up -d mongodb
   ```

## Configuration

The following environment variables can be configured in the `.env` file:

- `MONGO_USERNAME`: MongoDB admin username
- `MONGO_PASSWORD`: MongoDB admin password
- `MONGO_PORT`: Port to expose MongoDB on

## Django Integration

The Django application will automatically detect if Docker is available and use containerized analysis when possible. 
If Docker is not available, it will fall back to local execution.

To ensure Docker is used:

1. Make sure the Docker daemon is running
2. Ensure the `docker` command is available to the user running the Django application
3. Ensure the MongoDB container is running

## Troubleshooting

### Connection Issues

If the Django application can't connect to MongoDB:

1. Check that the MongoDB container is running:
   ```bash
   docker ps | grep xendity-mongodb
   ```

2. Verify MongoDB credentials in Django settings match those in `.env`

### Analysis Failures

If analysis fails in the Docker container:

1. Check container logs:
   ```bash
   docker logs xscout-analysis-[analysis_id]
   ```

2. Verify the firmware file is accessible and properly mounted

## Cleaning Up

To stop MongoDB and clean up:

```bash
# Stop MongoDB
docker compose down

# Remove MongoDB data volume (caution: this will delete all stored analyses)
docker volume rm xscout_docker_mongodb_data
``` 