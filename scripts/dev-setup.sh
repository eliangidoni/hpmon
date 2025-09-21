#!/bin/bash
set -e

echo "Setting up HPMon development environment..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker Desktop."
    exit 1
fi

# Build development container
echo "Building development container..."
docker-compose -f docker-compose.dev.yml build

# Set up git pre-push hook
echo "Setting up git pre-push hook..."
mkdir -p .git/hooks

cat > .git/hooks/pre-push << 'EOF'
#!/bin/sh
# Pre-push hook that runs code quality checks
echo "Running code quality checks before push..."
./scripts/dev-check.sh
if [ $? -ne 0 ]; then
    echo "❌ Code quality checks failed. Push aborted."
    echo "Please fix the issues and try again."
    exit 1
fi
echo "✅ Code quality checks passed. Proceeding with push."
EOF

chmod +x .git/hooks/pre-push
echo "Git pre-push hook installed successfully!"

echo "Development environment ready!"
echo "Run 'scripts/dev-start.sh' to start development container"
