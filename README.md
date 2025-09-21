# HPMon

Process monitoring built with eBPF: CPU usage, syscalls, network, i/o, etc.

## Quick Start

### Setup Development Environment
```bash
# Initialize development environment
chmod +x scripts/*.sh
./scripts/dev-setup.sh

# Start development container
./scripts/dev-start.sh

# Inside container - build and test
make all
sudo make test
sudo ./hpmon --help
```

### VS Code Development
1. Install the Dev Containers extension
2. Open project folder in VS Code
3. Select "Reopen in Container" when prompted

## Examples

```bash
# Basic monitoring (requires root privileges in container)
sudo ./hpmon --pid 1234

# Terminal UI mode
sudo ./hpmon -t --pid 1234
```

## Structure

```
hpmon/
├── src/
│   ├── bpf/           # eBPF programs
│   ├── user/          # User-space application
│   └── common/        # Shared utilities
├── include/           # Public headers
├── tests/            # Unit tests
├── scripts/          # Development scripts
├── .devcontainer/    # VS Code Dev Containers
└── Makefile          # Build system
```
