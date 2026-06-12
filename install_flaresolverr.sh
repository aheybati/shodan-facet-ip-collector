#!/bin/bash
# ============================================================
# install_flaresolverr.sh — Abbas Scanner Setup
# Installs Docker + FlareSolverr on a fresh Linux server
# Supports: Ubuntu/Debian, CentOS/RHEL/Rocky, Fedora
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

echo ""
echo "============================================================"
echo "  🔥 FlareSolverr Installer — Abbas Scanner Setup"
echo "============================================================"
echo ""

# ────────────────────────────────────────────────────────────
# 1. Detect OS
# ────────────────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_NAME=$PRETTY_NAME
else
    fail "Cannot detect OS. Only Ubuntu/Debian/CentOS/RHEL/Fedora supported."
fi

info "Detected OS: $OS_NAME"

# ────────────────────────────────────────────────────────────
# 2. Check if Docker is already installed
# ────────────────────────────────────────────────────────────
if command -v docker &>/dev/null; then
    DOCKER_VERSION=$(docker --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
    ok "Docker is already installed (version $DOCKER_VERSION)"
else
    info "Installing Docker..."
    
    # Update packages
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        apt-get update -yqq
        apt-get install -yqq ca-certificates curl gnupg lsb-release
        
        # Add Docker GPG key & repo
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/$ID/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
        chmod a+r /etc/apt/keyrings/docker.gpg
        
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
            https://download.docker.com/linux/$ID $(lsb_release -cs) stable" \
            > /etc/apt/sources.list.d/docker.list
        
        apt-get update -yqq
        apt-get install -yqq docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
    elif [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "rocky" || "$OS" == "almalinux" ]]; then
        yum install -y yum-utils
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        systemctl enable --now docker
        
    elif [[ "$OS" == "fedora" ]]; then
        dnf install -y dnf-plugins-core
        dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
        dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        systemctl enable --now docker
        
    else
        fail "Unsupported OS: $OS"
    fi
    
    ok "Docker installed successfully!"
fi

# Ensure Docker daemon is running
if ! systemctl is-active --quiet docker 2>/dev/null; then
    info "Starting Docker daemon..."
    systemctl start docker
    systemctl enable docker
fi
ok "Docker daemon is running"

# ────────────────────────────────────────────────────────────
# 3. Check if FlareSolverr is already running
# ────────────────────────────────────────────────────────────
if docker ps --format '{{.Names}}' | grep -q 'flaresolverr'; then
    warn "FlareSolverr container is already running!"
    echo ""
    docker ps --filter name=flaresolverr --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
    echo ""
    read -p "Do you want to recreate it? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Removing existing container..."
        docker stop flaresolverr 2>/dev/null || true
        docker rm flaresolverr 2>/dev/null || true
    else
        ok "Keeping existing FlareSolverr. Done!"
        exit 0
    fi
fi

# ────────────────────────────────────────────────────────────
# 4. Pull & Run FlareSolverr
# ────────────────────────────────────────────────────────────
info "Pulling FlareSolverr Docker image..."
docker pull ghcr.io/flaresolverr/flaresolverr:latest

info "Starting FlareSolverr container..."
docker run -d \
    --name=flaresolverr \
    -p 8191:8191 \
    -e LOG_LEVEL=info \
    -e LOG_HTML=false \
    -e CAPTCHA_SOLVER=none \
    --restart unless-stopped \
    ghcr.io/flaresolverr/flaresolverr:latest

ok "FlareSolverr container started!"

# ────────────────────────────────────────────────────────────
# 5. Wait & Health Check
# ────────────────────────────────────────────────────────────
info "Waiting for FlareSolverr to be ready..."
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if curl -s http://localhost:8191/health 2>/dev/null | grep -q "ok"; then
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    printf "  ⏳ %ds\r" $WAITED
done
echo ""

if [ $WAITED -ge $MAX_WAIT ]; then
    warn "FlareSolverr not responding after ${MAX_WAIT}s (might still be starting...)"
    warn "Check logs: docker logs flaresolverr"
else
    ok "FlareSolverr is UP and responding on port 8191!"
fi

# ────────────────────────────────────────────────────────────
# 6. Final Summary
# ────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  ✅ FlareSolverr Installation Complete!"
echo "============================================================"
echo ""
echo "  🌐 API Endpoint:  http://$(hostname -I 2>/dev/null | awk '{print $1}'):8191"
echo "  🌐 Local:         http://localhost:8191"
echo "  📋 Health Check:  curl http://localhost:8191/health"
echo "  📋 View Logs:     docker logs -f flaresolverr"
echo "  📋 Restart:       docker restart flaresolverr"
echo "  📋 Stop:          docker stop flaresolverr"
echo "  📋 Remove:        docker rm -f flaresolverr"
echo ""
echo "  📌 Now run Abbas Scanner:"
echo "     python3 shodan_facet_collector.py -u USER -p PASS -q 'port:\"22\"'"
echo ""
echo "============================================================"
