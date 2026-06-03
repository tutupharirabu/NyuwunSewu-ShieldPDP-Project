#!/bin/bash
# Setup and run script for NyuwunSewu + Phantom Agent Integration
set -e

echo "🚀 NyuwunSewu + Phantom Agent Integration Setup"
echo "=" * 50

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

cd /root/NyuwunSewu-ShieldPDP-Project

echo -e "\n${BLUE}1. Checking prerequisites...${NC}"
if ! command -v python3 &> /dev/null; then
    echo "❌ python3 not found"
    exit 1
fi
echo "✅ python3: $(python3 --version)"

if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found. Run: python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi
echo "✅ Virtual environment ready"

echo -e "\n${BLUE}2. Environment setup...${NC}"
if [ ! -f ".env" ]; then
    echo "❌ .env file not found. Copy from .env.example and configure."
    exit 1
fi

# Check for AGENT_SECRET
if grep -q "AGENT_SECRET" .env; then
    echo "✅ AGENT_SECRET configured"
else
    echo "⚠️  AGENT_SECRET not set in .env"
    echo "   Add: AGENT_SECRET=your-secret-here"
fi

echo -e "\n${BLUE}3. Starting NyuwunSewu server...${NC}"
echo "   Server will start on http://127.0.0.1:8000"
echo "   API docs: http://127.0.0.1:8000/docs"

# Start server in background
DATABASE_URL=sqlite+aiosqlite:///./nyuwunsewu_prod.db \
ALLOW_PRIVATE_TARGETS=true \
USE_CELERY=false \
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 &
SERVER_PID=$!

echo "   Server PID: $SERVER_PID"

# Wait for server to be ready
echo "   Waiting for server to start..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Server is healthy!${NC}"
        break
    fi
    sleep 2
done

echo -e "\n${BLUE}4. Starting Phantom webhook receiver...${NC}"
echo "   Receiver will listen on port 8080"

# Load environment from .env file
set -a
source .env
set +a

# Verify required variables are set
REQUIRED_VARS=(PHANTOM_WEBHOOK_SECRET PHANTOM_AGENT_SECRET ADMIN_PASSWORD)
MISSING=()
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        MISSING+=("$var")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "❌ Missing required environment variables: ${MISSING[*]}"
    echo "   Please set them in .env file"
    exit 1
fi

python3 phantom_webhook_receiver.py &
WEBHOOK_PID=$!

echo "   Webhook receiver PID: $WEBHOOK_PID"
sleep 3

echo -e "\n${GREEN}✅ Integration running!${NC}"
echo ""
echo "NyuwunSewu server:  http://127.0.0.1:8000"
echo "API docs:           http://127.0.0.1:8000/docs"
echo "Webhook receiver:   http://127.0.0.1:8080"
echo ""
echo "PIDs to kill: $SERVER_PID $WEBHOOK_PID"
echo "Press Ctrl+C to stop"

# Wait for processes
wait $SERVER_PID $WEBHOOK_PID
