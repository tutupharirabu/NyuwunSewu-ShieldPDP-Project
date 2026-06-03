#!/bin/bash
# Start the Phantom webhook receiver
cd /root/NyuwunSewu-ShieldPDP-Project
set -a
source .env
set +a
exec python3 phantom_webhook_receiver.py
