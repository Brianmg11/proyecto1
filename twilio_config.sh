#!/bin/bash
# twilio_config.sh - Configuracion de credenciales de Twilio

export TWILIO_SID=""
export TWILIO_AUTH_TOKEN=""
export TWILIO_FROM="whatsapp:+14155238886"
export TWILIO_TO="whatsapp:+593986982046"

echo "Variables de Twilio configuradas."
echo "  SID:  ${TWILIO_SID:0:10}..."
echo "  FROM: $TWILIO_FROM"
echo "  TO:   $TWILIO_TO"
