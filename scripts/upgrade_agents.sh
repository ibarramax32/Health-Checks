#!/bin/bash
# ============================================================================
# Wazuh — Mass Agent Upgrade Script
# ============================================================================
# Prerequisito: instalar jq (apt install jq / yum install jq)
#
# Uso: bash upgrade_agents.sh
#
# Configurar las variables de abajo antes de ejecutar.
# ============================================================================

API_USER="wazuh-wui"
API_PASSWORD="wazuh-wui"
MANAGER="<MANAGER_IP_O_HOSTNAME>"

echo -e "\n🔑 Obteniendo token...\n"
TOKEN=$(curl -s -u "$API_USER:$API_PASSWORD" -k -X GET 
  "https://$MANAGER:55000/security/user/authenticate?raw=true")

if [ -z "$TOKEN" ]; then
    echo -e "\n❌ Error: No se pudo obtener el token. Verificar credenciales y conectividad.\n"
    exit 1
fi

echo -e "\n🔍 Buscando agentes desactualizados...\n"
IDs=$(curl -s -k -X GET "https://$MANAGER:55000/agents/outdated" 
  -H "Authorization: Bearer $TOKEN" | 
  jq -r '.data.affected_items | .[] | .id' | head -99 | xargs | sed -e 's/ /,/g')

if [ -z "$IDs" ]; then
    echo -e "\n✅ No hay agentes para actualizar.\n"
else
    echo -e "\n⚠️  Agentes desactualizados: $IDs\n"
    echo -e "\n🚀 Iniciando actualización...\n"
    MESSAGE=$(curl -s -k -X PUT 
      "https://$MANAGER:55000/agents/upgrade?agents_list=$IDs" 
      -H "Authorization: Bearer $TOKEN" | jq -r '.message')
    echo -e "\n📋 Resultado: $MESSAGE\n"

    echo -e "\n⏳ Esperando 30 segundos para verificar resultados...\n"
    sleep 30

    echo -e "\n📊 Estado de la actualización:\n"
    curl -s -k -X GET 
      "https://$MANAGER:55000/agents/upgrade_result?agents_list=$IDs" 
      -H "Authorization: Bearer $TOKEN" | jq '.'.
fi
