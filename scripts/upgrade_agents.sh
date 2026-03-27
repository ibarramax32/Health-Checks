#!/bin/bash
# ============================================================================
# Wazuh - Mass Agent Upgrade Script
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

echo ""
echo "Obteniendo token..."
echo ""
TOKEN=$(curl -s -u "$API_USER:$API_PASSWORD" -k -X GET \
  "https://$MANAGER:55000/security/user/authenticate?raw=true")

if [ -z "$TOKEN" ]; then
    echo ""
    echo "Error: No se pudo obtener el token. Verificar credenciales y conectividad."
    echo ""
    exit 1
fi

echo ""
echo "Buscando agentes desactualizados..."
echo ""
IDs=$(curl -s -k -X GET "https://$MANAGER:55000/agents/outdated" \
  -H "Authorization: Bearer $TOKEN" | \
  jq -r '.data.affected_items | .[] | .id' | head -99 | xargs | sed -e 's/ /,/g')

if [ -z "$IDs" ]; then
    echo ""
    echo "No hay agentes para actualizar."
    echo ""
else
    echo ""
    echo "Agentes desactualizados: $IDs"
    echo ""
    echo "Iniciando actualizacion..."
    echo ""
    MESSAGE=$(curl -s -k -X PUT \
      "https://$MANAGER:55000/agents/upgrade?agents_list=$IDs" \
      -H "Authorization: Bearer $TOKEN" | jq -r '.message')
    echo ""
    echo "Resultado: $MESSAGE"
    echo ""

    echo ""
    echo "Esperando 30 segundos para verificar resultados..."
    echo ""
    sleep 30

    echo ""
    echo "Estado de la actualizacion:"
    echo ""
curl -s -k -X GET \
      "https://$MANAGER:55000/agents/upgrade_result?agents_list=$IDs" \
      -H "Authorization: Bearer $TOKEN" | jq '.'
fi
