#!/bin/bash
# ============================================================================
# Wazuh Indexer - Shard Diagnostic Script
# ============================================================================
# Uso: bash wazuh_shard_diagnostic.sh [usuario] [password] [url_indexer]
#
# Defaults: admin / admin / https://localhost:9200
# ============================================================================

USER="${1:-admin}"
PASS="${2:-admin}"
URL="${3:-https://localhost:9200}"
CURL="curl -sk -u $USER:$PASS"

echo "============================================="
echo "  WAZUH INDEXER - SHARD DIAGNOSTIC"
echo "  $(date)"
echo "============================================="

echo ""
echo "1. SALUD DEL CLUSTER"
echo "---------------------------------------------"
$CURL "$URL/_cluster/health?pretty"

echo ""
echo "2. SHARDS TOTALES vs NO ASIGNADOS"
echo "---------------------------------------------"
TOTAL=$($CURL "$URL/_cat/shards" 2>/dev/null | wc -l)
UNASSIGNED=$($CURL "$URL/_cat/shards" 2>/dev/null | grep -c UNASSIGNED)
echo "  Shards totales:      $TOTAL"
echo "  Shards sin asignar:  $UNASSIGNED"

echo ""
echo "3. DETALLE DE SHARDS SIN ASIGNAR"
echo "---------------------------------------------"
UNASSIGNED_OUTPUT=$($CURL "$URL/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason" 2>/dev/null | grep UNASSIGNED)
if [ -z "$UNASSIGNED_OUTPUT" ]; then
    echo "  No hay shards sin asignar"
else
    echo "$UNASSIGNED_OUTPUT"
fi

echo ""
echo "4. INDICES EN ESTADO YELLOW o RED"
echo "---------------------------------------------"
YELLOW=$($CURL "$URL/_cat/indices?v&health=yellow&s=index" 2>/dev/null)
RED=$($CURL "$URL/_cat/indices?v&health=red&s=index" 2>/dev/null)
if [ -n "$YELLOW" ]; then
    echo "  YELLOW:"
    echo "$YELLOW"
fi
if [ -n "$RED" ]; then
    echo "  RED:"
    echo "$RED"
fi
if [ -z "$YELLOW" ] && [ -z "$RED" ]; then
    echo "  Todos los indices estan en GREEN"
fi

echo ""
echo "5. EXPLICACION DE ALLOCATION (primer shard sin asignar)"
echo "---------------------------------------------"
if [ "$UNASSIGNED" -gt 0 ]; then
    $CURL "$URL/_cluster/allocation/explain?pretty" 2>/dev/null
else
    echo "  No aplica - no hay shards sin asignar"
fi

echo ""
echo "6. DETALLE DE INDICES DE ALERTAS"
echo "---------------------------------------------"
$CURL "$URL/_cat/indices/wazuh-alerts-*?v&h=index,health,pri,rep,docs.count,store.size&s=index" 2>/dev/null

echo ""
echo "7. MAX SHARDS PER NODE"
echo "---------------------------------------------"
$CURL "$URL/_cluster/settings?include_defaults=true&filter_path=defaults.cluster.max_shards_per_node&pretty" 2>/dev/null

echo ""
echo "8. CONFIGURACION ISM HISTORY REPLICAS"
echo "---------------------------------------------"
$CURL "$URL/_cluster/settings?pretty&filter_path=persistent.opendistro" 2>/dev/null

echo ""
echo "9. TEMPLATES CON REPLICAS CONFIGURADAS"
echo "---------------------------------------------"
$CURL "$URL/_index_template?pretty" 2>/dev/null | grep -B2 -A2 "number_of_replicas"

echo ""
echo "============================================="
if [ "$UNASSIGNED" -gt 0 ]; then
    echo "  RESULTADO: $UNASSIGNED shards sin asignar"
    echo "  Revisar la guia de remediacion en README.md"
else
    echo "  RESULTADO: Cluster saludable"
fi
echo "=============================================
