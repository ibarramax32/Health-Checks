# 🩺 Wazuh Health Check — Guía Completa Paso a Paso

> **Aplica para:** Wazuh AIO (All-In-One) o componentes individuales (Manager, Indexer, Dashboard)
> 
> **Referencias de la comunidad:** [wazuh/wazuh](https://github.com/wazuh/wazuh), [wazuh/wazuh-indexer](https://github.com/wazuh/wazuh-indexer), [wazuh/integrations](https://github.com/wazuh/integrations)

---

## 📋 FASE 1: Revisión del Servidor (Aplica a TODOS los componentes)

### 1.1 Recursos del Sistema

```bash
# CPU
lscpu

# Memoria RAM
free -h

# Disco
df -h

# Sistema Operativo
cat /etc/*release*
```

### 1.2 Estado de los Servicios

```bash
# Wazuh Manager
systemctl status wazuh-manager
journalctl -u wazuh-manager --no-pager -n 50

# Wazuh Indexer
systemctl status wazuh-indexer
journalctl -u wazuh-indexer --no-pager -n 50

# Wazuh Dashboard
systemctl status wazuh-dashboard
journalctl -u wazuh-dashboard --no-pager -n 50

# Filebeat (en el nodo Manager)
systemctl status filebeat
journalctl -u filebeat --no-pager -n 50
```

### 1.3 Carga del Sistema

```bash
# Carga promedio y uptime
uptime

# Top procesos por CPU/RAM
top -bn1 | head -20

# Procesos de Wazuh corriendo
ps aux | grep -E "wazuh|ossec|filebeat|opensearch|dashboard"

# Conexiones de red activas (puertos clave)
ss -tlnp | grep -E "1514|1515|1516|55000|9200|9300|443|5601"
```

---

## 📋 FASE 2: Wazuh Manager

### 2.1 Versión e Información General

```bash
/var/ossec/bin/wazuh-control info | grep WAZUH_VERSION
cat /var/ossec/etc/ossec-init.conf 2>/dev/null || cat /etc/ossec-init.conf 2>/dev/null
```

### 2.2 Logs de Errores

```bash
# Revisión completa de errores
tail -100 /var/ossec/logs/ossec.log | grep -iE "ERROR|CRITICAL|WARNING"

# Por nivel separado:
tail -100 /var/ossec/logs/ossec.log | grep "ERROR"
tail -100 /var/ossec/logs/ossec.log | grep "CRITICAL"
tail -100 /var/ossec/logs/ossec.log | grep "WARNING"

# Logs de la API
tail -50 /var/ossec/logs/api.log | grep -iE "ERROR|CRITICAL"
```

### 2.3 Estado del Clúster (si aplica)

```bash
/var/ossec/bin/cluster_control -l
/var/ossec/bin/cluster_control -i
```

### 2.4 Espacio en Disco — Logs del Manager

```bash
du -sh /var/ossec/logs/alerts/
du -sh /var/ossec/logs/archives/
du -sh /var/ossec/logs/
find /var/ossec/logs/ -type f -exec ls -lhS {} + | head -20
```

### 2.5 Tareas de Mantenimiento (Crontab)

```bash
crontab -l
```

> **Ejemplo recomendado de limpieza automática (retención 90 días):**
```bash
0 0 * * * find /var/ossec/logs/alerts/ -type f -mtime +90 -exec rm -f {} \;
0 0 * * * find /var/ossec/logs/archives/ -type f -mtime +90 -exec rm -f {} \;
```

### 2.6 Configuración Principal

```bash
cat /var/ossec/etc/ossec.conf
xmllint --noout /var/ossec/etc/ossec.conf 2>&1 || echo "xmllint no instalado, revisar manualmente"
```

---

## 📋 FASE 3: Filebeat (en el nodo Manager)

### 3.1 Conectividad y Configuración

```bash
filebeat test output
cat /etc/filebeat/filebeat.yml
grep "number_of_shards" /etc/filebeat/wazuh-template.json
grep "number_of_replicas" /etc/filebeat/wazuh-template.json
```

> ⚠️ **IMPORTANTE:** El valor de `index.number_of_shards` debe coincidir con el número total de nodos de Indexer.

### 3.2 Certificados

```bash
ls -la /etc/filebeat/certs/
openssl x509 -in /etc/filebeat/certs/filebeat.pem -noout -dates 2>/dev/null
```

---

## 📋 FASE 4: Wazuh Indexer (OpenSearch)

### 4.1 Salud del Clúster

```bash
curl -k -u admin:admin "https://localhost:9200/_cluster/health?pretty"
curl -k -u admin:admin "https://localhost:9200/_cat/health?v"
```

Desde **Dev Tools**:
```
GET _cluster/health
GET _cat/health?v
```

> **Resultado esperado:** `status: green`. Si es `yellow` o `red`, investigar shards.

### 4.2 Revisión de Índices de Alertas (Shards, Tamaño, Réplicas)

```
GET _cat/indices/wazuh-alerts-*?v&h=index,health,status,pri,rep,docs.count,store.size&s=index
```

| Columna | Significado |
|---------|-------------|
| `pri` | **Shards primarios** del índice |
| `rep` | **Réplicas** del índice |
| `docs.count` | Cantidad de documentos |
| `store.size` | **Tamaño** del índice |
| `health` | Estado de salud |

```bash
curl -k -u admin:admin "https://localhost:9200/_cat/shards?v" | wc -l
curl -k -u admin:admin "https://localhost:9200/_cat/shards/wazuh-alerts-*?v"
curl -k -u admin:admin "https://localhost:9200/_cat/indices/wazuh-alerts-*?v&s=store.size:desc"
```

---

## 📋 FASE 4.3: Diagnóstico y Remediación de Unassigned Shards

### 🔍 4.3.1 — Entender el Problema

Un clúster Wazuh Indexer en estado **`yellow`** o **`red`** casi siempre significa **shards sin asignar (unassigned)**.

| Causa Raíz | Descripción | Escenario Típico |
|---|---|---|
| **Réplicas en nodo único** | Por defecto muchos índices se crean con `number_of_replicas: 1`. En un solo nodo no hay dónde colocar la réplica. | AIO / Single Node |
| **ISM History con réplicas** | El ISM crea índices `.opendistro-ism-managed-index-history-*` **con 1 réplica por defecto**, ignorando templates. | Todos los entornos |
| **Job Scheduler Lock** | El índice `.opendistro-job-scheduler-lock` también se crea con réplicas. | Single Node |
| **Templates no aplicados** | Los index templates a veces no se aplican porque tienen prioridad baja o la política ISM los sobreescribe. | Todos |
| **Protección de índices de sistema** | `plugins.security.system_indices.enabled: true` impide modificar réplicas de índices `.opendistro-*`. | Todos |
| **Post-upgrade** | Después de actualizar Wazuh, pueden quedar shards huérfanos de índices incompatibles. | Upgrades 4.x → 4.x |
| **Límite de shards por nodo** | Si se alcanza `cluster.max_shards_per_node`, nuevos shards no se asignan. | Entornos con muchos índices |

> 📖 **Ref:** [wazuh/wazuh-indexer#79](https://github.com/wazuh/wazuh-indexer/issues/79) — Bug confirmado en v4.8.0.

---

### 🔍 4.3.2 — Diagnóstico Paso a Paso

**Paso 1: Verificar estado del clúster**

```bash
curl -k -u admin:admin "https://localhost:9200/_cluster/health?pretty"
```

> 💡 El [health checker oficial de Wazuh](https://github.com/wazuh/integrations/blob/main/integrations/monitoring/monitoring.py) alerta si `unassigned_shards > 0`.

**Paso 2: Listar shards sin asignar**

```bash
curl -k -u admin:admin "https://localhost:9200/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason" | grep UNASSIGNED
```

**Paso 3: Obtener explicación detallada**

```bash
curl -k -u admin:admin "https://localhost:9200/_cluster/allocation/explain?pretty"
```

> 📖 **Ref:** [wazuh/wazuh#28605](https://github.com/wazuh/wazuh/issues/28605) — Output exacto reportado por la comunidad.

**Paso 4: Identificar índices problemáticos**

```
GET _cat/indices?v&health=yellow&s=index
GET _cat/indices?v&health=red&s=index
```

---

### 🛠️ 4.3.3 — Remediación según la Causa

#### 🅰️ Réplicas en entorno Single Node (la más común)

```bash
# Quitar réplicas de TODOS los índices
curl -k -u admin:admin -XPUT "https://localhost:9200/_all/_settings" 
  -H 'Content-Type: application/json' 
  -d '{"index": {"number_of_replicas": 0}}'

# O solo alertas:
curl -k -u admin:admin -XPUT "https://localhost:9200/wazuh-alerts-*/_settings" 
  -H 'Content-Type: application/json' 
  -d '{"index": {"number_of_replicas": 0}}'
```

#### 🅱️ ISM History creando réplicas automáticamente (RECURRENTE)

> ⚠️ **Problema más reportado.** El ISM crea índices de historial **cada día** con 1 réplica.

**Fix definitivo — Configuración persistente:**

```
PUT /_cluster/settings
{
  "persistent": {
    "opendistro": {
      "index_state_management": {
        "history": {
          "number_of_replicas": "0"
        }
      }
    }
  }
}
```

> 📖 **Ref:** [wazuh/wazuh#28605 — Solución confirmada](https://github.com/wazuh/wazuh/issues/28605#issuecomment-2885881987)

**Aplicar a índices ISM existentes:**
```
PUT .opendistro-ism-managed-index-history-*/_settings
{ "index": { "number_of_replicas": 0 } }
```

#### 🅲 Job Scheduler Lock con réplicas

```
PUT .opendistro-job-scheduler-lock/_settings
{ "index": { "number_of_replicas": 0 } }
```

> 📖 **Ref:** [wazuh/wazuh#32815](https://github.com/wazuh/wazuh/issues/32815)

#### 🅳 Protección de índices de sistema impide cambios

Si recibís error `403` o `security_exception`:

1. Editar `/etc/wazuh-indexer/opensearch.yml` — comentar:
```yaml
#plugins.security.system_indices.enabled: true
#plugins.security.system_indices.indices: [...]
```

2. Reiniciar: `systemctl restart wazuh-indexer`
3. Aplicar cambios de réplicas
4. **⚠️ Volver a habilitar** la protección y reiniciar

#### 🅴 Límite de shards por nodo alcanzado

```
GET /_cluster/settings?include_defaults=true&filter_path=defaults.cluster.max_shards_per_node

PUT /_cluster/settings
{ "persistent": { "cluster.max_shards_per_node": "3000" } }
```

#### 🅵 Post-Upgrade / Shards huérfanos

```
POST /_cluster/reroute?retry_failed=true

DELETE wazuh-monitoring-*
DELETE .opendistro-ism-managed-index-history-2024*
```

> 📖 **Ref:** [wazuh/wazuh#29907](https://github.com/wazuh/wazuh/issues/29907), [wazuh/wazuh#32044](https://github.com/wazuh/wazuh/issues/32044)

---

### 🛡️ 4.3.4 — Prevención (Single-Node)

```
PUT /_cluster/settings
{ "persistent": { "opendistro": { "index_state_management": { "history": { "number_of_replicas": "0" } } } } }

PUT _index_template/wazuh-alerts-template
{ "index_patterns": ["wazuh-alerts-*"], "priority": 100, "template": { "settings": { "number_of_replicas": 0, "number_of_shards": 1 } } }

PUT _index_template/security-auditlog-template
{ "index_patterns": ["security-auditlog-*"], "priority": 100, "template": { "settings": { "number_of_replicas": 0 } } }

PUT _index_template/ism-history-template
{ "index_patterns": [".opendistro-ism-managed-index-history-*"], "priority": 200, "template": { "settings": { "number_of_replicas": 0, "auto_expand_replicas": "false" } } }
```

---

### ✅ 4.3.5 — Verificación Post-Remediación

```bash
curl -k -u admin:admin "https://localhost:9200/_cluster/health?pretty" | grep -E "status|unassigned"
curl -k -u admin:admin "https://localhost:9200/_cat/shards?v" | grep UNASSIGNED
curl -k -u admin:admin "https://localhost:9200/_cat/health?v"
```

---

### 📚 Referencias de la Comunidad Wazuh

| Issue | Problema | Solución |
|---|---|---|
| [wazuh-indexer#79](https://github.com/wazuh/wazuh-indexer/issues/79) | Unassigned shards en OVA 4.8.0 | `number_of_replicas: 0` en templates |
| [wazuh#28605](https://github.com/wazuh/wazuh/issues/28605) | ISM history crea réplicas diarias | Cluster settings ISM replicas = 0 |
| [wazuh#32815](https://github.com/wazuh/wazuh/issues/32815) | Job scheduler lock con réplicas | Deshabilitar protección + replicas 0 |
| [wazuh-indexer#1199](https://github.com/wazuh/wazuh-indexer/issues/1199) | ISM policy no aplica replica_count | Forzar via _settings + template alta prioridad |
| [wazuh#29907](https://github.com/wazuh/wazuh/issues/29907) | Dashboard falla post-upgrade | Verificar versiones + reroute |
| [wazuh#32044](https://github.com/wazuh/wazuh/issues/32044) | Indexer roto en upgrade 4.12→4.13 | Limpiar índices + restart |
| [wazuh/integrations](https://github.com/wazuh/integrations/blob/main/integrations/monitoring/monitoring.py) | Health checker automatizado | Script Python con 17 verificaciones |

---

## 📋 FASE 4.4: Configuración del Clúster

```
GET _cluster/settings
GET _cluster/settings?include_defaults=true
```

### Ajuste de Shards y Réplicas

```
PUT /_cluster/settings
{ "persistent": { "cluster.index.number_of_shards": "1" } }

PUT _template/template_1
{ "index_patterns": ["security-auditlog-*"], "settings": { "number_of_replicas": 0 } }
```

### Certificados del Indexer

```bash
ls -la /etc/wazuh-indexer/certs/
openssl x509 -in /etc/wazuh-indexer/certs/indexer.pem -noout -dates
```

---

## 📋 FASE 5: Wazuh Dashboard

```bash
cat /etc/wazuh-dashboard/opensearch_dashboards.yml
ls -la /etc/wazuh-dashboard/certs/
openssl x509 -in /etc/wazuh-dashboard/certs/dashboard.pem -noout -dates
curl -k -I https://localhost:443
```

---

## 📋 FASE 6: Gestión de Agentes (API)

```
GET /manager/info
GET /agents/outdated
PUT /agents/upgrade?agents_list=all&wait_for_complete=true
PUT /agents/upgrade?agents_list=002,003
GET /agents/upgrade_result?agents_list=all

DELETE /agents?status=disconnected&older_than=30d&agents_list=all
DELETE /agents?status=never_connected&older_than=1d&agents_list=all
```

> Script de actualización masiva: [`scripts/upgrade_agents.sh`](scripts/upgrade_agents.sh)

---

## 📋 FASE 7: Registro de Nuevos Agentes

```bash
/var/ossec/bin/agent-auth -m <MANAGER_IP>
/var/ossec/bin/agent-auth -m <MANAGER_IP> -A <nombre_agente>
systemctl restart wazuh-agent
```

---

## 📋 FASE 8: Directorios y Archivos Importantes

| Archivo / Directorio | Descripción |
|---|---|
| `/var/ossec/etc/ossec.conf` | Config principal del Manager |
| `/etc/filebeat/filebeat.yml` | Config de Filebeat |
| `/etc/filebeat/wazuh-template.json` | Template de índices |
| `/usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json` | Pipeline de ingestión |
| `/etc/filebeat/certs/` | Certificados de Filebeat |
| `/etc/wazuh-indexer/opensearch.yml` | Config del Indexer |
| `/etc/wazuh-indexer/certs/` | Certificados del Indexer |
| `/etc/wazuh-dashboard/opensearch_dashboards.yml` | Config del Dashboard |
| `/etc/wazuh-dashboard/certs/` | Certificados del Dashboard |
| `/var/ossec/logs/ossec.log` | Log principal del Manager |
| `/var/ossec/logs/api.log` | Log de la API |
| `/var/ossec/logs/alerts/` | Alertas JSON/log |
| `/var/ossec/logs/archives/` | Archivos de logs completos |

---

## ✅ Checklist Resumen Rápido

| # | Verificación | Comando |
|---|---|---|
| 1 | CPU/RAM/Disco | `lscpu`, `free -h`, `df -h` |
| 2 | Servicios activos | `systemctl status wazuh-*` |
| 3 | Versión Wazuh | `/var/ossec/bin/wazuh-control info` |
| 4 | Errores en logs | `grep -iE "ERROR\|CRITICAL\|WARNING" ossec.log` |
| 5 | Clúster Manager | `/var/ossec/bin/cluster_control -l` |
| 6 | Filebeat → Indexer | `filebeat test output` |
| 7 | Salud del Indexer | `GET _cluster/health` |
| 8 | Shards totales | `GET _cat/shards?v` |
| 9 | Shards de alertas | `GET _cat/shards/wazuh-alerts-*?v` |
| 10 | Tamaño índices alertas | `GET _cat/indices/wazuh-alerts-*?v&s=store.size:desc` |
| 11 | Réplicas de alertas | `GET _cat/indices/wazuh-alerts-*?v&h=index,rep` |
| 12 | Shards no asignados | `GET _cluster/allocation/explain` |
| 13 | Certificados vigentes | `openssl x509 -in <cert> -noout -dates` |
| 14 | Agentes desactualizados | `GET /agents/outdated` |
| 15 | Crontab de limpieza | `crontab -l` |
| 16 | Dashboard accesible | `curl -k -I https://localhost:443` |
| 17 | Conexiones de red | `ss -tlnp` |
| 18 | Carga del sistema | `uptime`, `top` |

---

## 📂 Scripts Incluidos

| Script | Descripción | Uso |
|---|---|---|
| [`scripts/wazuh_shard_diagnostic.sh`](scripts/wazuh_shard_diagnostic.sh) | Diagnóstico completo de shards | `bash scripts/wazuh_shard_diagnostic.sh [user] [pass] [url]` |
| [`scripts/upgrade_agents.sh`](scripts/upgrade_agents.sh) | Actualización masiva de agentes | `bash scripts/upgrade_agents.sh` |

---

> **Mantenido por:** [@ibarramax32](https://github.com/ibarramax32)