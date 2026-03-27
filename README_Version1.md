# 🩺 Wazuh Health Check — Guía Completa Paso a Paso

> **Aplica para:** Wazuh AIO (All-In-One) o componentes individuales (Manager, Indexer, Dashboard)
>
> **Sistema de evaluación:** Cada sección incluye valores esperados para que compares tu output en tiempo real.
>
> | Indicador | Significado |
> |---|---|
> | 🟢 **Bueno** | Sistema saludable, sin acción requerida |
> | 🟡 **Regular** | Requiere atención o monitoreo cercano |
> | 🔴 **Malo** | Acción inmediata requerida |
>
> **Fuentes:** [Wazuh Docs](https://documentation.wazuh.com/current/), [wazuh/wazuh](https://github.com/wazuh/wazuh), [wazuh/wazuh-indexer](https://github.com/wazuh/wazuh-indexer), [OpenSearch Docs](https://opensearch.org/docs/latest/), [Wazuh Indexer Tuning](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-tuning.html)

---

## 📋 FASE 1: Revisión del Servidor (Aplica a TODOS los componentes)

### 1.1 Recursos del Sistema

```bash
# CPU
lscpu
nproc

# Memoria RAM
free -h

# Disco
df -h

# Sistema Operativo
cat /etc/*release*
```

**🔍 ¿Qué esperar? — Valores recomendados por Wazuh Docs:**

| Recurso | Componente | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|---|
| **CPU cores** | Manager | ≥4 cores | 2-3 cores | 1 core |
| **CPU cores** | Indexer | ≥8 cores | 4-7 cores | <4 cores |
| **RAM total** | Manager | ≥8 GB | 4-7 GB | <4 GB |
| **RAM total** | Indexer | ≥16 GB | 8-15 GB | <8 GB |
| **RAM total** | Dashboard | ≥4 GB | 2-3 GB | <2 GB |
| **Disco `/`** | Todos | <75% uso | 75-85% uso | >85% uso |
| **Disco `/var`** | Indexer | <70% uso | 70-85% uso | >85% uso |

> **📖 Fuente:** [Wazuh Installation Requirements](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html) · [Wazuh Indexer Tuning](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-tuning.html)
>
> **💡 Nota:** Si el Indexer tiene <8 GB RAM, el JVM heap será insuficiente y verás problemas de garbage collection. Wazuh recomienda 16 GB mínimo para producción.

---

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

**🔍 ¿Qué esperar? — Output de un servicio sano:**

| Campo en output | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| `Active:` | `active (running)` | `activating` / `reloading` | `inactive (dead)` / `failed` |
| `Loaded:` | `enabled` | `disabled` (no arranca al boot) | `masked` |
| `journalctl` | Sin errores, solo INFO | Warnings esporádicos | `ERROR` / `CRITICAL` repetidos |

> **📖 Fuente:** [wazuh-control reference](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-control.html)
>
> **🟢 Ejemplo de output sano:**
> ```
> ● wazuh-manager.service - Wazuh manager
>    Active: active (running) since Thu 2026-03-27 08:00:01 UTC; 12h ago
> ```
>
> **🔴 Ejemplo de output con problemas:**
> ```
> ● wazuh-manager.service - Wazuh manager
>    Active: failed (Result: exit-code) since Thu 2026-03-27 08:00:01 UTC
> ```

---

### 1.3 Carga del Sistema

```bash
# Carga promedio y uptime
uptime

# Top procesos
top -bn1 | head -20

# Procesos Wazuh específicos
ps aux | grep -E "wazuh|ossec" | grep -v grep
```

**🔍 ¿Qué esperar?**

El comando `uptime` muestra 3 valores de **load average** (1 min, 5 min, 15 min). Compará contra la cantidad de CPU cores (`nproc`):

| Métrica | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| **Load average** (÷ nº cores) | <0.7 | 0.7 – 1.0 | >1.0 por core |
| **CPU % total** (`top`) | <70% | 70-90% | >90% sostenido |
| **RAM usada** (`free -h`) | <80% | 80-90% | >90% |
| **Swap usado** | 0 MB | <500 MB | >500 MB |

> **💡 Ejemplo:** Si tenés 4 cores y load average de `3.2, 2.8, 2.5` → `3.2/4 = 0.8` → 🟡 Regular
>
> **⚠️ Swap:** Si Wazuh está usando swap, el rendimiento cae drásticamente. Si ves swap >0 en un Indexer, es señal de que falta RAM.

---

### 1.4 Daemons Internos de Wazuh

```bash
/var/ossec/bin/wazuh-control status
```

**🔍 ¿Qué esperar? — Daemons de un Manager sano:**

| Daemon | Función | 🟢 Esperado |
|---|---|---|
| `wazuh-analysisd` | Motor de análisis | `is running...` |
| `wazuh-remoted` | Comunicación con agentes | `is running...` |
| `wazuh-syscheckd` | File integrity monitoring | `is running...` |
| `wazuh-logcollector` | Recolección de logs | `is running...` |
| `wazuh-monitord` | Monitoreo de agentes | `is running...` |
| `wazuh-modulesd` | Módulos (vulnerability, SCA) | `is running...` |
| `wazuh-db` | Base de datos | `is running...` |
| `wazuh-execd` | Ejecución de respuestas activas | `is running...` |
| `wazuh-clusterd` | Cluster (si aplica) | `is running...` |
| `wazuh-apid` | API REST | `is running...` |
| `wazuh-authd` | Registro de agentes | `is running...` |

**Daemons que pueden estar detenidos sin ser problema:**

| Daemon | `not running...` es OK si... |
|---|---|
| `wazuh-agentlessd` | No usás monitoreo agentless |
| `wazuh-integratord` | No tenés integraciones (Slack, Virustotal, etc.) |
| `wazuh-dbd` | No usás base de datos externa |
| `wazuh-csyslogd` | No enviás logs a syslog remoto |
| `wazuh-maild` | No tenés alertas por correo |

> **📖 Fuente:** [wazuh-control](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-control.html)
>
> **🔴 Alerta:** Si `wazuh-analysisd`, `wazuh-remoted` o `wazuh-db` están detenidos → el Manager NO está procesando eventos.

---

## 🔧 FASE 2: Wazuh Manager — Health Check Profundo

### 2.1 Versión y Configuración

```bash
/var/ossec/bin/wazuh-control info
cat /var/ossec/etc/ossec.conf | head -50
```

**🔍 ¿Qué esperar?**
- La versión debe coincidir con la del Indexer y Dashboard (mismatch de versiones causa problemas).
- El `ossec.conf` debe ser XML válido.

| Verificación | 🟢 Bueno | 🔴 Malo |
|---|---|---|
| Versión Manager = Indexer = Dashboard | Todas iguales (ej: `4.9.0`) | Versiones diferentes |
| `ossec.conf` sin errores XML | Se muestra correctamente | Errores de parsing |

---

### 2.2 Logs del Manager

```bash
# Últimos errores
grep -iE "error|critical|warning" /var/ossec/logs/ossec.log | tail -30

# Logs del cluster (si aplica)
grep -iE "error|critical" /var/ossec/logs/cluster.log | tail -20

# Tamaño de logs
du -sh /var/ossec/logs/
ls -lah /var/ossec/logs/ossec.log
```

**🔍 ¿Qué esperar?**

| Métrica | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| Errores en `ossec.log` | 0 ERROR/CRITICAL en últimas 24h | Warnings esporádicos | ERROR/CRITICAL repetidos |
| Tamaño de `ossec.log` | <500 MB | 500 MB – 1 GB | >1 GB (rotación rota) |
| Tamaño `/var/ossec/logs/` | <2 GB | 2-5 GB | >5 GB |

**Errores comunes que son "normales" (no alarmarse):**
```
# Estos mensajes son informativos y no indican problemas:
WARNING: Cluster synchronization timeout (occasional)
wazuh-remoted: INFO: Agent 'XXX' disconnected
```

**Errores que SÍ requieren acción inmediata:**
```
# 🔴 Estos sí son problemas reales:
ERROR: Cannot connect to database
CRITICAL: wazuh-analysisd: Event queue is full
ERROR: Could not connect to the cluster
```

> **📖 Fuente:** [Wazuh Logging](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/logging.html)

---

### 2.3 Estado del Cluster (si aplica)

```bash
# Listar nodos del cluster
/var/ossec/bin/cluster_control -l

# Info del cluster
/var/ossec/bin/cluster_control -i

# Salud del cluster
/var/ossec/bin/cluster_control -l -a
```

**🔍 ¿Qué esperar?**

| Campo | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| `Type` | `master` + `worker(s)` presentes | — | Falta el master o workers |
| `Status` de cada nodo | `connected` | `disconnected` temporal (<5 min) | `disconnected` persistente |
| `Version` de cada nodo | Todas iguales | — | Versiones diferentes |

> **🟢 Ejemplo de output sano:**
> ```
>   Name       Type    Version  Address        Status
>   master01   master  4.9.0    10.0.0.1       connected
>   worker01   worker  4.9.0    10.0.0.2       connected
>   worker02   worker  4.9.0    10.0.0.3       connected
> ```
>
> **📖 Fuente:** [cluster_control](https://documentation.wazuh.com/current/user-manual/reference/tools/cluster-control.html)

---

### 2.4 Agentes Conectados

```bash
# Resumen de agentes
/var/ossec/bin/agent_control -l | head -30

# Contar por estado
/var/ossec/bin/agent_control -l | grep -c "Active"
/var/ossec/bin/agent_control -l | grep -c "Disconnected"
/var/ossec/bin/agent_control -l | grep -c "Never connected"

# Vía API
curl -s -k -u "wazuh-wui:wazuh-wui" \
  "https://localhost:55000/agents/summary/status?pretty"
```

**🔍 ¿Qué esperar?**

| Métrica | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| % Agentes `Active` | >95% | 80-95% | <80% |
| Agentes `Disconnected` | 0 | <5% del total | >5% del total |
| Agentes `Never connected` | 0 | 1-3 (recién registrados) | Muchos (problema de despliegue) |
| Agentes por Manager/Worker | <3,000 por nodo | 3,000-5,000 | >5,000 por nodo |

> **📖 Fuente:** [Wazuh Agent Management](https://documentation.wazuh.com/current/user-manual/agent/agent-management.html)
>
> **💡 Nota:** Cada Manager/Worker puede manejar ~3,000-5,000 agentes dependiendo del hardware. Si superás este número, considerá agregar Workers al cluster.

---

### 2.5 Cola de Eventos (Event Queue)

```bash
# Verificar estado del análisis
/var/ossec/bin/wazuh-control info

# Buscar señales de cola llena
grep -i "queue" /var/ossec/logs/ossec.log | tail -10
grep -i "event queue is full" /var/ossec/logs/ossec.log
```

**🔍 ¿Qué esperar?**

| Métrica | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| Mensajes "queue is full" | 0 | Esporádico (picos de carga) | Frecuente / constante |
| EPS (eventos por segundo) procesados | Estable | Fluctuante | Cayendo o 0 |

> **⚠️ "Event queue is full"** significa que `wazuh-analysisd` no puede procesar eventos tan rápido como llegan. Soluciones:
> - Aumentar `analysisd.event_queue_size` en `ossec.conf`
> - Agregar más CPU al Manager
> - Distribuir agentes en más Workers

---

## 🗄️ FASE 3: Wazuh Indexer — Health Check Profundo

### 3.1 Salud del Cluster del Indexer

```bash
# Salud general
curl -sk -u admin:admin "https://localhost:9200/_cluster/health?pretty"

# Nodos del cluster
curl -sk -u admin:admin "https://localhost:9200/_cat/nodes?v"

# Estadísticas del cluster
curl -sk -u admin:admin "https://localhost:9200/_cluster/stats?pretty" | head -50
```

**🔍 ¿Qué esperar? — El campo `status` es el más crítico:**

| Campo | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| `status` | `green` | `yellow` | `red` |
| `number_of_nodes` | = nodos esperados | — | Menor al esperado |
| `active_primary_shards` | Todas activas | — | Menor al esperado |
| `unassigned_shards` | `0` | 1-5 | >5 |
| `relocating_shards` | `0` | >0 (temporal OK) | >0 persistente |
| `active_shards_percent` | `100.0%` | >90% | <90% |

**Significado de cada estado:**
- 🟢 **`green`**: Todos los shards primarios y réplicas están activos. **Estado ideal.**
- 🟡 **`yellow`**: Los primarios están bien, pero algunas réplicas no están asignadas. Datos accesibles pero sin redundancia completa. **Aceptable en single-node.**
- 🔴 **`red`**: Uno o más shards primarios no están activos. **Posible pérdida de datos. Acción inmediata.**

> **🟢 Ejemplo de output sano:**
> ```json
> {
>   "cluster_name": "wazuh-cluster",
>   "status": "green",
>   "number_of_nodes": 3,
>   "active_primary_shards": 45,
>   "active_shards": 90,
>   "relocating_shards": 0,
>   "unassigned_shards": 0,
>   "active_shards_percent_as_number": 100.0
> }
> ```
>
> **📖 Fuente:** [Wazuh Indexer Cluster Management](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/cluster-management.html) · [OpenSearch Cluster Health API](https://opensearch.org/docs/latest/api-reference/cluster-health/)

---

### 3.2 JVM Heap Memory

```bash
# Uso de heap por nodo
curl -sk -u admin:admin "https://localhost:9200/_cat/nodes?v&h=name,heap.percent,heap.current,heap.max,ram.percent,cpu"

# Detalle del JVM
curl -sk -u admin:admin "https://localhost:9200/_nodes/stats/jvm?pretty" | grep -A5 "heap"
```

**🔍 ¿Qué esperar?**

| Métrica | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| `heap.percent` | <75% | 75-85% | >85% |
| `heap.max` | ≤32 GB y ≥4 GB | <4 GB | >32 GB (pierde compressed oops) |
| `ram.percent` (nodo) | <85% | 85-90% | >90% |
| `cpu` (nodo) | <70% | 70-85% | >85% sostenido |

**Configuración recomendada del Heap:**
| RAM del servidor | `heap.max` recomendado | Regla |
|---|---|---|
| 8 GB | 4 GB | 50% de RAM |
| 16 GB | 8 GB | 50% de RAM |
| 32 GB | 16 GB | 50% de RAM |
| 64 GB+ | 32 GB (máx) | Nunca >32 GB |

> **📖 Fuente:** [Wazuh Indexer Tuning](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-tuning.html)
>
> **⚠️ Si `heap.percent` está >85% constantemente:**
> - Aumentar la RAM del servidor
> - Ajustar `-Xms` y `-Xmx` en `/etc/wazuh-indexer/jvm.options`
> - Reducir el número de shards o cerrar índices antiguos
>
> **⚠️ Si `heap.max` >32 GB:** El JVM pierde la optimización de "compressed ordinary object pointers" y el rendimiento CAE.

---

### 3.3 Disco y Watermarks

```bash
# Espacio por nodo
curl -sk -u admin:admin "https://localhost:9200/_cat/allocation?v&s=node"

# Configuración de watermarks actual
curl -sk -u admin:admin "https://localhost:9200/_cluster/settings?include_defaults=true&pretty" | grep -A3 "watermark"

# Disco del SO
df -h /var/lib/wazuh-indexer/
```

**🔍 ¿Qué esperar? — Disk Watermarks (valores por defecto de OpenSearch):**

| Watermark | Umbral Default | Qué pasa | Evaluación |
|---|---|---|---|
| **Low** | 85% usado | ⚠️ No asigna nuevos shards al nodo | 🟡 Atención |
| **High** | 90% usado | ⚠️ Reubica shards fuera del nodo | 🟡 Riesgo |
| **Flood stage** | 95% usado | 🛑 Índices pasan a read-only | 🔴 Crítico |

| Métrica de disco | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| Uso disco del Indexer | <75% | 75-85% | >85% |
| Espacio libre absoluto | >50 GB | 20-50 GB | <20 GB |

> **📖 Fuente:** [OpenSearch Disk Watermarks](https://opensearch.org/docs/latest/install-and-configure/configuring-opensearch/cluster-settings/)
>
> **💡 Si llegaste a flood stage (95%):**
> ```bash
> # Desbloquear índices después de liberar espacio:
> curl -sk -u admin:admin -X PUT "https://localhost:9200/_all/_settings" \
>   -H 'Content-Type: application/json' \
>   -d '{"index.blocks.read_only_allow_delete": null}'
> ```

---

### 3.4 Shards — Conteo y Estado

```bash
# Resumen de shards
curl -sk -u admin:admin "https://localhost:9200/_cat/shards?v&s=state" | head -50

# Solo los NO asignados
curl -sk -u admin:admin "https://localhost:9200/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason" | grep UNASSIGNED

# Conteo rápido
echo "Total shards: $(curl -sk -u admin:admin 'https://localhost:9200/_cat/shards' 2>/dev/null | wc -l)"
echo "Unassigned:   $(curl -sk -u admin:admin 'https://localhost:9200/_cat/shards' 2>/dev/null | grep -c UNASSIGNED)"
```

**🔍 ¿Qué esperar?**

| Métrica | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| Shards `UNASSIGNED` | 0 | 1-5 (réplicas en single-node es normal) | >5 o primarios sin asignar |
| Shards por nodo | <1,000 | 1,000-1,500 | >1,500 |
| Shards por GB de heap | <20 | 20-30 | >30 |

**Razones comunes de `UNASSIGNED`:**
| Razón | Significado | Severidad |
|---|---|---|
| `INDEX_CREATED` | Réplica sin nodo destino (single-node) | 🟡 Normal en AIO |
| `CLUSTER_RECOVERED` | Recuperando tras reinicio | 🟡 Temporal |
| `NODE_LEFT` | Un nodo salió del cluster | 🔴 Investigar |
| `ALLOCATION_FAILED` | Fallo de asignación (disco lleno, etc.) | 🔴 Investigar |

> **📖 Fuente:** [Wazuh Indexer Cluster](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/index.html)
>
> **💡 En instalación AIO (single-node):** Es NORMAL ver `yellow` y shards réplica como `UNASSIGNED` porque no hay otro nodo donde colocarlas. Para silenciar esto:
> ```bash
> curl -sk -u admin:admin -X PUT "https://localhost:9200/_settings" \
>   -H 'Content-Type: application/json' \
>   -d '{"index.number_of_replicas": 0}'
> ```

---

### 3.5 Índices — Tamaño y Estado

```bash
# Listar índices con tamaño
curl -sk -u admin:admin "https://localhost:9200/_cat/indices?v&s=index" | head -30

# Solo índices de Wazuh
curl -sk -u admin:admin "https://localhost:9200/_cat/indices/wazuh-*?v&s=index"

# ISM (Index State Management) policy
curl -sk -u admin:admin "https://localhost:9200/_opendistro/_ism/explain/wazuh-alerts-*?pretty" | head -30
```

**🔍 ¿Qué esperar?**

| Métrica | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| Estado de índices | Todos `open` / `green` | Algunos `yellow` | Alguno `red` o `close` inesperado |
| Tamaño por índice diario | <10 GB | 10-30 GB | >30 GB (demasiados eventos o logs) |
| Índices totales | <100 | 100-300 | >300 (considerar ISM/rollover) |
| ISM policy activa | `wazuh` policy aplicada | Sin policy (no hay rotación automática) | Policy en error |

> **📖 Fuente:** [Wazuh Indexer Cluster Management](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/cluster-management.html)

---

## 📡 FASE 4: Filebeat — Health Check

### 4.1 Estado y Conectividad

```bash
# Estado del servicio
systemctl status filebeat

# Test de output (conectividad al Indexer)
filebeat test output

# Test de configuración
filebeat test config
```

**🔍 ¿Qué esperar?**

| Verificación | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| `systemctl status` | `active (running)` | `activating` | `failed` / `inactive` |
| `filebeat test output` | Todos los hosts `OK` / `talk to server... OK` | Retries / timeouts | `connection refused` / `certificate` errors |
| `filebeat test config` | `Config OK` | — | `Config error` |

> **🟢 Ejemplo de output sano de `filebeat test output`:**
> ```
> elasticsearch: https://127.0.0.1:9200...
>   parse url... OK
>   connection... OK
>   TLS... OK
>   talk to server... OK
>   version: 7.10.2
> ```

---

### 4.2 Cola y Rendimiento de Filebeat

```bash
# Verificar logs de filebeat
grep -iE "error|warn|dropping" /var/log/filebeat/filebeat | tail -20

# Verificar métricas internas
grep -i "harvester\|output\|queue\|pipeline" /var/log/filebeat/filebeat | tail -20
```

**🔍 ¿Qué esperar?**

| Métrica | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| `events.active` (en cola) | <30% de `queue.mem.events` (default 4096) | 30-70% | >70% constantemente |
| `events.dropped` | 0 | Esporádico | Frecuente |
| Errores de conexión al Indexer | 0 | Retries esporádicos | `connection refused` constante |
| EPS procesados | Estable y >0 | Fluctuante | 0 o cayendo |

> **📖 Fuente:** [Wazuh Filebeat Configuration](https://documentation.wazuh.com/current/user-manual/manager/wazuh-server-cluster.html)
>
> **💡 Si ves "dropping events":** Significa que Filebeat no puede enviar al Indexer tan rápido como recibe. Posibles causas:
> - Indexer saturado (verificar heap y disco)
> - Red lenta entre Manager e Indexer
> - Aumentar `queue.mem.events` en `filebeat.yml`

---

## 🔐 FASE 5: Certificados SSL/TLS

### 5.1 Verificar Expiración

```bash
# Certificados del Indexer
openssl x509 -enddate -noout -in /etc/wazuh-indexer/certs/wazuh-indexer.pem

# Certificados del Manager
openssl x509 -enddate -noout -in /var/ossec/etc/sslmanager.cert

# Certificados del Dashboard
openssl x509 -enddate -noout -in /etc/wazuh-dashboard/certs/wazuh-dashboard.pem

# Ver todos los detalles
openssl x509 -text -noout -in /etc/wazuh-indexer/certs/wazuh-indexer.pem | head -20
```

**🔍 ¿Qué esperar?**

| Métrica | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| Días hasta expiración | >90 días | 30-90 días | <30 días |
| Certificado expirado | No | — | Sí (servicios fallarán) |
| CN/SAN del certificado | Coincide con hostname/IP | — | No coincide (errores TLS) |

> **⚠️ Si un certificado expira:** Wazuh dejará de comunicarse entre componentes. Los agentes perderán conexión.
>
> **💡 Comando para ver días restantes:**
> ```bash
> CERT="/etc/wazuh-indexer/certs/wazuh-indexer.pem"
> EXPIRY=$(openssl x509 -enddate -noout -in "$CERT" | cut -d= -f2)
> DAYS=$(( ( $(date -d "$EXPIRY" +%s) - $(date +%s) ) / 86400 ))
> echo "Días restantes: $DAYS"
> ```

---

## 🌐 FASE 6: Wazuh API — Health Check

### 6.1 Conectividad y Respuesta

```bash
# Obtener token
TOKEN=$(curl -s -u "wazuh-wui:wazuh-wui" -k \
  "https://localhost:55000/security/user/authenticate?raw=true")

# Health check de la API
curl -s -k -X GET "https://localhost:55000/?pretty" \
  -H "Authorization: Bearer $TOKEN"

# Resumen de agentes vía API
curl -s -k -X GET "https://localhost:55000/agents/summary/status?pretty" \
  -H "Authorization: Bearer $TOKEN"

# Info del Manager vía API
curl -s -k -X GET "https://localhost:55000/manager/info?pretty" \
  -H "Authorization: Bearer $TOKEN"
```

**🔍 ¿Qué esperar?**

| Verificación | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| Obtener token | Token recibido (string largo) | Lento (>5s) | `Error` / vacío |
| `GET /` responde | HTTP 200, muestra versión | Respuesta lenta | Connection refused / 500 |
| `GET /agents/summary/status` | JSON con conteos | — | Error o vacío |
| Tiempo de respuesta | <2 segundos | 2-5 segundos | >5 segundos |

> **📖 Fuente:** [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)

---

## 🔬 FASE 7: Wazuh Dashboard — Health Check

### 7.1 Verificar Servicio y Acceso

```bash
# Estado del servicio
systemctl status wazuh-dashboard

# Verificar puerto
ss -tlnp | grep 443

# Test de conectividad
curl -sk -o /dev/null -w "%{http_code}" "https://localhost:443"
```

**🔍 ¿Qué esperar?**

| Verificación | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| `systemctl status` | `active (running)` | `activating` | `failed` / `inactive` |
| Puerto 443 escuchando | `LISTEN` | — | No aparece |
| HTTP status code | `302` (redirect a login) | `200` | `502` / `503` / connection refused |

---

## 📊 FASE 8: Verificación End-to-End

### 8.1 Test de Flujo Completo

```bash
# Generar alerta de prueba desde el Manager
/var/ossec/bin/wazuh-logtest <<< '{"message":"test health check alert"}'

# Verificar que llegó al Indexer (esperar ~30 segundos)
curl -sk -u admin:admin \
  "https://localhost:9200/wazuh-alerts-*/_search?pretty&size=1&sort=timestamp:desc" | head -30

# Verificar que Filebeat está reenviando
grep -c "events" /var/log/filebeat/filebeat 2>/dev/null | tail -1
```

**🔍 ¿Qué esperar?**

| Verificación | 🟢 Bueno | 🟡 Regular | 🔴 Malo |
|---|---|---|---|
| `wazuh-logtest` | Responde con análisis | Lento | No responde o error |
| Alerta en Indexer | Aparece en <60s | Tarda 1-5 min | No aparece |
| Filebeat reenviando | Conteo de events creciendo | Estancado | 0 o decreciendo |

> **💡 Si la alerta no llega al Indexer:** El problema está en la cadena `Manager → Filebeat → Indexer`. Revisá:
> 1. Filebeat: `filebeat test output`
> 2. Indexer: `_cluster/health` (¿acepta escritura?)
> 3. Certificados: ¿Son válidos entre Filebeat e Indexer?

---

## 🛠️ Scripts de Diagnóstico Automatizado

Este repositorio incluye scripts listos para usar:

| Script | Descripción | Uso |
|---|---|---|
| [`scripts/upgrade_agents.sh`](scripts/upgrade_agents.sh) | Actualización masiva de agentes | `bash upgrade_agents.sh` |
| [`scripts/wazuh_shard_diagnostic.sh`](scripts/wazuh_shard_diagnostic.sh) | Diagnóstico completo de shards | `bash wazuh_shard_diagnostic.sh [user] [pass] [url]` |

---

## 📚 Referencias y Fuentes

| Recurso | URL |
|---|---|
| Wazuh Documentation (Oficial) | https://documentation.wazuh.com/current/ |
| Wazuh Indexer Tuning | https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-tuning.html |
| Wazuh Cluster Management | https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/cluster-management.html |
| wazuh-control Reference | https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-control.html |
| cluster_control Reference | https://documentation.wazuh.com/current/user-manual/reference/tools/cluster-control.html |
| OpenSearch Cluster Health API | https://opensearch.org/docs/latest/api-reference/cluster-health/ |
| OpenSearch Disk Watermarks | https://opensearch.org/docs/latest/install-and-configure/configuring-opensearch/cluster-settings/ |
| Wazuh API Reference | https://documentation.wazuh.com/current/user-manual/api/reference.html |
| Wazuh GitHub (Community) | https://github.com/wazuh/wazuh |
| Wazuh Indexer GitHub | https://github.com/wazuh/wazuh-indexer |

---

> **Última actualización:** 2026-03-27
>
> **Autor:** @ibarramax32
>
> **Licencia:** Uso libre para la comunidad Wazuh 🤝