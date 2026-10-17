# infra-mcp

MCP-Server für die Infrastruktur: **Portainer** (Container und Stacks) und **Nginx Proxy Manager** (Proxy-Hosts und Zertifikate) in einem Dienst.

Läuft ausschliesslich als Docker-Container (Stack in Portainer) mit Streamable-HTTP-Transport und wird nur als Custom Connector in Claude genutzt. Kein lokaler Betrieb, kein `uvx`, kein stdio.

Hauptfälle:

- neue Dienste (z.B. weitere MCP-Server) komplett veröffentlichen: Stack, Proxy-Host, Let's-Encrypt-Zertifikat, HTTPS-Test
- Updates nach einem neuen ghcr-Image ausrollen
- Fehler anhand von Logs und Status analysieren
- Ressourcen des Docker-Hosts abfragen (CPU, RAM, Disk) inkl. 24-h-Verlauf von CPU und RAM

Dieses Repo ist **öffentlich**: Code, README, Tests und Beispiele enthalten keine echten Hostnamen, IPs, Zugangsdaten oder Firmendaten - nur Platzhalter wie `portainer.example.com`, `npm.example.com`, `app.example.com` oder `203.0.113.10`. Echte Werte gehören ausschliesslich in die Stack-Variablen in Portainer.

## Aufbau

| Datei | Inhalt |
|---|---|
| `infra_mcp/server.py` | HTTP-Transport, Bearer-Auth, Start |
| `infra_mcp/app.py` | MCPServer-Instanz, Tool-Registrierung mit Audit-Log |
| `infra_mcp/portainer_client.py` | Portainer-API-Client, Log-Demux, Stats |
| `infra_mcp/npm_client.py` | NPM-API-Client mit Token-Cache und -Erneuerung |
| `infra_mcp/tools_portainer.py` | `portainer_*`-Tools |
| `infra_mcp/tools_npm.py` | `npm_*`-Tools |
| `infra_mcp/tools_workflow.py` | `infra_*`-Tools (kombinierte Abläufe) |
| `infra_mcp/guard.py` | Schutzlisten, confirm-Logik, Schwärzung, Compose-Prüfung |
| `infra_mcp/netcheck.py` | DNS-Vorabprüfung, HTTPS-Test |
| `infra_mcp/metrics.py` | Host-Ressourcen über node-exporter, 24-h-Verlauf |
| `infra_mcp/config.py`, `version.py`, `audit.py` | Env-Konfiguration, Version, JSON-Audit-Log |

Python, `mcp` (MCPServer, die FastMCP-API des offiziellen SDK 2.x), nur HTTP. Kein `pyproject.toml`, keine Paketierung: Abhängigkeiten gepinnt in `requirements.txt`, Start im Dockerfile per `python -m infra_mcp`.

## Tools

Alle schreibenden Tools führen nur mit `confirm=true` aus. Ohne `confirm` liefern sie eine Vorschau (Payload bzw. Diff und betroffene Objekte) und ändern nichts. Geschützte Container, Stacks und Domains werden auch in der Vorschau blockiert.

### Portainer - lesend

| Tool | Beschreibung |
|---|---|
| `portainer_version` | Portainer-Version |
| `portainer_endpoint_list` | Umgebungen (Endpoints) |
| `portainer_container_list(endpoint_id, all=true, filter_name)` | Container mit Status, Image, Stack, Ports |
| `portainer_container_inspect(endpoint_id, container)` | Status, Image, Ports, Mounts, RestartPolicy, Health, Networks. Env nur Variablennamen |
| `portainer_container_logs(endpoint_id, container, tail=200, since, grep)` | stdout+stderr, ohne TTY korrekt demultiplext (8-Byte-Header), lange Ausgaben vorne gekürzt |
| `portainer_container_stats(endpoint_id, container)` | CPU-%, RAM genutzt/Limit, Netzwerk |
| `portainer_stack_list` | Stacks mit Typ, Status, Git-Quelle, Env-Namen |
| `portainer_stack_file(stack_id)` | Compose-Datei, Werte mit PASSWORD/TOKEN/KEY/SECRET im Namen geschwärzt |
| `portainer_image_list`, `portainer_volume_list`, `portainer_network_list` | je `endpoint_id` |

### Portainer - schreibend

| Tool | Beschreibung |
|---|---|
| `portainer_container_action(endpoint_id, container, action, confirm)` | `start`, `stop`, `restart` |
| `portainer_stack_redeploy(stack_id, pull_image=true, confirm)` | Compose: `PUT /api/stacks/{id}` mit bestehendem StackFileContent und Env, `PullImage`, `Prune=false`. Git: `PUT /api/stacks/{id}/git/redeploy` |
| `portainer_stack_start` / `portainer_stack_stop(stack_id, confirm)` | Stack starten/stoppen (nichts wird gelöscht) |
| `portainer_stack_create(name, endpoint_id, compose_content, env, allow_docker_socket=false, confirm)` | Neuer Compose-Stack. Vorher geprüft: YAML gültig, keine `privileged`-Container, kein Docker-Socket-Mount ohne `allow_docker_socket=true`, Name frei |

### NPM - lesend

| Tool | Beschreibung |
|---|---|
| `npm_version` | NPM-Version (`GET /api/`) |
| `npm_proxy_host_list(filter)` | id, Domains, Forward-Ziel, enabled, Zertifikat inkl. Ablauf, ssl_forced |
| `npm_proxy_host_get(id_or_domain)` | Ein Proxy-Host mit allen Einstellungen, `advanced_config` geschwärzt |
| `npm_certificate_list` | Ablaufdatum, `expiring_soon` bei weniger als 14 Tagen |
| `npm_redirection_host_list`, `npm_stream_list`, `npm_access_list_list`, `npm_host_report` | Übersichten (Access-Lists ohne Benutzer/Passwörter) |

### NPM - schreibend

| Tool | Beschreibung |
|---|---|
| `npm_proxy_host_create(domain_names, forward_scheme, forward_host, forward_port, websocket=false, block_exploits=true, ssl=true, http2=true, hsts=false, access_list_id, advanced_config, confirm)` | Duplikate (Proxy- und Redirection-Hosts) werden verhindert. Bei `ssl=true` muss jede Domain auf `PUBLIC_IP` auflösen, sonst Abbruch. Fordert ein Let's-Encrypt-Zertifikat an und setzt danach `ssl_forced` |
| `npm_proxy_host_update(id, <nur geänderte Felder>, confirm)` | Holt den aktuellen Stand und zeigt den Diff |
| `npm_proxy_host_enable` / `npm_proxy_host_disable(id, confirm)` | Aktivieren/deaktivieren (nicht löschen) |
| `npm_certificate_renew(id, confirm)` | Let's-Encrypt-Zertifikat erneuern |

### Kombinierte Abläufe

| Tool | Beschreibung |
|---|---|
| `infra_version` | `APP_VERSION`, Commit, Build-Zeit |
| `infra_publish_service(stack_name, endpoint_id, compose_content, domain, forward_port, env, websocket=false, service, forward_scheme="http", allow_docker_socket=false, confirm)` | 1. Prüft Stack-Name und Domain frei, DNS auf `PUBLIC_IP`, Compose gültig, Dienst im NPM-Netz. 2. Legt den Stack an und wartet max. 120 s auf running (bzw. healthy, falls Healthcheck). 3. Forward-Ziel = Containername im gemeinsamen Netz mit NPM (nach dem Start geprüft). 4. Proxy-Host mit Zertifikat. 5. HTTPS-Test (Statuscode, Zertifikat gültig). Bei Fehlern wird nichts zurückgebaut; die Antwort nennt `created`, `missing` und `failed_step` |
| `infra_update_service(stack_name, confirm)` | Images pullen, Stack redeployen, warten bis running/healthy, danach letzte Log-Zeilen und HTTPS-Test der zugehörigen Domain(s) |
| `infra_service_status(stack_name_or_domain)` | Stack, Container-Status, Health, letzte Fehler im Log, Proxy-Host, Zertifikatsablauf, DNS, HTTPS-Test |
| `infra_host_resources` | Docker-Host jetzt: CPU-% (über 1 s gemessen), Kerne, Load, RAM, Swap, Belegung jedes Dateisystems (`warning` ab 85 %), Uptime |
| `infra_host_history(hours=24, bucket_minutes=60)` | Verlauf von Host-CPU und -RAM: Durchschnitt, Maximum mit Zeitpunkt, Werte pro Zeitfenster, Lücken in der Aufzeichnung |

### Host-Ressourcen

Im Stack läuft neben infra-mcp ein [node-exporter](https://github.com/prometheus/node_exporter) (`quay.io/prometheus/node-exporter:v1.12.1`). Er liest `/proc` und die Dateisysteme des Hosts über einen read-only-Mount von `/` und ist nur im stack-internen Netz erreichbar (kein veröffentlichter Port, kein Zugang über NPM). infra-mcp selbst bekommt weiterhin weder Host-Mounts noch den Docker-Socket.

infra-mcp fragt den node-exporter alle `METRICS_INTERVAL` Sekunden (Standard 60) ab und speichert CPU-%, RAM-% und Load für 24 h im Volume `infra-mcp-data` (`/data/host-metrics.jsonl`). Der Verlauf übersteht Neustarts und Redeploys. Ist die Datei nicht beschreibbar, läuft die Aufzeichnung nur im Speicher weiter (`persisted: false`). Pausen, z.B. durch einen Neustart, erscheinen in `infra_host_history` als `gaps`.

CPU-% = Anteil der CPU-Zeit ausser `idle` und `iowait`, über alle Kerne. RAM belegt = `MemTotal - MemAvailable`. Disk belegt wie `df` (Grösse minus für Benutzer verfügbar); flüchtige Dateisysteme (tmpfs, overlay usw.) und Docker-interne Mounts sind ausgeblendet.

`service` bei `infra_publish_service` ist nur nötig, wenn die Compose-Datei mehrere Dienste hat. Der Dienst muss im Docker-Netz von NPM hängen, z.B.:

```yaml
services:
  app:
    image: ghcr.io/example/app:1.0
    networks: [npm]
networks:
  npm:
    external: true
    name: npm_default   # = NPM_DOCKER_NETWORK
```

DNS-Einträge legt infra-mcp nicht an. Fehlt einer, meldet das Tool den nötigen A-Record, z.B. `app.example.com. IN A 203.0.113.10`.

## Regeln für schreibende Tools

- `confirm=true` zwingend (nur der Wert `true`, nicht `"true"` oder `1`), sonst nur Vorschau.
- Geschützte Container, Stacks und Domains werden blockiert, mit Begründung. Ein Stack gilt auch als geschützt, wenn einer seiner Container geschützt ist.
- Kein Löschen von Stacks, Containern, Volumes, Images, Proxy-Hosts, Zertifikaten oder Access-Lists. Kein Prune. Keine Änderungen an Benutzern, Einstellungen, Registries oder Endpoints. Die entsprechenden API-Aufrufe existieren im Code nicht.
- Timeouts: Verbindungsaufbau 10 s, Stack-Deploy bis 300 s, Zertifikatsanforderung bis 180 s. Läuft ein Schreibvorgang in einen Timeout, meldet das Tool, dass der Zustand unklar ist, und verlangt zuerst eine Prüfung des Ist-Zustands. Es wird nie automatisch wiederholt. (Ausnahme: Antwortet NPM mit 401, wird nach neuem Login genau einmal wiederholt - 401 heisst, NPM hat nichts ausgeführt.)
- Ohne gesetztes `PROTECTED_DOMAINS` sind alle schreibenden NPM-Tools gesperrt.

## Umgebungsvariablen

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `PORTAINER_URL` | ja | - | z.B. `https://portainer.example.com` (`/api` wird angehängt) |
| `PORTAINER_API_KEY` | ja | - | Access Token des Benutzers `mcp`, gesendet als `X-API-Key` |
| `PORTAINER_TLS_VERIFY` | nein | `1` | `0` nur bei selbstsigniertem Zertifikat |
| `NPM_URL` | ja | - | intern, z.B. `http://npm:81/api` |
| `NPM_USER` / `NPM_PASSWORD` | ja | - | eigener NPM-Benutzer für den MCP (E-Mail und Passwort) |
| `NPM_DEFAULT_EMAIL` | nur NPM bis v2.12 | - | Let's-Encrypt-E-Mail. Ab NPM v2.13 nimmt NPM die E-Mail des angemeldeten NPM-Benutzers, das Feld wird dann nicht gesendet |
| `NPM_DOCKER_NETWORK` | für `infra_publish_service` | - | Docker-Netz, in dem NPM hängt |
| `PUBLIC_IP` | für SSL-Hosts | - | öffentliche IP, auf die neue Domains zeigen müssen |
| `PROTECTED_CONTAINERS` | nein | - | kommagetrennt, Glob-Muster (`db-*`). Immer zusätzlich geschützt: `portainer*`, `nginx-proxy-manager*`, `npm*`, `infra-mcp*` und der eigene Container |
| `PROTECTED_STACKS` | nein | - | wie oben, gleiche Standardmuster |
| `PROTECTED_DOMAINS` | für NPM-Schreibtools | - | mindestens die Domains von Portainer, NPM und infra-mcp |
| `MCP_API_KEY` | ja | - | statisches Bearer-Token für den Connector. Ohne startet der Server nicht |
| `NODE_EXPORTER_URL` | für Host-Ressourcen | in der Compose-Datei `http://infra-mcp-node-exporter:9100/metrics` | leer = Host-Tools und Aufzeichnung aus |
| `METRICS_INTERVAL` | nein | `60` | Messintervall in Sekunden (min. 10) |
| `METRICS_FILE` | nein | `/data/host-metrics.jsonl` | Datei für den 24-h-Verlauf |
| `MCP_HOST_PORT` | nein | `8427` | Host-Port |
| `MCP_BIND_ADDR` | nein | `0.0.0.0` | Bind-Adresse des Host-Ports (alle Interfaces, wie bei den übrigen MCP-Stacks) |
| `LOG_LEVEL` | nein | `INFO` | |

Secrets nur über Env bzw. Portainer-Stack-Variablen, nie im Image.

## Sicherheit

- Jeder HTTP-Request braucht `Authorization: Bearer <MCP_API_KEY>`, sonst `401 unauthorized` - auch `/healthz`. Gleicher Mechanismus wie plesk-mcp, also-mcp und dr-mcp (Konstantzeit-Vergleich, CORS für Claude.ai).
- Kein Docker-Socket. Der Container läuft als Non-Root-User (UID 10001) mit Docker-`HEALTHCHECK`.
- Der node-exporter mountet `/` des Hosts read-only und kann damit alle Dateien des Hosts lesen. Er liefert nur Metriken, hat keinen veröffentlichten Port und hängt nur im internen Netz (`internal: true`, kein Zugang nach aussen). Den Stack deshalb als Administrator anlegen; ein Nicht-Administrator darf in Portainer je nach Einstellung keine Bind-Mounts nutzen.
- Fehlerantworten enthalten keine Passwörter, Tokens oder Header. Bekannte Secret-Werte werden zusätzlich aus allen Texten entfernt.
- Container-Env wird nur mit Namen ausgegeben, Stack-Env ebenso; Compose-Dateien und `advanced_config` nur geschwärzt.
- Jeder Tool-Aufruf wird als JSON-Zeile auf stdout geloggt: Toolname, Parameter ohne Secrets (Env nur Namen, Compose nur Länge), Resultat-Kurzfassung, Dauer.

### Benötigte Rechte in Portainer (Benutzer `mcp`)

Geprüft am Portainer-Quellcode 2.45.2 (CE):

- Eigener Benutzer `mcp`, Rolle **Standard user** (kein Administrator), mit eigenem Access Token (*My account > Access tokens*, angemeldet als `mcp`).
- Zugriff auf die Umgebung(en), die infra-mcp verwalten soll (*Environments > Manage access*).
- In den Sicherheitseinstellungen der Umgebung darf die Stack-Verwaltung für Nicht-Administratoren nicht deaktiviert sein (`AllowStackManagementForRegularUsers`), sonst kann `mcp` keine Stacks anlegen oder ändern.
- Nicht-Administratoren sehen nur Stacks und Container, die ihnen, ihrem Team oder öffentlich zugeordnet sind. Von einem Administrator angelegte Stacks sind standardmässig "Administrators only" und für `mcp` unsichtbar. Stacks, die infra-mcp verwalten soll, unter *Access control* einem Team mit `mcp` zuordnen. Stacks, die `mcp` selbst anlegt, gehören automatisch `mcp`.
- Portainer, NPM und infra-mcp selbst auf "Administrators only" lassen - dann sieht `mcp` sie gar nicht (zusätzlich zu den Schutzlisten).
- Sind Bind-Mounts für Nicht-Administratoren in der Umgebung deaktiviert (`AllowBindMountsForRegularUsers`), blockiert der Docker-Proxy von Portainer Bind-Mounts für `mcp`. Ob das auch für Stacks greift, ist noch nicht live geprüft.

### Benötigte Rechte in NPM (eigener MCP-Benutzer)

Geprüft am NPM-Quellcode v2.16.0 (`backend/lib/access`, `backend/internal`):

| Einstellung | Wert | Grund |
|---|---|---|
| Rolle | User (nicht Administrator) | |
| Item Visibility | **All Items** | sonst sieht der Benutzer nur selbst angelegte Hosts und Zertifikate |
| Proxy Hosts | Manage | anlegen, ändern, aktivieren/deaktivieren |
| Certificates | Manage | Let's Encrypt anfordern und erneuern |
| Redirection Hosts | View | Duplikat-Prüfung, Liste |
| Streams | View | Liste |
| Access Lists | View | Liste, Zuordnung per `access_list_id` |
| 404 Hosts | Hidden | nicht benötigt |

Zusätzlich: Zwei-Faktor-Anmeldung für diesen Benutzer aus, und ab NPM v2.13 muss seine E-Mail-Adresse die gewünschte Let's-Encrypt-Adresse sein.

## Getestete Versionen

| Komponente | Stand |
|---|---|
| Portainer | API-Pfade und Payloads gegen den Quellcode **2.45.2** geprüft. Noch nicht gegen eine laufende Instanz getestet |
| Nginx Proxy Manager | Payloads gegen den Quellcode **v2.16.0** geprüft (Let's-Encrypt-Altformat gegen v2.12.6). Noch nicht gegen eine laufende Instanz getestet |
| node-exporter | v1.12.1 (Standardausschlüsse für Dateisysteme gegen den Quellcode geprüft) |
| Python / SDK | Python 3.12 (Image), `mcp==2.3.0` |

Die Tests laufen mit gemockten APIs. Nach dem ersten Einsatz hier die tatsächlich eingesetzten Versionen eintragen.

## Release (nur über Git-Tags)

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions (`.github/workflows/docker-publish.yml`) führt zuerst die Tests aus und baut nur bei grünen Tests das Image:

- Tag `vX.Y.Z` -> `ghcr.io/kdt-solutions/infra-mcp:X.Y.Z` und `:latest`, Build-Args `APP_VERSION=X.Y.Z`, `GIT_SHA`, `BUILD_TIME`
- manueller Lauf (*Run workflow*) -> nur `:dev-<kurzer Commit>`, `APP_VERSION=dev-<kurzer Commit>`
- Push ohne Tag und Pull Requests -> nur Tests

Ohne `APP_VERSION` meldet `infra_version` die Version `dev-<kurzer Commit>`.

## Deployment

1. In Portainer und NPM die Benutzer mit den Rechten oben anlegen, Portainer-Access-Token für `mcp` erzeugen.
2. In Portainer **als Administrator** einen neuen Stack aus `docker-compose.yml` anlegen (Repository oder Web-Editor) und die Variablen setzen (siehe `.env.example`), mindestens `PORTAINER_URL`, `PORTAINER_API_KEY`, `NPM_URL`, `NPM_USER`, `NPM_PASSWORD`, `NPM_DOCKER_NETWORK`, `PUBLIC_IP`, `PROTECTED_DOMAINS`, `MCP_API_KEY` (z.B. `openssl rand -hex 32`).
3. Der Stack hängt im Docker-Netz von NPM (`NPM_DOCKER_NETWORK`), dadurch ist die NPM-API intern unter `http://<npm-container>:81/api` erreichbar. Port 81 bleibt nicht öffentlich.
4. DNS: A-Record für die Subdomain von infra-mcp (z.B. `infra-mcp.example.com`) auf die öffentliche IP.
5. In NPM einen Proxy-Host anlegen: Domain `infra-mcp.example.com` -> `http://<Host-IP>:8427` (wie die übrigen MCP-Stacks) oder über das gemeinsame Docker-Netz `http://infra-mcp:8000`, Let's-Encrypt-Zertifikat, Force SSL. Diese Domain in `PROTECTED_DOMAINS` aufnehmen.
6. Prüfen: `curl -i https://infra-mcp.example.com/healthz` liefert `401`, mit `-H "Authorization: Bearer <MCP_API_KEY>"` liefert es `200`.

## Als Connector in Claude hinzufügen

Gleich wie bei den anderen MCP-Connectors:

- URL: `https://infra-mcp.example.com/mcp`
- Authentifizierung: keine Anmeldung (kein OAuth), Request-Header `Authorization: Bearer <MCP_API_KEY>`
- Danach `infra_version` aufrufen und Version/Commit prüfen.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

Abgedeckt: Host-Metriken und 24-h-Verlauf, Log-Demux, Schwärzung, NPM-Token-Erneuerung und 401-Wiederholung, Schutzlisten, Duplikat-Prüfung, DNS-Vorabprüfung, confirm-Logik, Compose-Prüfung, Bearer-Auth, Audit-Log und der Ablauf von `infra_publish_service` mit Fehlern in jedem Schritt.
