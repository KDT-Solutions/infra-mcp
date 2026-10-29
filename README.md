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
| `portainer_stack_create(name, endpoint_id, compose_content, env, confirm)` | Neuer Compose-Stack. Vorher geprüft (siehe Compose-Prüfung), Name frei. Wartet auf das asynchrone Deploy und meldet die Fehlermeldung von Portainer |
| `portainer_stack_create_git(name, endpoint_id, repository_url, reference="refs/heads/main", compose_path="docker-compose.yml", env, auto_update_interval, force_pull_image=true, confirm)` | Neuer Git-Stack (Portainer "Repository", `POST /api/stacks/create/standalone/repository`). Nur öffentliche GitHub-Repositories: die Compose-Datei wird vorher über raw.githubusercontent.com geladen und wie bei `portainer_stack_create` geprüft. Vorschau zeigt Env-Namen, fehlende Variablen ohne Default und ungenutzte Variablen. Optional GitOps-Polling. Wartet auf das Deploy |
| `portainer_stack_update(stack_id, compose_content, env_set, env_unset, pull_image=true, confirm)` | Bestehenden Compose-Stack ändern und neu ausrollen (`Prune=false`). Compose-Datei ersetzen und/oder einzelne Env-Variablen setzen/entfernen; alle übrigen Env-Werte bleiben erhalten und laufen nicht durch den Chat. Vorschau mit geschwärztem Diff und den betroffenen Env-Namen (`neu`/`geändert`/`entfernt`; neue Werte nur, wenn der Name nicht nach Secret aussieht, bestehende Werte nie). Git-Stacks: nur `env_set`/`env_unset` (siehe unten), `compose_content` bleibt gesperrt |

### Git-Stacks (Portainer ab 2.4x)

Portainer speichert die Git-Daten eines Stacks in einer GitOps-Source. Hat der API-Benutzer keinen Zugriff auf diese Source, liefert die API `GitConfig: null`, `WorkflowID` ist aber gesetzt. infra-mcp behandelt jeden Stack mit `WorkflowID` als Git-Stack und schickt dafür nie `PUT /stacks/{id}` - das würde die Git-Anbindung lösen und den Stack zum Editor-Stack machen. Redeploys laufen immer über `git/redeploy`; ohne Zugriff auf die Source meldet das Tool, dass der Benutzer Zugriff auf die Source braucht.

`portainer_stack_update` ändert bei Git-Stacks nur Env-Variablen (`env_set`, `env_unset`); eine neue Compose-Datei wird abgelehnt, die gehört ins Repository. Ablauf:

- Die aktuelle Env wird aus `GET /api/stacks/{id}` geladen, nur die genannten Namen werden gesetzt bzw. entfernt, alle anderen Werte unverändert übernommen. Fehlt bei einem bestehenden Eintrag der Wert, bricht das Tool ab.
- Ausgerollt wird mit `PUT /api/stacks/{id}/git/redeploy?endpointId=..` und der vollständigen Liste im Feld `Env`. Portainer ersetzt die Env damit komplett (geprüft gegen den Quellcode 2.45.2: ohne `Env` bleibt sie unverändert, mit `Env` wird sie ersetzt). Deshalb wird nie eine Teilliste geschickt.
- Die bisherige Git-Referenz geht als `RepositoryReferenceName` mit. Ist sie nicht sichtbar (kein Zugriff auf die GitOps-Source), bricht das Tool ab.
- `pull_image` wie bei `portainer_stack_redeploy`, `Prune` immer aus.
- Mit `confirm=true` wartet das Tool auf das Deploy, meldet eine Fehlermeldung von Portainer und prüft danach, ob die gespeicherte Env der geschickten entspricht.
- Pro geänderter Variable ein Audit-Eintrag `stack_env_change` (Stack, Name, Aktion, ohne Wert).

### Compose-Prüfung

Gilt für `portainer_stack_create`, `portainer_stack_create_git`, `portainer_stack_update` und `infra_publish_service`, auch in der Vorschau ohne `confirm`. Blockiert wird alles, womit ein Container aus seiner Isolation ausbricht oder an fremde Daten kommt:

- `privileged`, `cap_add`, `devices`, `device_cgroup_rules`, `cgroup_parent`
- `security_opt` ausser `no-new-privileges` (also kein `seccomp:unconfined`, `apparmor:unconfined`, `label:disable` ...)
- Namespaces: `pid`, `ipc`, `uts`, `userns_mode`, `network_mode`, `cgroup` mit `host` sowie mit `container:<id>` oder `service:<name>` (Namespace-Join auf fremde Container)
- `sysctls` ausser `net.*` (wirken nur im Netz-Namespace des Containers); `ulimits` nur als ganze Zahlen >= 0 (kein `-1` = unbegrenzt), `nofile` max. 1048576, `nproc` max. 65536
- Bind-Mounts (Host-Pfade):
  - Quellpfade werden normalisiert (`posixpath.normpath`), Pfade mit `..` werden abgelehnt (`/home/../etc`)
  - nur unterhalb der Verzeichnisse aus `BIND_MOUNT_ALLOWED_PREFIXES`. Leer = **keine Bind-Mounts** (fail-safe), nur benannte Volumes
  - `/`, `/run`, `/var/run` nie, auch nicht read-only - ein `:ro`-Mount verhindert kein `connect()` auf Unix-Sockets wie `docker.sock` oder `containerd.sock`
  - sensible Pfade nur read-only, auch wenn die Allowlist sie abdeckt: `/etc` (inkl. `/etc/cron*`), `/root`, `/boot`, `/proc`, `/sys`, `/dev`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/portainer`, `/var/spool/cron`
  - `/home`, `/opt`, `/srv` read-write nur, wenn `BIND_MOUNT_ALLOWED_PREFIXES` ein Verzeichnis *darunter* nennt (z.B. `/srv/stacks`); ein Eintrag `/srv` allein erlaubt darunter nur read-only
  - relative Pfade (`./config`) zeigen in das Projektverzeichnis des Stacks (Compose-Datei bzw. Git-Checkout) und sind erlaubt, solange sie es nicht verlassen (`../`, `~` nicht)
- Docker-Socket-Mount (`/var/run/docker.sock`, `/run/docker.sock`) nur, wenn der Betreiber `ALLOW_DOCKER_SOCKET_STACKS=true` in der Umgebung von infra-mcp setzt. Es gibt keinen Tool-Parameter dafür - der Client (das Modell) kann sich den Socket nicht selbst erlauben
- `volumes_from` (hängt Volumes fremder Container ein, z.B. Portainers `/data`)
- Benannte Volumes nur, wenn sie im selben Dokument unter Top-level `volumes` definiert sind - ohne `external`, ohne `name` (würde ein bestehendes Volume übernehmen), ohne `driver_opts` (`type: none`, `device: /...`, `o: bind` = versteckter Bind-Mount) und ohne fremden `driver`
- `extends` mit `file`, `env_file` sowie Top-level `secrets`/`configs` mit `file` nur innerhalb des Projektverzeichnisses (keine absoluten Pfade, kein `..`)
- Compose-Variablen (`${X}`) in sicherheitsrelevanten Feldern (`privileged`, `volumes`, `pid`, `sysctls` ...), da Portainer sie erst beim Deploy auflöst und die Prüfung sonst nur den Platzhalter sieht

Hinweis: Portainer selbst lehnt `security_opt` für Nicht-Administratoren ab, solange das in den Sicherheitseinstellungen der Umgebung gesperrt ist. Empfohlen ist stattdessen `"no-new-privileges": true` in `/etc/docker/daemon.json` des Hosts - dann gilt der Schutz für alle Container, ohne dass ein Stack `security_opt` braucht.

### NPM - lesend

| Tool | Beschreibung |
|---|---|
| `npm_version` | NPM-Version (`GET /api/`) |
| `npm_proxy_host_list(filter)` | id, Domains, Forward-Ziel, enabled, Zertifikat inkl. Ablauf, ssl_forced |
| `npm_proxy_host_get(id_or_domain)` | Ein Proxy-Host mit allen Einstellungen inkl. Custom Locations (Pfad, Ziel), `advanced_config` geschwärzt |
| `npm_certificate_list` | Ablaufdatum, `expiring_soon` bei weniger als 14 Tagen |
| `npm_redirection_host_list`, `npm_stream_list`, `npm_access_list_list`, `npm_host_report` | Übersichten (Access-Lists ohne Benutzer/Passwörter) |

### NPM - schreibend

| Tool | Beschreibung |
|---|---|
| `npm_proxy_host_create(domain_names, forward_scheme, forward_host, forward_port, websocket=false, block_exploits=true, ssl=true, http2=true, hsts=false, access_list_id, advanced_config, locations, confirm)` | Duplikate (Proxy- und Redirection-Hosts) werden verhindert. Bei `ssl=true` muss jede Domain auf `PUBLIC_IP` auflösen, sonst Abbruch. Fordert ein Let's-Encrypt-Zertifikat an und setzt danach `ssl_forced`. `locations`: Custom Locations, gleiche Prüfungen wie unten |
| `npm_proxy_host_update(id, <nur geänderte Felder>, confirm)` | Holt den aktuellen Stand und zeigt den Diff |
| `npm_proxy_host_update(id, locations_set, locations_remove, confirm)` | Custom Locations anlegen, ersetzen (gleicher `path`) oder per Pfad entfernen. Alle übrigen Locations und Einstellungen des Hosts bleiben unverändert. Nicht zusammen mit den übrigen Feldern in einem Aufruf. Details unter Custom Locations |
| `npm_proxy_host_enable` / `npm_proxy_host_disable(id, confirm)` | Aktivieren/deaktivieren (nicht löschen) |
| `npm_certificate_renew(id, confirm)` | Let's-Encrypt-Zertifikat erneuern |


`advanced_config` (auch `locations[].advanced_config`) landet 1:1 in der nginx-Konfiguration des NPM-Containers und ist deshalb auf eine Allowlist beschränkt - auch in der Vorschau ohne `confirm`:

- nur einzelne Direktiven, eine pro Zeile, Form `<direktive> <argumente>;` - keine Blöcke (`{ }`), kein zweites `;` auf der Zeile, keine Steuerzeichen; Kommentarzeilen (`#`) und Leerzeilen sind erlaubt
- erlaubte Direktiven: `add_header`, `expires`, `client_max_body_size`, `proxy_read_timeout`, `proxy_send_timeout`, `proxy_connect_timeout`, `proxy_buffering`, `proxy_buffer_size`, `proxy_buffers`, `gzip`, `gzip_types`, `real_ip_header`, `set_real_ip_from` - jeweils mit geprüften Argumenten
- `add_header`: Name aus `[A-Za-z0-9_-]`, Wert ohne Zeilenumbruch und ohne `;` (auch nicht in Anführungszeichen), optional `always`
- damit ausgeschlossen: `location`, `proxy_pass` (z.B. auf die NPM-Admin-API `127.0.0.1:81` oder Portainer), `alias`/`root` (z.B. `/data`, `/etc/letsencrypt`), `include`, `return`, `rewrite`, `auth_*`, `lua_*`/`*_by_lua*`, `ssl_*`
- maximal 4000 Zeichen und 60 Zeilen

### Custom Locations

Eine Location leitet einen Pfad eines bestehenden Proxy-Hosts an ein anderes Ziel weiter, z.B. `/app` auf `http://192.0.2.25:8438`. Sie übernimmt vom Host Zugriffsliste, SSL-Zwang, HSTS, `block_exploits` und WebSocket; die `advanced_config` des Hosts steht auf Server-Ebene und gilt auch für die Locations.

Eine Location ist ein Objekt mit `path`, `forward_scheme`, `forward_host`, `forward_port` und optional `forward_path`, `advanced_config`, `access_list_id`. Andere Felder werden abgelehnt.

- `locations_set`: Eine vorhandene Location mit gleichem `path` wird ersetzt (ihre `id` bleibt), sonst wird die neue angehängt.
- `locations_remove`: Pfade, die entfernt werden. Ein Pfad, den der Host nicht hat, wird abgelehnt.
- Alle nicht genannten Locations werden unverändert übernommen, inklusive `id`. Die Liste lässt sich nicht als Ganzes überschreiben.

NPM ersetzt bei `PUT /api/nginx/proxy-hosts/{id}` die gespeicherte Liste `locations` komplett, wenn das Feld im Body steht (geprüft am Quellcode v2.12.6 und v2.16.0). infra-mcp liest deshalb den aktuellen Stand, baut daraus die vollständige Liste und schickt einen PUT, der nur `locations` enthält. Die übrigen Felder des Hosts gehen nicht mit.

Prüfungen (auch in der Vorschau ohne `confirm`, Verstoss = Abbruch ohne Schreibzugriff):

- `path`: `^/[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*/?$`, max. 100 Zeichen, kein Segment `..`. Damit sind ausgeschlossen: `/` allein (würde die Standard-Location des Hosts ersetzen), nginx-Modifikatoren (`=`, `~`, `~*`, `^~`), Leerzeichen und `` { } ; $ \ ` " ``. Jeder Pfad nur einmal pro Host.
- `forward_scheme` `http`/`https`, `forward_host` ohne `/` (sonst würde NPM den Rest still zum `forward_path` machen), `forward_port` 1-65535.
- `forward_path`: leer oder gleiche Regel wie `path`.
- Ziel: nur `DOCKER_HOST_IP` mit einem Port, den ein für `mcp` sichtbarer Container veröffentlicht, oder ein für `mcp` sichtbarer Container im NPM-Netz (`NPM_DOCKER_NETWORK`). Nie `127.0.0.1`, `localhost`, `::1`, `0.0.0.0`. Die Ports 81 (NPM-Admin-API), 9000 und 9443 (Portainer) sind immer gesperrt. Geprüft werden nur neue und geänderte Locations.
- `advanced_config` einer Location: gleiche Allowlist wie beim Host.
- `access_list_id`: wird nur gesendet, wenn das Schema der Instanz (`GET /api/schema`) das Feld im Location-Objekt kennt (ab v2.16.0). v2.12.6 lehnt es ab; dann wird es weggelassen und die Antwort enthält einen Hinweis.
- Schutzliste: Locations auf Hosts mit geschützter Domain werden blockiert.
- Höchstens 20 Locations pro Host.

Die Vorschau zeigt pro Location `neu`, `geändert` oder `entfernt` mit Pfad und Ziel (bei `geändert` auch das bisherige Ziel), `advanced_config` geschwärzt, und die vollständige Liste danach.

#### Verhalten bei nginx-Fehlern

NPM testet die nginx-Konfiguration nach jeder Änderung. Schlägt der Test fehl, setzt NPM `meta.nginx_online = false` und `meta.nginx_err`, benennt die Config des Hosts in `.err` um und entfernt die laufende Config - der ganze Host ist dann offline. Deshalb mit `confirm=true`:

1. aktuellen Stand lesen, vollständige Liste bauen,
2. `PUT` nur mit `locations`,
3. Host neu lesen und prüfen, dass die gespeicherten Locations den geschickten entsprechen und `meta.nginx_online` true ist,
4. ist `nginx_online` false: einmal automatisch die vorherigen Locations zurückschreiben und erneut prüfen. Die Antwort enthält `nginx_err` (gekürzt auf 500 Zeichen) und das Ergebnis der Wiederherstellung (`restore`). Schlägt auch die Wiederherstellung fehl, steht in `warnung`, dass der Host offline ist,
5. weichen die gespeicherten Locations ab, meldet die Antwort `ok: false` mit beiden Listen,
6. Timeout beim `PUT`: Zustand unklar, keine automatische Wiederholung (wie bei den übrigen Schreibtools). Antwortet NPM mit einem Fehler, wird trotzdem der Ist-Zustand gelesen; sind die Locations unverändert, kommt der Fehler zurück.

Ist der Host deaktiviert, schreibt NPM keine nginx-Config; `nginx_online` wird dann nicht ausgewertet.

Audit-Log: pro geänderter Location ein Eintrag `proxy_host_location_change` (Host-ID, Domains, Pfad, Aktion, Ziel), bei automatischer Wiederherstellung zusätzlich `proxy_host_location_restore`. Im Tool-Log erscheinen von `locations`/`locations_set` nur Pfad und Ziel, `advanced_config` nur als Länge.

### Kombinierte Abläufe

| Tool | Beschreibung |
|---|---|
| `infra_version` | `APP_VERSION`, Commit, Build-Zeit |
| `infra_publish_service(stack_name, endpoint_id, compose_content, domain, forward_port, env, websocket=false, service, forward_scheme="http", confirm)` | 1. Prüft Stack-Name und Domain frei, DNS auf `PUBLIC_IP`, Compose gültig, Dienst im NPM-Netz. 2. Legt den Stack an und wartet max. 120 s auf running (bzw. healthy, falls Healthcheck). 3. Forward-Ziel = Containername im gemeinsamen Netz mit NPM (nach dem Start geprüft). 4. Proxy-Host mit Zertifikat. 5. HTTPS-Test (Statuscode, Zertifikat gültig). Bei Fehlern wird nichts zurückgebaut; die Antwort nennt `created`, `missing` und `failed_step` |
| `infra_update_service(stack_name, confirm)` | Images pullen, Stack redeployen, warten bis running/healthy, danach letzte Log-Zeilen und HTTPS-Test der zugehörigen Domain(s) |
| `infra_service_status(stack_name_or_domain)` | Stack, Container-Status, Health, letzte Fehler im Log, Proxy-Host, Zertifikatsablauf, DNS, HTTPS-Test |
| `infra_host_resources` | Docker-Host jetzt: CPU-% (über 1 s gemessen), Kerne, Load, RAM, Swap, Belegung jedes Dateisystems (`warning` ab 85 %), Uptime |
| `infra_host_history(hours=24, bucket_minutes=60)` | Verlauf von Host-CPU und -RAM: Durchschnitt, Maximum mit Zeitpunkt, Werte pro Zeitfenster, Lücken in der Aufzeichnung |

### Host-Ressourcen

Im Stack läuft neben infra-mcp ein [node-exporter](https://github.com/prometheus/node_exporter) (`quay.io/prometheus/node-exporter:v1.12.1`). Er liest `/proc` und die Dateisysteme des Hosts über einen read-only-Mount von `/` und ist nur im stack-internen Netz erreichbar (kein veröffentlichter Port, kein Zugang über NPM). infra-mcp selbst bekommt weiterhin weder Host-Mounts noch den Docker-Socket.

infra-mcp fragt den node-exporter alle `METRICS_INTERVAL` Sekunden (Standard 60) ab und speichert CPU-%, RAM-% und Load für 24 h im Volume `infra-mcp-data` (`/data/host-metrics.jsonl`). Der Verlauf übersteht Neustarts und Redeploys. Ist die Datei nicht beschreibbar, läuft die Aufzeichnung nur im Speicher weiter (`persisted: false`). Pausen, z.B. durch einen Neustart, erscheinen in `infra_host_history` als `gaps`.

CPU-% = Anteil der CPU-Zeit ausser `idle` und `iowait`, über alle Kerne. RAM belegt = `MemTotal - MemAvailable`. Disk belegt wie `df` (Grösse minus für Benutzer verfügbar); flüchtige Dateisysteme (tmpfs, overlay usw.) und Docker-interne Mounts sind ausgeblendet.

`service` bei `infra_publish_service` ist nur nötig, wenn die Compose-Datei mehrere Dienste hat. `forward_port` ist der Port im Container.

**Mit `DOCKER_HOST_IP` (empfohlen):** Der Dienst veröffentlicht `forward_port` auf einem Host-Port, z.B. `ports: ["8430:8000"]` oder `"${MCP_BIND_ADDR:-0.0.0.0}:${MCP_HOST_PORT:-8430}:8000"` (Variablen werden mit `env` aufgelöst). Vor dem Anlegen wird geprüft, dass der Host-Port weder von einem für `mcp` sichtbaren Container noch von einem NPM-Proxy-Host auf `DOCKER_HOST_IP` belegt ist; bei Konflikt nennt das Tool den nächsten freien Port. Eine Bindung an `127.0.0.1` wird abgelehnt, da NPM den Dienst dann nicht erreicht.

**Ohne `DOCKER_HOST_IP`:** Der Dienst muss im Docker-Netz von NPM hängen, z.B.:

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

`GIT_ALLOWED_REPO_PREFIXES` (optional, kommagetrennt, z.B. `https://github.com/example-org`): Nur Repositories mit diesem Präfix dürfen als Git-Stack angelegt werden. Leer = jedes öffentliche GitHub-Repository.

`BIND_MOUNT_ALLOWED_PREFIXES` (optional, kommagetrennt, z.B. `/srv/stacks`): Host-Verzeichnisse, unterhalb derer Stacks Bind-Mounts verwenden dürfen. Einträge müssen absolut sein, ohne `..` und nicht `/`; ungültige Einträge werden beim Start geloggt und verworfen. Leer = keine Bind-Mounts (nur benannte Volumes). Details unter Compose-Prüfung.

`ALLOW_DOCKER_SOCKET_STACKS` (optional, Standard `false`): Erlaubt Stacks den Mount von `/var/run/docker.sock` - das ist Root auf dem Docker-Host für diesen Container. Nur hier schaltbar, kein Tool-Parameter.


| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `PORTAINER_URL` | ja | - | z.B. `https://portainer.example.com` (`/api` wird angehängt) |
| `PORTAINER_API_KEY` | ja | - | Access Token des Benutzers `mcp`, gesendet als `X-API-Key` |
| `PORTAINER_TLS_VERIFY` | nein | `1` | `0` nur bei selbstsigniertem Zertifikat |
| `NPM_URL` | ja | - | intern, z.B. `http://npm:81/api` |
| `NPM_USER` / `NPM_PASSWORD` | ja | - | eigener NPM-Benutzer für den MCP (E-Mail und Passwort) |
| `NPM_DEFAULT_EMAIL` | nur NPM bis v2.12 | - | Let's-Encrypt-E-Mail. Ab NPM v2.13 nimmt NPM die E-Mail des angemeldeten NPM-Benutzers, das Feld wird dann nicht gesendet |
| `DOCKER_HOST_IP` | empfohlen | - | LAN-IP des Docker-Hosts. Gesetzt: `infra_publish_service` leitet auf `<DOCKER_HOST_IP>:<Host-Port>` weiter (Host-Port aus der Compose-Datei, vorher auf frei geprüft), und Proxy-Hosts werden über den Host-Port ihrem Stack zugeordnet |
| `NPM_DOCKER_NETWORK` | nur ohne `DOCKER_HOST_IP` | - | Docker-Netz, in dem NPM hängt; dann leitet NPM direkt auf den Containernamen weiter |
| `PUBLIC_IP` | für SSL-Hosts | - | öffentliche IP, auf die neue Domains zeigen müssen |
| `PROTECTED_CONTAINERS` | nein | - | kommagetrennt, Glob-Muster (`db-*`). Immer zusätzlich geschützt: `portainer*`, `nginx-proxy-manager*`, `npm*`, `infra-mcp*` und der eigene Container |
| `PROTECTED_STACKS` | nein | - | wie oben, gleiche Standardmuster |
| `PROTECTED_DOMAINS` | für NPM-Schreibtools | - | mindestens die Domains von Portainer, NPM und infra-mcp |
| `GIT_ALLOWED_REPO_PREFIXES` | nein | - | kommagetrennt, erlaubte Repository-Präfixe für Git-Stacks; leer = jedes öffentliche GitHub-Repository |
| `BIND_MOUNT_ALLOWED_PREFIXES` | nein | - | kommagetrennt, Host-Verzeichnisse für Bind-Mounts in Stacks; leer = keine Bind-Mounts |
| `ALLOW_DOCKER_SOCKET_STACKS` | nein | `false` | `true` erlaubt Stacks den Docker-Socket-Mount (= Host-Root) |
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
- Alles, was einem Stack Host-Zugriff geben könnte (Docker-Socket, Bind-Mounts), ist serverseitig über Env-Variablen gesteuert (`ALLOW_DOCKER_SOCKET_STACKS`, `BIND_MOUNT_ALLOWED_PREFIXES`), nicht über Tool-Parameter - eine Prompt-Injection über Container-Logs oder eine Compose-Datei aus Git kann sich diese Rechte nicht selbst geben. `advanced_config` für NPM ist auf eine Direktiven-Allowlist beschränkt.
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
| Portainer | **CE 2.45.2** (Docker 28.5.2): lesende Tools live getestet. Schreibende Payloads gegen den Quellcode 2.45.2 geprüft |
| Nginx Proxy Manager | **v2.16.0** und **v2.12.6**: lesende Tools live getestet. Payloads gegen den Quellcode beider Versionen geprüft; das Let's-Encrypt-Format wird bei jeder Zertifikatsanforderung am Schema der Instanz erkannt |
| node-exporter | v1.12.1, live getestet |
| Python / SDK | Python 3.12 (Image), `mcp==2.3.0` |

Die automatischen Tests laufen mit gemockten APIs. Schreibende Tools sind gegen die laufenden Instanzen noch nicht ausgeführt worden.

## Release (über Git-Tags, automatisch gesetzt)

Die Version steht in der Datei `VERSION` (z.B. `0.2.1`). Für ein Release diese Datei erhöhen und auf `main` pushen:

```bash
echo 0.2.2 > VERSION
git commit -am "Release 0.2.2" && git push
```

GitHub Actions (`.github/workflows/docker-publish.yml`) führt zuerst die Tests aus. Sind sie grün und gibt es den Tag `v<VERSION>` noch nicht, setzt der Workflow den Tag selbst und baut `ghcr.io/kdt-solutions/infra-mcp:<VERSION>` und `:latest` mit den Build-Args `APP_VERSION`, `GIT_SHA`, `BUILD_TIME`.

- Push ohne Änderung an `VERSION` (Tag existiert schon) -> nur Tests, kein Image
- Tag `vX.Y.Z` von Hand gesetzt -> ebenfalls `:X.Y.Z` und `:latest`
- manueller Lauf (*Run workflow*) -> nur `:dev-<kurzer Commit>`
- Pull Requests -> nur Tests

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

Abgedeckt: Host-Metriken und 24-h-Verlauf, Log-Demux, Schwärzung, NPM-Token-Erneuerung und 401-Wiederholung, Schutzlisten, Duplikat-Prüfung, DNS-Vorabprüfung, confirm-Logik, Compose-Prüfung, Bearer-Auth, Audit-Log, Custom Locations (Zusammenführen, Pfad- und Zielprüfung, `access_list_id` je nach Schema, nginx-Fehler mit Wiederherstellung) und der Ablauf von `infra_publish_service` mit Fehlern in jedem Schritt.
