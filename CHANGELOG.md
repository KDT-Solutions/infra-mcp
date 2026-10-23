# Changelog

## 0.6.0

Sicherheits-Release nach Security-Review (drei hohe Befunde). **Breaking:** der Tool-Parameter `allow_docker_socket` entfällt, Bind-Mounts brauchen neu eine Allowlist, `advanced_config` ist auf nginx-Direktiven aus einer Allowlist beschränkt.

- **Docker-Socket nur serverseitig:** `allow_docker_socket` ist aus `portainer_stack_create`, `portainer_stack_create_git`, `portainer_stack_update` und `infra_publish_service` entfernt. Docker-Socket-Mounts (`/var/run/docker.sock`, `/run/docker.sock`) sind nur erlaubt, wenn der Betreiber `ALLOW_DOCKER_SOCKET_STACKS=true` setzt (Standard `false`). Der Client kann sich Host-Root damit nicht mehr selbst freigeben.
- **Bind-Mount-Allowlist:** neue Env-Variable `BIND_MOUNT_ALLOWED_PREFIXES` (kommagetrennt, absolut, ohne `..`, nicht `/`). Host-Pfade in Stacks nur unterhalb dieser Verzeichnisse; leer = keine Bind-Mounts (fail-safe, nur benannte Volumes). Quellpfade werden mit `posixpath.normpath` normalisiert, `..` wird abgelehnt (`/home/../etc`).
- **Compose-Prüfung verschärft:** `/`, `/run`, `/var/run` auch read-only verboten (Unix-Sockets bleiben über `:ro` nutzbar). Zusätzlich nur read-only: `/var/spool/cron`, `/etc/cron*`, `/var/lib/portainer`, `/var/lib/containerd`. Unter `/home`, `/opt`, `/srv` read-write nur mit einem Allowlist-Eintrag unterhalb (z.B. `/srv/stacks`). `volumes_from` abgelehnt. Benannte Volumes nur, wenn im selben Dokument unter Top-level `volumes` definiert, ohne `external`, `name`, `driver_opts` (versteckter Bind-Mount über `type: none`/`o: bind`) oder fremden `driver`. `pid`/`ipc`/`uts`/`network_mode`/`cgroup`/`userns_mode` mit `container:` oder `service:` abgelehnt, `cgroup_parent` abgelehnt, `sysctls` nur `net.*`, `ulimits` nur ganze Zahlen >= 0 mit Obergrenzen für `nofile`/`nproc`. `extends` mit `file`, `env_file` und Top-level `secrets`/`configs` nur innerhalb des Projektverzeichnisses. Compose-Variablen in sicherheitsrelevanten Feldern abgelehnt (würden erst beim Deploy aufgelöst). Relative Pfade (`./config`) bleiben erlaubt, solange sie das Projektverzeichnis nicht verlassen.
- **NPM `advanced_config` Allowlist:** nur einzelne Direktiven `<direktive> <argumente>;` aus `add_header`, `expires`, `client_max_body_size`, `proxy_read_timeout`, `proxy_send_timeout`, `proxy_connect_timeout`, `proxy_buffering`, `proxy_buffer_size`, `proxy_buffers`, `gzip`, `gzip_types`, `real_ip_header`, `set_real_ip_from` mit geprüften Argumenten. Keine Blöcke, kein `location`/`proxy_pass`/`alias`/`root`/`include`/`return`/`rewrite`/`auth_*`/`lua_*`/`ssl_*`, `add_header`-Werte ohne Zeilenumbruch und `;`, max. 4000 Zeichen / 60 Zeilen. Gilt für `npm_proxy_host_create`, `npm_proxy_host_update` und `locations[].advanced_config`; Verstoss = `GuardError`, auch in der Vorschau ohne `confirm`.
- Tests für alle Umgehungsfälle aus dem Review und die weiterhin erlaubten Fälle.

## 0.5.0

- `portainer_stack_update` kann bei Git-Stacks Env-Variablen ändern (`env_set`, `env_unset`). Ausgerollt wird über `PUT /api/stacks/{id}/git/redeploy` mit der vollständigen, aus der aktuellen Env zusammengeführten Liste und der bisherigen Git-Referenz (`RepositoryReferenceName`). `pull_image` steuerbar, Prune immer aus. `compose_content` bleibt bei Git-Stacks gesperrt.
- Vorschau ohne `confirm` zeigt die betroffenen Variablen mit `neu`/`geändert`/`entfernt`. Neue Werte nur, wenn der Name kein PASSWORD, TOKEN, KEY, SECRET (u.ä.) enthält; bestehende Werte nie.
- Mit `confirm=true` wird auf das Deploy gewartet, eine Fehlermeldung von Portainer zurückgegeben und kontrolliert, ob Portainer die Env so gespeichert hat wie geschickt.
- Abbruch ohne Änderung, wenn die Git-Referenz nicht sichtbar ist oder die aktuelle Env unvollständig gelesen wird.
- Audit-Log: ein Eintrag `stack_env_change` pro geänderter Variable (Stack, Name, Aktion, ohne Wert), auch bei Compose-Stacks.
- Audit-Log der Tool-Aufrufe enthält bei `env_set` nur noch die Variablennamen, keine Werte mehr.
