# Changelog

## 0.5.0

- `portainer_stack_update` kann bei Git-Stacks Env-Variablen ändern (`env_set`, `env_unset`). Ausgerollt wird über `PUT /api/stacks/{id}/git/redeploy` mit der vollständigen, aus der aktuellen Env zusammengeführten Liste und der bisherigen Git-Referenz (`RepositoryReferenceName`). `pull_image` steuerbar, Prune immer aus. `compose_content` bleibt bei Git-Stacks gesperrt.
- Vorschau ohne `confirm` zeigt die betroffenen Variablen mit `neu`/`geändert`/`entfernt`. Neue Werte nur, wenn der Name kein PASSWORD, TOKEN, KEY, SECRET (u.ä.) enthält; bestehende Werte nie.
- Mit `confirm=true` wird auf das Deploy gewartet, eine Fehlermeldung von Portainer zurückgegeben und kontrolliert, ob Portainer die Env so gespeichert hat wie geschickt.
- Abbruch ohne Änderung, wenn die Git-Referenz nicht sichtbar ist oder die aktuelle Env unvollständig gelesen wird.
- Audit-Log: ein Eintrag `stack_env_change` pro geänderter Variable (Stack, Name, Aktion, ohne Wert), auch bei Compose-Stacks.
- Audit-Log der Tool-Aufrufe enthält bei `env_set` nur noch die Variablennamen, keine Werte mehr.
