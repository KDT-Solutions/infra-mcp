"""Gemeinsame Fehlerklassen. Meldungen sind für den Client bestimmt und
enthalten nie Header, Tokens oder Passwörter."""


class InfraError(Exception):
    """Basisklasse für erwartete Fehler mit Klartext-Meldung."""


class PortainerError(InfraError):
    pass


class NpmError(InfraError):
    pass


class GuardError(InfraError):
    """Aktion durch Schutzregeln blockiert oder Eingabe unzulässig."""


class UnclearStateError(InfraError):
    """Timeout während eines Schreibvorgangs: Ob die Aktion ausgeführt wurde, ist unbekannt."""
