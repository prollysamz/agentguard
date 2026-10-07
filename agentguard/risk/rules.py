import re

SENSITIVE_PATH = re.compile(
    r"(?i)(?:^|[/\\\s\"'])(?:\.ssh|\.aws|\.gnupg|\.kube)(?:[/\\\s\"']|$)"
    r"|(?:^|[/\\\s\"'])\.env(?:[.\s\"']|$)|id_(?:rsa|ed25519)|/etc/(?:shadow|passwd)"
)
DANGEROUS_COMMANDS = [
    (
        re.compile(
            r"(?i)\brm\s+[^\n]*-[a-z]*r[a-z]*f|\brm\s+[^\n]*-[a-z]*f[a-z]*r|\brm\s+.*--recursive"
        ),
        "Recursive forced deletion",
    ),
    (
        re.compile(
            r"(?i)\b(?:sudo|mkfs(?:\.\w+)?|diskpart)\b|\bdd\s+.*\bof="
            r"|(?<![-\w])format(?:\.com)?\s+[a-z]:"
        ),
        "Privilege escalation or destructive disk operation",
    ),
    (re.compile(r"(?i)\bchmod\s+(?:-[a-z]+\s+)*777\b"), "World-writable permissions"),
    (
        re.compile(
            r"(?i)(?:curl|wget|invoke-webrequest|iwr).*\|\s*(?:sh|bash|iex|invoke-expression)"
        ),
        "Download and execute pipeline",
    ),
    (
        re.compile(
            r"(?i)\b(?:powershell|pwsh)\b.*(?:-enc|downloadstring|invoke-expression)|\b(?:iex|invoke-expression)\b"
        ),
        "Dynamic or encoded command execution",
    ),
    (
        re.compile(r"(?i)\bremove-item\b.*(?:-recurse|-force)|\b(?:del|rmdir|rd)\s+/[sq]"),
        "Destructive Windows command",
    ),
]
EXTERNAL_COMMAND = re.compile(
    r"(?i)\b(?:curl|wget|scp|sftp|ftp|invoke-webrequest|invoke-restmethod)\b"
)
REMOTE_PUSH = re.compile(r"(?i)\bgit\s+push\b")
PROTECTED_PUSH = re.compile(r"(?i)\bgit\s+push\b.*(?:\bmain\b|\bmaster\b|--force|\s-f\b)")
