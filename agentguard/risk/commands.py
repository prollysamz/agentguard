"""Shell-aware detection of destructive commands.

Commands are tokenized like a POSIX shell, split into simple commands at ``; & | && ||``,
newlines, ``$( )`` and backticks, and unwrapped from ``bash -c '...'``, ``env``, ``nohup``,
``sudo`` and similar prefixes. Each simple command is judged by its program and flags, so
``rm -r -f /`` is caught and ``echo rm -rf`` is not. Text that cannot be parsed falls back
to the conservative regular expressions in ``rules``.
"""

import re
import shlex

from agentguard.risk.rules import DANGEROUS_COMMANDS

PUNCTUATION = ";&|()"
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox"}
INTERPRETERS = SHELLS | {
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "php",
    "iex",
    "invoke-expression",
    "pwsh",
    "powershell",
}
DOWNLOADERS = {"curl", "wget", "iwr", "invoke-webrequest", "invoke-restmethod", "irm"}
# Programs that run the rest of their arguments as a command.
WRAPPERS = {
    "env",
    "command",
    "builtin",
    "exec",
    "nohup",
    "time",
    "nice",
    "ionice",
    "xargs",
    "stdbuf",
    "setsid",
    "unbuffer",
    "timeout",
    "watch",
}
PRIVILEGE = {"sudo", "doas", "su", "runas", "pkexec"}
DISK_TOOLS = {"diskpart", "wipefs", "fdisk", "sfdisk", "parted", "shred"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
DANGEROUS_TARGETS = {"/", "/*", "~", "~/", "*", "$home", "${home}", "c:\\", "c:/"}
MAX_DEPTH = 4

RM = "Recursive forced deletion"
DISK = "Privilege escalation or destructive disk operation"
WORLD = "World-writable permissions"
FETCH_EXEC = "Download and execute pipeline"
DYNAMIC = "Dynamic or encoded command execution"
WINDOWS = "Destructive Windows command"
SETUID = "Setuid or setgid permissions"
FIREWALL = "Disables firewall or network protection"
DECODE_EXEC = "Decoded payload executed"
# Ask-level concerns: often legitimate, worth a human look.
INFRA = "Irreversible infrastructure or data operation"
RAW_NET = "Raw network transfer"
DNS_SUBST = "Command output sent through DNS lookup"
INLINE_NET = "Inline code with network access"
SECRET_ENV = "Reads secret environment variables"
ENV_DUMP = "Environment dump sent to another program"

CLOUD_CLIS = {"aws", "gcloud", "gsutil", "az", "doctl", "oci"}
DESTRUCTIVE_VERBS = {"delete", "rm", "rb", "destroy", "terminate-instances", "purge", "remove"}
SQL_CLIENTS = {
    "psql",
    "mysql",
    "mariadb",
    "sqlite3",
    "sqlcmd",
    "mongosh",
    "mongo",
    "clickhouse-client",
}
SQL_DESTRUCTIVE = re.compile(
    r"(?i)\b(drop|truncate)\s+(table|database|schema|collection)\b|\bdelete\s+from\b|\.drop\("
)
RAW_NET_TOOLS = {"nc", "ncat", "netcat", "socat", "telnet"}
INLINE_INTERPRETERS = {"python", "python3", "node", "perl", "ruby", "php", "deno", "bun"}
NETWORK_CODE = re.compile(
    r"urllib|requests\.|http\.client|https?:|socket|fetch\(|net/http|LWP|Net::|XMLHttpRequest|require\(['\"]https?"
)
DECODERS = {"base64", "b64decode", "xxd", "uudecode", "openssl", "certutil"}
DNS_TOOLS = re.compile(r"(?i)\b(nslookup|dig|host|drill|resolve-dnsname)\b[^;&|\n]*(\$\(|`)")
SECRET_VARIABLE = re.compile(
    r"\$\{?[A-Za-z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|DATABASE_URL)[A-Za-z0-9_]*\}?"
)


def _program(token):
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _tokens(command):
    text = command.replace("`", " ; ").replace("\r", "\n").replace("\n", " ; ")
    lexer = shlex.shlex(text, posix=True, punctuation_chars=PUNCTUATION)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _pipelines(tokens):
    """[[argv, argv, ...], ...]: pipelines of simple commands."""
    pipelines, pipeline, argv = [], [], []
    for word in tokens:
        if word and all(c in PUNCTUATION for c in word):
            if argv:
                pipeline.append(argv)
                argv = []
            if word not in {"|", "|&"} and pipeline:
                pipelines.append(pipeline)
                pipeline = []
        elif word != "$":  # The "$" of "$(" arrives as its own word.
            argv.append(word)
    if argv:
        pipeline.append(argv)
    if pipeline:
        pipelines.append(pipeline)
    return pipelines


def _skip_options(argv, takes_value=frozenset()):
    while argv and argv[0].startswith("-") and argv[0] != "-":
        option, argv = argv[0], argv[1:]
        if option in takes_value and argv:
            argv = argv[1:]
    return argv


def _unwrap(argv):
    """Drop env assignments and wrapper programs. Returns (argv, privileged)."""
    privileged = False
    while argv:
        program = _program(argv[0])
        if ASSIGNMENT.match(argv[0]):
            argv = argv[1:]
        elif program in PRIVILEGE:
            privileged = True
            argv = _skip_options(argv[1:], {"-u", "-g", "-C", "-h", "-p", "-U", "-c"})
        elif program in WRAPPERS:
            argv = _skip_options(argv[1:], {"-n", "-s", "-k", "-u", "-i", "-o", "-e"})
            if program == "timeout" and argv and argv[0][:1].isdigit():
                argv = argv[1:]
        else:
            break
    return argv, privileged


def _world_writable(mode):
    if re.fullmatch(r"[0-7]{3,4}", mode):
        return int(mode[-1]) & 2 == 2
    symbolic = re.fullmatch(r"([ugoa]*)[+=]([rwxXst]+)", mode)
    return bool(symbolic and set(symbolic.group(1)) & {"a", "o"} and "w" in symbolic.group(2))


def _setuid(mode):
    if re.fullmatch(r"[0-7]{4}", mode):
        return int(mode[0]) & 6 != 0
    symbolic = re.fullmatch(r"[ugoa]*[+=]([rwxXst]+)", mode)
    return bool(symbolic and "s" in symbolic.group(1))


def _disables_firewall(program, args):
    joined = " ".join(args)
    if program == "ufw":
        return "disable" in args
    if program in {"iptables", "ip6tables"}:
        return bool({"-f", "--flush", "-x"} & set(args)) or "-p input accept" in joined
    if program == "nft":
        return "flush ruleset" in joined
    if program in {"systemctl", "service"}:
        return bool({"stop", "disable", "mask"} & set(args)) and any(
            unit in joined for unit in ("firewalld", "ufw", "nftables", "iptables", "apparmor")
        )
    if program == "setenforce":
        return "0" in args or "permissive" in args
    if program == "netsh":
        return "advfirewall" in joined and "off" in args
    if program == "set-netfirewallprofile":
        return "-enabled" in joined and "false" in joined
    if program == "set-mppreference":
        return "-disablerealtimemonitoring" in joined
    return False


def _concerns(argv, position):
    """Ask-level reasons for one simple command at ``position`` in its pipeline."""
    # A bare env/printenv dumps the environment; check before unwrapping "env" as a prefix.
    if position == 0 and len(argv) == 1 and _program(argv[0]) in {"env", "printenv", "set"}:
        return ["__env_source__"]
    argv, _ = _unwrap(argv)
    if not argv:
        return []
    program, args = _program(argv[0]), argv[1:]
    lowered = [a.lower() for a in args]
    concerns = []
    if program in {"terraform", "tofu"} and ("destroy" in lowered or "-destroy" in lowered):
        concerns.append(INFRA)
    elif program == "pulumi" and {"destroy", "down"} & set(lowered):
        concerns.append(INFRA)
    elif program == "kubectl" and lowered[:1] == ["delete"]:
        concerns.append(INFRA)
    elif program == "helm" and lowered[:1] and lowered[0] in {"uninstall", "delete"}:
        concerns.append(INFRA)
    elif program in CLOUD_CLIS and (
        set(lowered) & DESTRUCTIVE_VERBS or any(a.startswith("delete-") for a in lowered)
    ):
        concerns.append(INFRA)
    elif program in SQL_CLIENTS and any(SQL_DESTRUCTIVE.search(a) for a in args):
        concerns.append(INFRA)
    elif program == "git" and (
        ("reset" in lowered and "--hard" in lowered)
        or ("clean" in lowered and any(a.startswith("-") and "f" in a for a in lowered))
        or ("push" in lowered and {"--mirror", "--delete"} & set(lowered))
    ):
        concerns.append(INFRA)
    if (
        program in RAW_NET_TOOLS
        and (
            position > 0
            or "<" in args
            or {"-e", "--exec", "-c"} & set(lowered)
            or program == "socat"
        )
        and "-z" not in lowered
    ):
        concerns.append(RAW_NET)
    if program in INLINE_INTERPRETERS:
        for index, arg in enumerate(args):
            if arg in {"-c", "-e", "--eval", "-r"} and index + 1 < len(args):
                if NETWORK_CODE.search(args[index + 1]):
                    concerns.append(INLINE_NET)
    return concerns


def assess(command, depth=0):
    """(deny_reasons, ask_reasons) for ``command``."""
    deny = analyze(command, depth)
    try:
        pipelines = _pipelines(_tokens(command))
    except ValueError:
        pipelines = []
    ask = []
    for pipeline in pipelines:
        stage_concerns = [_concerns(argv, index) for index, argv in enumerate(pipeline)]
        if "__env_source__" in stage_concerns[0] and len(pipeline) > 1:
            ask.append(ENV_DUMP)
        for concerns in stage_concerns:
            ask += [c for c in concerns if c != "__env_source__"]
    if DNS_TOOLS.search(command):
        ask.append(DNS_SUBST)
    if SECRET_VARIABLE.search(command):
        ask.append(SECRET_ENV)
    return deny, list(dict.fromkeys(ask))


def _judge(argv, depth):
    argv, privileged = _unwrap(argv)
    reasons = [DISK] if privileged else []
    if not argv:
        return reasons
    program, args = _program(argv[0]), argv[1:]
    lowered = [a.lower() for a in args]
    if program in SHELLS and "-c" in args:
        index = args.index("-c")
        if index + 1 < len(args):
            reasons += analyze(args[index + 1], depth + 1)
    if program == "cmd" and lowered[:1] and lowered[0] in {"/c", "/k", "/r"}:
        reasons += analyze(" ".join(args[1:]), depth + 1)
    if program in {"powershell", "pwsh"}:
        for index, arg in enumerate(lowered):
            if arg.startswith("-c") and "-command".startswith(arg) and index + 1 < len(args):
                reasons += analyze(" ".join(args[index + 1 :]), depth + 1)
                break
    if program in {"rm", "remove-item", "ri", "del", "erase", "rd", "rmdir"}:
        short = {c for a in args if a.startswith("-") and not a.startswith("--") for c in a[1:]}
        recursive = bool(short & {"r", "R"}) or "--recursive" in args
        recursive |= any(a.startswith("-r") and "-recurse".startswith(a) for a in lowered)
        force = "f" in short or "--force" in args
        force |= any(a.startswith("-fo") and "-force".startswith(a) for a in lowered)
        targets = {a for a in lowered if not a.startswith("-")}
        if recursive and (force or targets & DANGEROUS_TARGETS):
            reasons.append(RM if program == "rm" else WINDOWS)
        if program in {"rd", "rmdir", "del", "erase"} and "/s" in lowered:
            reasons.append(WINDOWS)
    elif program == "find" and (
        "-delete" in lowered
        or any(
            a in {"-exec", "-execdir", "-ok"}
            and i + 1 < len(args)
            and _program(args[i + 1]) == "rm"
            for i, a in enumerate(lowered)
        )
    ):
        reasons.append(RM)
    elif program == "chmod":
        modes = [a for a in args if not a.startswith("-") or re.fullmatch(r"-[rwxXst]+", a)]
        if modes and _world_writable(modes[0].lstrip("+")):
            reasons.append(WORLD)
        if modes and _setuid(modes[0]):
            reasons.append(SETUID)
    elif _disables_firewall(program, lowered):
        reasons.append(FIREWALL)
    elif program == "dd" and any(a.startswith(("of=/dev/", "of=\\\\.\\")) for a in lowered):
        reasons.append(DISK)
    elif program.startswith("mkfs") or program in DISK_TOOLS:
        reasons.append(DISK)
    elif program in {"format", "format.com"} and any(re.fullmatch(r"[a-z]:", a) for a in lowered):
        reasons.append(DISK)
    elif program in {"iex", "invoke-expression"}:
        reasons.append(DYNAMIC)
    elif program in {"powershell", "pwsh"}:
        encoded = any(a.startswith("-e") and "-encodedcommand".startswith(a) for a in lowered)
        joined = " ".join(lowered)
        if (
            encoded
            or "downloadstring" in joined
            or re.search(r"\b(iex|invoke-expression)\b", joined)
        ):
            reasons.append(DYNAMIC)
    return reasons


def _decodes(argv):
    lowered = [a.lower() for a in _unwrap(argv)[0][1:]]
    return bool({"-d", "--decode", "-r", "-decode", "-D"} & set(lowered)) or "enc" in lowered


def analyze(command, depth=0):
    """Reasons ``command`` is destructive; empty if none were found."""
    if depth > MAX_DEPTH:
        return ["Command nesting too deep to analyze"]
    try:
        tokens = _tokens(command)
    except ValueError:
        # Unbalanced quotes and similar: use the conservative patterns on the raw text.
        return [reason for pattern, reason in DANGEROUS_COMMANDS if pattern.search(command)]
    reasons = []
    for pipeline in _pipelines(tokens):
        programs = []
        for argv in pipeline:
            reasons += _judge(argv, depth)
            unwrapped = _unwrap(argv)[0]
            programs.append(_program(unwrapped[0]) if unwrapped else "")
        for index, program in enumerate(programs):
            later = set(programs[index + 1 :])
            if program in DOWNLOADERS and later & INTERPRETERS:
                reasons.append(FETCH_EXEC)
            if program in DECODERS and later & INTERPRETERS and _decodes(pipeline[index]):
                reasons.append(DECODE_EXEC)
    return list(dict.fromkeys(reasons))
