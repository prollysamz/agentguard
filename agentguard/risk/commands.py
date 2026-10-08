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
    for token in tokens:
        if token and all(c in PUNCTUATION for c in token):
            if argv:
                pipeline.append(argv)
                argv = []
            if token not in {"|", "|&"} and pipeline:
                pipelines.append(pipeline)
                pipeline = []
        elif token != "$":  # The "$" of "$(" arrives as its own token.
            argv.append(token)
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
            if program in DOWNLOADERS and set(programs[index + 1 :]) & INTERPRETERS:
                reasons.append(FETCH_EXEC)
    return list(dict.fromkeys(reasons))
