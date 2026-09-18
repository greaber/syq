#!/usr/bin/env python3
"""Update/check command-reference tables using the public help-only entry point.

Usage: python3 tests/cli_reference.py [--check] target/debug/syq
Prose outside the marked blocks is hand-written. No transfer commands run.
"""
import argparse
import difflib
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
BLOCK = re.compile(r"<!-- CLI: (.*?) -->\n(.*?)<!-- /CLI -->", re.S)
# Streaming is omitted from the site while its interface matures.
DOCS_EXCLUDED_COMMANDS = {("stream",)}
GROUP_LINKS = {
    "--performance-tuning": "[Workers, request sizes, and copy methods](../tuning.md)",
    "--resource-limits": "[Bandwidth limit](../resource-limits.md)",
    "--integrity-checking": "[Comparison and transfer checksums](../integrity-checking.md)",
}


def read_help(binary, command):
    env = {key: value for key, value in os.environ.items()
           if key not in ("SYQ_CP_OPTIONS", "SYQ_RM_OPTIONS", "SYQ_RSYNC_OPTIONS", "SYQ_STREAM_OPTIONS")}
    env.update(NO_COLOR="1", COLUMNS="100", SYQ_NO_UPDATE_CHECK="1")
    return subprocess.run([str(binary), "help", *command, "--help-all"], env=env,
                          check=True, text=True, capture_output=True, timeout=10).stdout


def parse_help(text):
    """Clap long help has section headings, six-column labels, and indented prose."""
    usage, groups, children = [], [], []
    section = None
    row = None
    started = False
    for line in text.splitlines():
        if line.startswith("Usage: "):
            started = True
            usage.append(line.removeprefix("Usage: "))
            continue
        if not started:
            continue
        if line.startswith("       syq "):
            usage.append(line.strip())
            continue
        if line.startswith(("Documentation:", "Environment:", "Advanced commands:")):
            break
        if line and not line[0].isspace() and line.endswith(":"):
            section = line[:-1]
            row = None
            if section != "Commands":
                groups.append((section, []))
            continue
        if section == "Commands":
            match = re.match(r"^  (\S+)\s{2,}(.*)", line)
            if match:
                name, description = match.groups()
                if name != "help":  # automatic help dispatch is documented at the root
                    children.append((name, description.removeprefix("Advanced: ")))
            continue
        match = re.match(r"^ {2,6}(\S.*)$", line)
        if match and groups:
            row = [match[1], []]
            groups[-1][1].append(row)
        elif row is not None:
            row[1].append(line.strip())
    if not usage or not groups:
        raise ValueError("unrecognized full-help layout")
    return usage, groups, children


def cell(text):
    return text.replace("|", r"\|")


def prose(lines):
    paragraphs = re.split(r"\n\s*\n", "\n".join(lines).strip())
    formatted = []
    for paragraph in paragraphs:
        # Preserve value lists while joining help's wrapped prose.
        items = re.split(r"\n(?=- )", paragraph)
        formatted.append("<br>".join(" ".join(item.split()) for item in items))
    return cell("<br><br>".join(formatted))


def anchor(command):
    return "syq-" + "-".join(command)


def render(command, parsed, commands):
    usage, groups, children = parsed
    out = ["```text", *usage, "```", ""]
    if children:
        out += ["| Command | Purpose |", "|---|---|"]
        for name, description in children:
            child = (*command, name)
            target = (f"{name}.md" if not command else f"#{anchor(child)}")
            out.append(f"| [`{' '.join(child)}`]({target}) | {cell(description)} |")
        if not command:
            out.append("| [`help`](#syq-help) | Show help for any command or nested command |")
        out.append("")
    for heading, rows in groups:
        if not rows:
            continue
        # The family's table covers identical help flags on nested commands.
        if len(command) > 1 and heading == "Help and version" and (heading, rows) in commands[(command[0],)][1]:
            continue
        if len(command) == 1 and children and heading == "Help and version":
            heading = "Help (also available on subcommands)"
        title = f"## {heading}" if len(command) == 1 and not children and not command[0].startswith("--") else f"**{heading}**"
        if command == ("cp",):
            # Preserve links to the previously published section headings.
            aliases = {
                "Sources and filtering": ["sources-and-selection"],
                "Destination and mapping": ["destination-placement"],
                "Updates and deletion": ["copy-policy-and-filtering"],
                "Verification": ["integrity-checking"],
                "Connections and remote execution": ["ssh-and-transport", "remote-to-remote-transfers"],
                "Performance and resource limits": ["performance-tuning", "resource-limits"],
                "Preview, progress, and results": ["progress-and-results", "preview-and-output"],
            }
            for old in aliases.get(heading, []):
                out += [f'<a id="{old}"></a>', ""]
        out += [title, "", "| Argument / option | Meaning |", "|---|---|"]
        for signature, description in rows:
            body = prose(description)
            for flag, link in GROUP_LINKS.items():
                if signature.startswith(flag + " "):
                    body = link
                    if flag == "--performance-tuning" and command in (("rm",), ("clean-partials",)):
                        body = "Filesystem removal workers: [workers=N](../tuning.md#transfer-controls)"
            # Some management arguments have no help string. Their usage and
            # command-specific prose supply meaning; never silently omit them.
            body = body or "See the command description above."
            out.append(f"| `{cell(signature)}` | {body} |")
        out.append("")
    return "\n".join(out) + "\n"


def collect(binary):
    commands = {}
    def visit(command):
        usage, groups, children = parse_help(read_help(binary, command))
        children = [(name, description) for name, description in children
                    if (*command, name) not in DOCS_EXCLUDED_COMMANDS]
        parsed = usage, groups, children
        commands[command] = parsed
        for name, _ in parsed[2]:
            visit((*command, name))
    visit(())
    commands[("--self-update",)] = parse_help(read_help(binary, ("--self-update",)))
    return commands


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    commands = collect(args.binary.resolve())
    expected = set(commands)
    seen = set()
    changed = False
    for path in sorted((ROOT / "docs" / "commands").glob("*.md")):
        original = path.read_text()
        def replace(match):
            command = tuple(match[1].split()) if match[1] != "syq" else ()
            if command in seen or command not in commands:
                raise ValueError(f"duplicate or obsolete command block: {command}")
            seen.add(command)
            return f"<!-- CLI: {match[1]} -->\n{render(command, commands[command], commands)}<!-- /CLI -->"
        updated = BLOCK.sub(replace, original)
        if updated != original:
            changed = True
            if args.check:
                print(f"{path.relative_to(ROOT)}: reference differs from CLI help")
                sys.stdout.writelines(difflib.unified_diff(original.splitlines(True), updated.splitlines(True), n=1))
            else:
                path.write_text(updated)
    key_errors = []
    # Group references must list the exact key inventory, even though the
    # command tables link to those pages instead of repeating their long help.
    for flag, page in [("--performance-tuning", "tuning.md"),
                       ("--resource-limits", "resource-limits.md"),
                       ("--integrity-checking", "integrity-checking.md")]:
        descriptions = [" ".join(description)
                        for _, rows in commands[("cp",)][1]
                        for signature, description in rows if signature.startswith(flag + " ")]
        if len(descriptions) != 1:
            raise ValueError(f"missing advanced group in cp help: {flag}")
        keys = set(re.findall(r"(?<![\w-])([a-z][a-z-]*)=", descriptions[0]))
        text = (ROOT / "docs" / page).read_text()
        documented = set(re.findall(r"^\| `([a-z][a-z-]*)` \|", text, re.M))
        if keys != documented:
            key_errors.append(f"{page}: missing keys {sorted(keys - documented)}, obsolete keys {sorted(documented - keys)}")
    for error in key_errors:
        print(error)
    missing = expected - seen
    if missing:
        print("Missing command sections: " + ", ".join(" ".join(c) or "syq" for c in sorted(missing)))
    print(f"{'Checked' if args.check else 'Updated'} {len(seen)} command sections")
    return int(bool(missing) or bool(key_errors) or (args.check and changed))


if __name__ == "__main__":
    sys.exit(main())
