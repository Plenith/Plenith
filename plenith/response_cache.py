import datetime as dt
import re
import yaml

class ResponseCache:
    def __init__(self, cache_path):
        with open(cache_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        self.exact = data.get("exact", {}) or {}
        self.prefix = data.get("prefix", {}) or {}

    def lookup(self, cmd, persona, cwd):
        c = cmd.strip()
        if not c:
            return ""

        # Dynamic responses first.
        if c == "date":
            return dt.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y") + "\n"
        if c in ("ls", "ls -la", "ls -l", "ls -a", "ll"):
            return self._render_ls(c, persona, cwd)
        # Plain `echo foo` only — skip if there's a redirect/pipe/$. The
        # orchestrator handles `echo ... > file` ahead of the cache.
        if c.startswith("echo ") and not any(x in c[5:] for x in (">", ">>", "|", "$")):
            return c[5:] + "\n"
        if c == "pwd":
            return cwd + "\n"

        vars_ = {
            "user": persona.username,
            "cwd": cwd,
            "hostname": persona.hostname,
            "id_output": persona.id_output,
            "uname": persona.uname,
            "os_release": persona.os_release,
        }

        if c in self.exact:
            raw = self.exact[c]
            if raw == "":
                return None
            return self._format(raw, vars_)

        return None

    def _render_ls(self, variant, persona, cwd):
        listing = persona.home_listing if cwd == persona.home else []
        if not listing:
            return ""
        if variant in ("ls", "ls -a"):
            items = listing[:]
            if variant == "ls -a":
                items = [".", ".."] + items
            return "  ".join(items) + "\n"
        # long form
        lines = []
        if variant in ("ls -la", "ls -a"):
            lines.append(_long_entry("drwxr-xr-x", 5, persona, "."))
            lines.append(_long_entry("drwxr-xr-x", 3, persona, ".."))
        for name in listing:
            mode = "drwxr-xr-x" if not name.startswith(".") and "." not in name else "-rw-r--r--"
            if name in ("projects", ".ssh", ".aws"):
                mode = "drwx------" if name.startswith(".") else "drwxr-xr-x"
            lines.append(_long_entry(mode, 1, persona, name))
        return "total " + str(len(listing) * 4) + "\n" + "\n".join(lines) + "\n"

    def _format(self, raw, vars_):
        try:
            return raw.format(**vars_)
        except (KeyError, IndexError):
            return raw

def _long_entry(mode, links, persona, name):
    return f"{mode} {links} {persona.username} {persona.username} 4096 May 11 09:14 {name}"
