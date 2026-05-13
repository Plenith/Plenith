"""Virtual filesystem for a single deception session.

Backs the simulated /home/<persona> tree so the attacker's writes survive
across commands in the same session:

    $ echo "secret" > /tmp/foo
    $ cat /tmp/foo
    secret

Honeytokens (synthetic.py) are loaded as initial state — they are just
pre-seeded VFS entries. Attacker writes can shadow or delete them.

Design choices:
- Canonical absolute POSIX paths internally. `~` and relative paths are
  resolved at the boundary using `(cwd, persona.home)`.
- File-only model. Directories are inferred from the set of file paths;
  we don't track empty directories. `mkdir foo` is a no-op for the MVP.
- No metadata (mtime, mode, owner). Real shells show these in `ls -l` etc.;
  the response_cache renders plausible values from persona, not the VFS.
- Cross-session: nothing persists. Each `Session` gets a fresh VFS.
"""
import posixpath


class VirtualFS:
    def __init__(self, seed_files=None):
        # path -> content bytes (str for now)
        self._files = {}
        if seed_files:
            for path, content in seed_files.items():
                self._files[self._canon(path, cwd=None, home=None)] = content
        # Files that have been explicitly deleted. Tracked so a stat-style
        # call can distinguish "never existed" from "removed by attacker".
        self._deleted = set()

    # --- public API -------------------------------------------------------

    def read(self, path, cwd, home):
        p = self._canon(path, cwd, home)
        if p in self._deleted:
            return None
        return self._files.get(p)

    def exists(self, path, cwd, home):
        p = self._canon(path, cwd, home)
        return p in self._files and p not in self._deleted

    def write(self, path, content, cwd, home, append=False):
        p = self._canon(path, cwd, home)
        self._deleted.discard(p)
        if append and p in self._files:
            self._files[p] = self._files[p] + content
        else:
            self._files[p] = content

    def touch(self, path, cwd, home):
        p = self._canon(path, cwd, home)
        self._deleted.discard(p)
        self._files.setdefault(p, "")

    def unlink(self, path, cwd, home):
        p = self._canon(path, cwd, home)
        self._files.pop(p, None)
        self._deleted.add(p)

    def list_under(self, prefix, cwd, home):
        """All file paths whose canonical form starts with `prefix`."""
        pfx = self._canon(prefix, cwd, home).rstrip("/") + "/"
        return sorted(p for p in self._files if p.startswith(pfx) and p not in self._deleted)

    def list_directory_typed(self, path, cwd, home):
        """Immediate children of `path` split into (files, dirs).

        Directories are *inferred* from longer paths in the VFS — if any
        file exists at `path/foo/bar`, then `foo` is reported as a dir.
        Empty directories (no files inside) aren't tracked and don't appear.
        """
        canon = self._canon(path, cwd, home)
        prefix = canon.rstrip("/") + "/" if canon != "/" else "/"
        files = set()
        dirs = set()
        for p, _body in self._files.items():
            if p in self._deleted:
                continue
            if not p.startswith(prefix):
                continue
            rest = p[len(prefix):]
            if not rest:
                continue
            parts = rest.split("/", 1)
            if len(parts) == 1:
                files.add(parts[0])
            else:
                dirs.add(parts[0])
        return sorted(files), sorted(dirs)

    def snapshot(self):
        """Plain dict of canonical path -> content, for serialization or
        for showing the LLM what currently exists."""
        return {p: c for p, c in self._files.items() if p not in self._deleted}

    def to_dict(self):
        """Full serializable representation (files + deletion tombstones).
        Use with `restore()` to round-trip across persistence boundaries.
        """
        return {
            "files": dict(self._files),
            "deleted": sorted(self._deleted),
        }

    def restore(self, data):
        """Replace VFS contents from a dict produced by `to_dict()`."""
        self._files = dict(data.get("files", {}))
        self._deleted = set(data.get("deleted", []))

    # --- internals --------------------------------------------------------

    @classmethod
    def canonical_path(cls, path, cwd, home):
        """Public alias for the canonical-path resolver — used by Session
        to keep observation-key paths in the same form as VFS keys."""
        return cls._canon(path, cwd, home)

    @staticmethod
    def _canon(path, cwd, home):
        """Canonicalize a path into a POSIX absolute path.

        `~` and `~/...` are expanded using `home`. Relative paths are
        resolved against `cwd`. Result has no trailing slash (except '/').
        """
        if not path:
            return ""
        if path == "~" or path.startswith("~/"):
            if home:
                path = home + path[1:]
            else:
                path = "/" + path[1:].lstrip("/")
        if not path.startswith("/"):
            base = cwd or "/"
            path = posixpath.join(base, path)
        path = posixpath.normpath(path)
        # normpath uses os.sep on Windows; force POSIX.
        path = path.replace("\\", "/")
        return path
