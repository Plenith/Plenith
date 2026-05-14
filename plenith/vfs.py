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
        # Dynamic re-render hooks — path -> callable() -> str. When a path
        # is read AND not tampered, the renderer is called and its output
        # is returned (and cached as the new static content). Used to keep
        # time-sensitive synthetic files like /var/log/auth.log current
        # across long-lived engagements without saturating disk on every
        # read. Not serialized — Session re-registers on restore.
        self._dynamic = {}
        # Paths the attacker has written to or deleted. Once tampered, a
        # path's dynamic renderer is permanently dropped — preserving the
        # attacker-visible modification (covering-tracks behavior is itself
        # the signal we want to detect; we mustn't overwrite it with a
        # fresh render).
        self._tampered = set()

    # --- public API -------------------------------------------------------

    def register_dynamic(self, path, renderer, cwd=None, home=None):
        """Register a renderer that produces fresh content each time `path`
        is read. Useful for synthetic files whose realism degrades over
        time (auth.log dates, uptime, last-output) — re-rendering on read
        keeps the honeypot's planted history current regardless of how
        long the engagement has been running.

        The renderer is dropped the first time the attacker writes to or
        deletes the path. Tampering preservation > freshness."""
        p = self._canon(path, cwd, home)
        self._dynamic[p] = renderer

    def read(self, path, cwd, home):
        p = self._canon(path, cwd, home)
        if p in self._deleted:
            return None
        # Dynamic-renderer path: re-render so time-sensitive content stays
        # current. Tampered paths skip the renderer so the attacker's
        # modification persists for tamper-detection heuristics.
        if p in self._dynamic and p not in self._tampered:
            try:
                fresh = self._dynamic[p]()
                self._files[p] = fresh
                return fresh
            except Exception:
                # Defensive: if a renderer throws, fall back to whatever
                # static content we last had. Better to serve stale than
                # to break a `cat` call.
                pass
        return self._files.get(p)

    def exists(self, path, cwd, home):
        p = self._canon(path, cwd, home)
        return p in self._files and p not in self._deleted

    def write(self, path, content, cwd, home, append=False, *, tamper=True):
        """Write content to a path. By default this marks the path as
        tampered, dropping any registered dynamic renderer. Pass
        `tamper=False` for system-driven writes (initial seeding) that
        shouldn't disable freshness re-rendering."""
        p = self._canon(path, cwd, home)
        self._deleted.discard(p)
        if tamper:
            self._tampered.add(p)
        if append and p in self._files:
            self._files[p] = self._files[p] + content
        else:
            self._files[p] = content

    def touch(self, path, cwd, home):
        p = self._canon(path, cwd, home)
        self._deleted.discard(p)
        self._tampered.add(p)
        self._files.setdefault(p, "")

    def unlink(self, path, cwd, home):
        p = self._canon(path, cwd, home)
        self._files.pop(p, None)
        self._tampered.add(p)
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
        """Full serializable representation (files + deletion tombstones +
        tampering flags). Use with `restore()` to round-trip across
        persistence boundaries.

        Note: registered dynamic renderers are NOT serialized — they're
        Python callables tied to live runtime state. The Session is
        responsible for re-registering them after restore (see
        `Session._register_dynamic_renderers`)."""
        return {
            "files": dict(self._files),
            "deleted": sorted(self._deleted),
            "tampered": sorted(self._tampered),
        }

    def restore(self, data):
        """Replace VFS contents from a dict produced by `to_dict()`.
        `_tampered` is restored so that dynamic renderers re-registered
        after this call correctly skip paths the attacker already
        modified."""
        self._files = dict(data.get("files", {}))
        self._deleted = set(data.get("deleted", []))
        self._tampered = set(data.get("tampered", []))
        self._dynamic = {}   # callers must re-register

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
