"""Unit tests for VirtualFS."""
from plenith.vfs import VirtualFS


class TestCanonicalPath:
    def test_absolute_path_passthrough(self):
        assert VirtualFS.canonical_path("/etc/passwd", cwd=None, home=None) == "/etc/passwd"

    def test_relative_path_against_cwd(self):
        assert VirtualFS.canonical_path("foo", cwd="/tmp", home=None) == "/tmp/foo"

    def test_tilde_expands_to_home(self):
        assert VirtualFS.canonical_path("~", cwd=None, home="/home/jdoe") == "/home/jdoe"
        assert VirtualFS.canonical_path("~/.ssh/id_rsa", cwd=None, home="/home/jdoe") == "/home/jdoe/.ssh/id_rsa"

    def test_dotdot_collapses(self):
        assert VirtualFS.canonical_path("../foo", cwd="/tmp/bar", home=None) == "/tmp/foo"

    def test_dot_drops(self):
        assert VirtualFS.canonical_path("./foo", cwd="/tmp", home=None) == "/tmp/foo"

    def test_empty_path(self):
        assert VirtualFS.canonical_path("", cwd=None, home=None) == ""


class TestReadWrite:
    def test_write_then_read(self):
        v = VirtualFS()
        v.write("/tmp/foo", "hello\n", cwd=None, home=None)
        assert v.read("/tmp/foo", cwd=None, home=None) == "hello\n"

    def test_read_missing_returns_none(self):
        v = VirtualFS()
        assert v.read("/nonexistent", cwd=None, home=None) is None

    def test_overwrite(self):
        v = VirtualFS()
        v.write("/tmp/foo", "first", cwd=None, home=None)
        v.write("/tmp/foo", "second", cwd=None, home=None)
        assert v.read("/tmp/foo", cwd=None, home=None) == "second"

    def test_append(self):
        v = VirtualFS()
        v.write("/tmp/foo", "a", cwd=None, home=None)
        v.write("/tmp/foo", "b", cwd=None, home=None, append=True)
        assert v.read("/tmp/foo", cwd=None, home=None) == "ab"

    def test_append_to_missing_creates(self):
        v = VirtualFS()
        v.write("/tmp/foo", "first", cwd=None, home=None, append=True)
        assert v.read("/tmp/foo", cwd=None, home=None) == "first"

    def test_touch_creates_empty(self):
        v = VirtualFS()
        v.touch("/tmp/foo", cwd=None, home=None)
        assert v.read("/tmp/foo", cwd=None, home=None) == ""
        assert v.exists("/tmp/foo", cwd=None, home=None)

    def test_touch_doesnt_overwrite(self):
        v = VirtualFS()
        v.write("/tmp/foo", "existing", cwd=None, home=None)
        v.touch("/tmp/foo", cwd=None, home=None)
        assert v.read("/tmp/foo", cwd=None, home=None) == "existing"


class TestUnlink:
    def test_unlink_removes(self):
        v = VirtualFS()
        v.write("/tmp/foo", "x", cwd=None, home=None)
        v.unlink("/tmp/foo", cwd=None, home=None)
        assert v.read("/tmp/foo", cwd=None, home=None) is None

    def test_unlink_then_write_recreates(self):
        v = VirtualFS()
        v.write("/tmp/foo", "x", cwd=None, home=None)
        v.unlink("/tmp/foo", cwd=None, home=None)
        v.write("/tmp/foo", "y", cwd=None, home=None)
        assert v.read("/tmp/foo", cwd=None, home=None) == "y"

    def test_unlink_tracks_deletion(self):
        v = VirtualFS({"/tmp/foo": "seeded"})
        v.unlink("/tmp/foo", cwd=None, home=None)
        assert not v.exists("/tmp/foo", cwd=None, home=None)


class TestListDirectory:
    def test_lists_immediate_children(self):
        v = VirtualFS({
            "/home/jdoe/.bashrc": "",
            "/home/jdoe/.ssh/config": "",
            "/home/jdoe/.ssh/id_rsa": "",
            "/home/jdoe/notes.md": "",
        })
        files, dirs = v.list_directory_typed("/home/jdoe", cwd=None, home=None)
        assert ".bashrc" in files
        assert "notes.md" in files
        assert ".ssh" in dirs
        assert ".bashrc" not in dirs
        assert ".ssh" not in files

    def test_empty_dir(self):
        v = VirtualFS()
        files, dirs = v.list_directory_typed("/tmp", cwd=None, home=None)
        assert files == []
        assert dirs == []

    def test_skips_deleted(self):
        v = VirtualFS({"/tmp/foo": "x", "/tmp/bar": "y"})
        v.unlink("/tmp/foo", cwd=None, home=None)
        files, _ = v.list_directory_typed("/tmp", cwd=None, home=None)
        assert "foo" not in files
        assert "bar" in files


class TestSerialization:
    def test_to_dict_then_restore(self):
        v1 = VirtualFS({"/a": "1", "/b": "2"})
        v1.unlink("/a", cwd=None, home=None)
        v1.write("/c", "3", cwd=None, home=None)
        snapshot = v1.to_dict()

        v2 = VirtualFS()
        v2.restore(snapshot)
        assert v2.read("/a", cwd=None, home=None) is None  # deleted
        assert v2.read("/b", cwd=None, home=None) == "2"
        assert v2.read("/c", cwd=None, home=None) == "3"

    def test_snapshot_excludes_deleted(self):
        v = VirtualFS({"/a": "1"})
        v.unlink("/a", cwd=None, home=None)
        assert v.snapshot() == {}


class TestDynamicRenderers:
    """Time-sensitive synthetic files (auth.log, etc.) need to re-render on
    every read so a multi-day engagement keeps showing 'today' in the
    planted history instead of 'whenever the engagement was first created'.
    Attacker tampering must take precedence over freshness — when the
    attacker writes to or deletes a dynamic path, the renderer drops and
    the persisted content (the attacker's modification) survives, which is
    what the tamper-detection heuristics need."""

    def test_renderer_called_on_each_read(self):
        v = VirtualFS()
        counter = {"n": 0}

        def renderer():
            counter["n"] += 1
            return f"call-{counter['n']}"

        v.register_dynamic("/var/log/auth.log", renderer)
        assert v.read("/var/log/auth.log", cwd=None, home=None) == "call-1"
        assert v.read("/var/log/auth.log", cwd=None, home=None) == "call-2"
        assert v.read("/var/log/auth.log", cwd=None, home=None) == "call-3"

    def test_attacker_write_drops_renderer(self):
        v = VirtualFS()
        v.register_dynamic("/var/log/auth.log", lambda: "FRESH")
        assert v.read("/var/log/auth.log", cwd=None, home=None) == "FRESH"
        # Attacker overwrites — classic log-tampering pattern
        v.write("/var/log/auth.log", "EMPTIED", cwd=None, home=None)
        assert v.read("/var/log/auth.log", cwd=None, home=None) == "EMPTIED"
        # Subsequent reads keep returning the tampered content, not fresh
        assert v.read("/var/log/auth.log", cwd=None, home=None) == "EMPTIED"

    def test_attacker_unlink_drops_renderer(self):
        v = VirtualFS()
        v.register_dynamic("/var/log/auth.log", lambda: "FRESH")
        v.read("/var/log/auth.log", cwd=None, home=None)
        v.unlink("/var/log/auth.log", cwd=None, home=None)
        # Deleted stays deleted — even if renderer would otherwise produce
        # fresh content, the attacker-visible state is "removed".
        assert v.read("/var/log/auth.log", cwd=None, home=None) is None

    def test_system_write_with_tamper_false_keeps_renderer(self):
        v = VirtualFS()
        rendered = ["FRESH-1", "FRESH-2", "FRESH-3"]
        v.register_dynamic("/var/log/auth.log", lambda: rendered.pop(0))
        # System-driven write (e.g. initial seed) must NOT drop the renderer
        v.write("/var/log/auth.log", "seed-content", cwd=None, home=None, tamper=False)
        # Read still re-renders because the path isn't tampered
        assert v.read("/var/log/auth.log", cwd=None, home=None) == "FRESH-1"
        assert v.read("/var/log/auth.log", cwd=None, home=None) == "FRESH-2"

    def test_tampered_state_round_trips_through_persistence(self):
        v1 = VirtualFS()
        v1.register_dynamic("/var/log/auth.log", lambda: "WOULD-BE-FRESH")
        v1.write("/var/log/auth.log", "ATTACKER-TAMPERED", cwd=None, home=None)
        snapshot = v1.to_dict()

        v2 = VirtualFS()
        v2.restore(snapshot)
        # Re-register the renderer on the restored VFS — simulating what
        # Session._register_dynamic_renderers does on engagement restore.
        v2.register_dynamic("/var/log/auth.log", lambda: "WOULD-BE-FRESH")
        # Tampering survived: renderer is registered but the path is still
        # tampered, so the persisted attacker content wins.
        assert v2.read("/var/log/auth.log", cwd=None, home=None) == "ATTACKER-TAMPERED"

    def test_untampered_renderer_re_enables_after_restore(self):
        """A common case: the engagement persists across days, the
        attacker hasn't touched auth.log, and we want subsequent reads to
        keep showing 'today's' login activity rather than the stale
        snapshot. Renderer re-registration on restore must work."""
        v1 = VirtualFS()
        calls = []
        v1.register_dynamic("/var/log/auth.log", lambda: "day-old-content")
        v1.read("/var/log/auth.log", cwd=None, home=None)  # populates cache
        snapshot = v1.to_dict()

        v2 = VirtualFS()
        v2.restore(snapshot)
        v2.register_dynamic(
            "/var/log/auth.log",
            lambda: (calls.append(1), "fresh-content")[1],
        )
        # Untampered path: renderer fires again, producing fresh content
        assert v2.read("/var/log/auth.log", cwd=None, home=None) == "fresh-content"
        assert len(calls) == 1

    def test_renderer_exception_falls_back_to_static(self):
        """Defensive: a buggy renderer must not break a `cat` call. Fall
        back to whatever static content the VFS had cached."""
        v = VirtualFS()
        v.write("/var/log/auth.log", "static-fallback", cwd=None, home=None, tamper=False)

        def bad_renderer():
            raise RuntimeError("renderer is broken")

        v.register_dynamic("/var/log/auth.log", bad_renderer)
        # Doesn't raise — returns the cached static content
        assert v.read("/var/log/auth.log", cwd=None, home=None) == "static-fallback"
