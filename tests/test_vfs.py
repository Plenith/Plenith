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
