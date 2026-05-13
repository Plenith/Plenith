import os
from pathlib import Path
import yaml


class Persona:
    def __init__(self, data):
        self.username = data["username"]
        self.full_name = data.get("full_name", "")
        self.title = data.get("title", "")
        self.department = data.get("department", "")
        # In the Linux fork each agent container sets PLENITH_HOSTNAME so
        # every persona on this agent claims that container's hostname (so
        # bash prompts, /etc/hostname, and auth.log reflect e.g. db-prod-01
        # vs api-prod-03 instead of the YAML default `corp-app01`). The env
        # var overrides any value in the YAML.
        self.hostname = os.environ.get("PLENITH_HOSTNAME") or data.get("hostname", "host")
        self.home = data.get("home", f"/home/{self.username}")
        self.shell = data.get("shell", "/bin/bash")
        self.os_release = data.get("os_release", "")
        self.uname = data.get("uname", "")
        self.id_output = data.get("id_output", f"uid=1000({self.username}) gid=1000({self.username})")
        self.groups = data.get("groups", [self.username])
        self.home_listing = data.get("home_listing", [])
        self.recent_projects = data.get("recent_projects", [])
        self.notes = data.get("notes", "")
        # Optional persona-specific pool that `synthetic.gen_bash_history`
        # samples from. Default pool is the generic developer set in
        # synthetic.py.
        self.bash_history_pool = data.get("bash_history_pool")

    @classmethod
    def from_yaml(cls, path):
        with open(path, "r", encoding="utf-8") as f:
            return cls(yaml.safe_load(f))

    def template_vars(self):
        return {
            "user": self.username,
            "hostname": self.hostname,
            "id_output": self.id_output,
            "uname": self.uname,
            "os_release": self.os_release,
        }


def load_persona(personas_dir, username):
    candidate = Path(personas_dir) / f"{username}.yaml"
    if candidate.exists():
        return Persona.from_yaml(candidate)
    fallback = Path(personas_dir) / "jdoe.yaml"
    if fallback.exists():
        return Persona.from_yaml(fallback)
    raise FileNotFoundError(f"No persona for {username} and no default jdoe.yaml")
