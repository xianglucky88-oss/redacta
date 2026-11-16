import hashlib
import json
import os
import shutil
import sqlite3
import uuid
from collections import Counter
from pathlib import Path
from .policy import Policy, canonical
from .transforms import Transformer


class Publisher:
    def __init__(self, root, key, *, transformer=None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.transformer = transformer or Transformer(key)
        self.db = sqlite3.connect(self.root / "audit.sqlite", timeout=10)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS policies (digest TEXT PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS releases (
              id TEXT PRIMARY KEY, policy TEXT NOT NULL, status TEXT NOT NULL,
              manifest TEXT NOT NULL, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        """)

    def publish(self, tables, policy):
        if not isinstance(policy, Policy):
            policy = Policy(policy)
        specs = policy.document["tables"]
        if set(tables) != set(specs):
            raise ValueError("input tables must exactly match the policy")
        transformed, totals = {}, {}
        for table, spec in specs.items():
            rows = []
            for row in tables[table]:
                if set(row) != set(spec["fields"]):
                    raise ValueError(f"{table}: undeclared or missing input fields")
                output = {field: self.transformer.apply(value, spec["fields"][field], row.get(spec.get("subject")))
                          for field, value in row.items() if spec["fields"][field]["op"] != "drop"}
                rows.append(output)
            totals[table] = len(rows)
            quasi = spec.get("quasi", [])
            counts = Counter(canonical([row[q] for q in quasi]) for row in rows)
            transformed[table] = [row for row in rows
                                  if counts[canonical([row[q] for q in quasi])] >= spec.get("k", 1)]
        # Cascading link suppression reaches a fixed point. Removing a parent must
        # never leave published child rows referring to suppressed entities.
        while True:
            changed = False
            for table, spec in specs.items():
                rows = transformed[table]
                for link in spec.get("links", []):
                    allowed = {row[link["target"]] for row in transformed[link["table"]]}
                    rows = [row for row in rows if row[link["field"]] in allowed]
                quasi = spec.get("quasi", [])
                counts = Counter(canonical([row[q] for q in quasi]) for row in rows)
                rows = [row for row in rows if counts[canonical([row[q] for q in quasi])] >= spec.get("k", 1)]
                changed |= len(rows) != len(transformed[table])
                transformed[table] = rows
            if not changed:
                break
        release_id = uuid.uuid4().hex
        stage = self.root / (".stage-" + release_id)
        destination = self.root / release_id
        stage.mkdir(mode=0o700)
        try:
            manifest = {"id": release_id, "policy": policy.digest, "policy_version": policy.document["version"], "tables": {}}
            for table, rows in transformed.items():
                content = "".join(canonical(row) + "\n" for row in rows).encode()
                (stage / (table + ".jsonl")).write_bytes(content)
                manifest["tables"][table] = {"rows": len(rows), "suppressed": totals[table] - len(rows),
                                             "sha256": hashlib.sha256(content).hexdigest()}
            (stage / "manifest.json").write_text(canonical(manifest), encoding="utf-8")
            with self.db:
                self.db.execute("INSERT OR IGNORE INTO policies VALUES (?,?)", (policy.digest, canonical(policy.document)))
                self.db.execute("INSERT INTO releases(id,policy,status,manifest) VALUES (?,?,?,?)",
                                (release_id, policy.digest, "active", canonical(manifest)))
                stage.rename(destination)
            return manifest
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            shutil.rmtree(destination, ignore_errors=True)
            raise

    def _lookup(self, release_id):
        if not isinstance(release_id, str) or len(release_id) != 32 or any(c not in "0123456789abcdef" for c in release_id):
            raise ValueError("invalid release id")
        row = self.db.execute("SELECT status,manifest FROM releases WHERE id=?", (release_id,)).fetchone()
        if row is None:
            raise KeyError("unknown release")
        return row[0], json.loads(row[1])

    def read(self, release_id, table):
        status, manifest = self._lookup(release_id)
        if status != "active":
            raise ValueError("release is revoked")
        if table not in manifest["tables"]:
            raise KeyError(table)
        content = (self.root / release_id / (table + ".jsonl")).read_bytes()
        if hashlib.sha256(content).hexdigest() != manifest["tables"][table]["sha256"]:
            raise ValueError("release checksum mismatch")
        return [json.loads(line) for line in content.splitlines()]

    def revoke(self, release_id):
        self._lookup(release_id)
        with self.db:
            self.db.execute("UPDATE releases SET status='revoked' WHERE id=?", (release_id,))
        shutil.rmtree(self.root / release_id, ignore_errors=False) if (self.root / release_id).exists() else None

    def close(self):
        self.db.close()
