# Deployment recipes

| Path | What |
| --- | --- |
| [`helm/contextosd`](helm/contextosd/README.md) | Hardened Helm chart: deployment, migration hook, NetworkPolicy, agent egress, PDB, HPA, ServiceMonitor, alert rules, pack sync from git |
| [`contextosd.example.toml`](contextosd.example.toml) | A production configuration with every section explained |
| [`alerts`](alerts), [`grafana`](grafana) | Alert rule tests and the governance dashboard |
| [`kind/e2e.sh`](kind/e2e.sh) | The chart installed and exercised on a kind cluster, as CI does |

## Install

Follow the [chart README](helm/contextosd/README.md): create the Secret your config
names, write a values file, validate the config with `contextosd --check-config`, then
`helm install`. The default config serves nobody until you add credentials, packs and
providers.

## Publish packs from git

Keep packs in a repository that has its own review, and let every replica pick up new
versions without a restart.

1. **Repository layout.** Packs and their tests live together; built packs are
   committed beside their sources:

   ```text
   packs/
     support/pack-5.2.0.json        # released versions stay; never edit one in place
     support/pack-5.3.0.json        # built: ctx build support/pack.source.json --out …
     support/pack.source.json
     support/pack_test.json
   libraries/chargebacks.json
   cases/support.json               # replay cases exported from real runs
   ```

2. **The pack repository's CI** checks each change before it can merge:

   ```sh
   ctx build packs/support/pack.source.json --check packs/support/pack-5.3.0.json
   ctx test --pack packs/support/pack-5.3.0.json packs/support/pack_test.json --junit results.xml
   ctx gate --baseline packs/support/pack-5.2.0.json --candidate packs/support/pack-5.3.0.json \
            --cases cases/support.json
   ```

   [`skills/contextos-pack-authoring/scripts/check_pack.sh`](../skills/contextos-pack-authoring/scripts/check_pack.sh)
   runs the same checks plus `ctx inspect` and a plan per role.

3. **Sync it into each pod** with the chart's `packSync`, and read it as a pack directory:

   ```yaml
   packSync:
     enabled: true
     repo: https://git.example.com/acme/packs.git
     ref: main
     periodSeconds: 30
     secretName: pack-repo        # GITSYNC_USERNAME / GITSYNC_PASSWORD (a read-only token)
   config: |
     pack_dirs = ["/var/lib/contextos/pack-sync/current/packs"]
     pack_reload_secs = 30
     # … the rest of your configuration
   ```

   A git-sync init container checks the repository out before contextosd starts (a
   pack directory must exist at startup); a sidecar keeps it current and swaps the
   checkout atomically. contextosd re-reads it every `pack_reload_secs`, adds new pack
   versions, audits each as `pack_loaded`, and refuses a changed file under a loaded
   reference. A restart does not lift that: each reference is bound to its digest in
   the store, so a pod that starts with an edited file (a force-pushed repository)
   fails to start instead of serving other content under the old reference.

4. **Roll out** once every replica has the version. `POST /v1/packs/reload` through a
   Service reaches one pod, so wait `periodSeconds + pack_reload_secs` after the merge
   (each pod syncs and reloads on its own), then start a shadow rollout
   (`POST /v1/rollouts`, GUIDE "Roll out in stages"). A replica that has not loaded the
   candidate yet answers `pack_not_found`, never a wrong decision.

Merging to the synced branch is the authority to publish packs: protect it like the
policy it is (required reviews, the checks above as required status checks).

## Deliver audit to a SIEM

Configure an audit sink (GUIDE, "Deliver the audit chain to a SIEM, masked") pointing
at a small receiver you run next to your SIEM's collector. The receiver checks each
request's signature, drops duplicates, and forwards entries:

```python
import hashlib, hmac, json, os, time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ["CONTEXTOS_SIEM_SECRET"].encode()
seen = set()   # keep this durable in production: (tenant_id, sequence) is the key

def authentic(header: str, body: bytes) -> bool:
    fields = dict(part.split("=", 1) for part in header.split(","))
    if abs(time.time() - int(fields["t"])) > 300:
        return False
    expected = hmac.new(SECRET, f'{fields["t"]}.'.encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, fields["v1"])

class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["content-length"]))
        if not authentic(self.headers.get("contextos-signature", ""), body):
            self.send_response(401); self.end_headers(); return
        batch = json.loads(body)
        for entry in batch["entries"]:
            key = (entry["tenant_id"], entry["sequence"])
            if key not in seen:
                seen.add(key)
                print(json.dumps(entry))   # forward: Splunk HEC, an OTLP log exporter, a Kafka topic …
        self.send_response(200); self.end_headers()   # only after forwarding: a non-2xx is retried

HTTPServer(("0.0.0.0", 8443), Receiver).serve_forever()   # behind TLS in production
```

Answer 2xx only once the batch is stored or forwarded: contextosd retries a failed batch
until it is accepted and never skips ahead, so a receiver outage delays the export but
loses nothing. Keep the exported chain verifiable by archiving entries unchanged and
the signing keys from `GET /v1/audit/keys`; `ctx audit-verify` checks an archive
offline and lists the entries whose payloads were masked.
