# collect-logs

Collect logs from every node in a deployed enterprise at three phases:
1) **pre** — after deployment, before any workflow runs  
2) **after each impact**  
3) **after each workflow run** (with `name[:N]` semantics)

## Highlights
- **No controller needed.**
- **Credentials**: parsed from `post-deploy-output.json` (`deployed.nodes[].addresses[].addr` and `password` per node).  
  Defaults: Windows user `Administrator`, Linux user `ubuntu`.
- **Transport**: uses your project’s `shell_handler.ShellHandler` (host, user, password).
- **Workflows & impacts (ordered)**:
  - `--impact <action>` follows your `impact.py` action format.
  - `--workflow <name[:N]>` repeats in the order given.
  - Uses `simulate-logins.py` then `emulate-logins.py --workflows <name>` per run.
- **Seeds**: `--seed` (default epoch-seconds), recorded in metadata; `emulate` uses `seed = base + run_index*9973`.
- **File capture**:
  - Windows: CBS/DISM/Panther, ProgramData\Elastic Agent\logs, inetpub logs, OpenSSH, wevtutil exports.
  - Linux: `/var/log/**`, journal export, Elastic Agent logs, Zeek logs.
  - Oversize handling: `--max-per-file-mb` tails from the **end**; `--max-collection-mb` caps per-node-per-step.
- **Storage mode**: `--store-mode compressed|expanded` (default: compressed). Expanded will unpack archives locally as well.
- **Overlap-trim sidecars (deltas)** — **always on**, even with compressed snapshots:
  - After each step, the tool computes **line overlap** between the **concatenated previous steps’ tail** and the **current step’s head** per file/path.
  - Writes sidecars: `*.continued-since-<firstprev>-to-<lastprev>.txt` containing **only the continued lines** (curr[k:]).
  - If no previous snapshot, sidecar equals the full file.
  - If multiple previous snapshots, the overlap is with **(1 + 2 + ... + N-1)**, so the “2nd suffix includes all of the 1st,” the “3rd includes 1+2,” etc.
  - Works the same for compressed (auto-extracts to `decompressed/`) and expanded (`extracted/`) trees.

- **Pruning full files** (default **ON**):
  - `-P/--prune-full-after-diff` (default) or `--no-prune-full-after-diff`.
  - After a sidecar is successfully written, delete the **full extracted/decompressed file copy** for that step.
  - Archives themselves are never deleted.
  - Lineage metadata is appended to `nodes/<node>/manifest.json`:
    ```json
    {
      "relpath": "var/log/syslog",
      "ancestor_step": "workflow-browse_iis-run01",
      "ancestor_relpath": "var/log/syslog",
      "overlap_lines": 1387,
      "pruned_after_sidecar": true,
      "full_bytes": 1048576,
      "full_sha256": "…",
      "no_ancestry_reason": null
    }
    ```
  - If there is no previous snapshot, or no overlap, or pruning disabled, we still record a lineage item with `ancestor_step: null` or a suitable `no_ancestry_reason`.

## Usage
```bash
python3 collect-logs.py   -p ./post-deploy-output.json   --user-roles ./user-roles/user-roles.json   --enterprise-json ./enterprise.json   -i availability=dc1   -w browse_iis:2   -i integrity=dc2   -w moodle:3   -o ./logs   -I '*' -E '*.gz'   -m 256 -M 4096   -S compressed   -v   --seed 424242   --prune-full-after-diff     # default ON; use --no-prune-full-after-diff to keep full files
```

## Output layout (example)
```
logs/
  enterprise.meta.json
  steps/
    00-pre/
      nodes/<node>/logs.tar.zst|logs.zip
      nodes/<node>/manifest.json
      nodes/<node>/node.meta.json
      nodes/<node>/decompressed/… (if compressed and delta pass ran)
      nodes/<node>/extracted/…   (if store-mode=expanded)
    impact-availability=dc1/…
    workflow-browse_iis-run01/…
    workflow-browse_iis-run02/…
    workflow-moodle-run01/…
```

## Notes
- Concurrency default: unlimited (threads = number of nodes). Use `-c` to cap.
- Includes default to `'*'`, excludes default to none.
- We never delete archives. Only per-file copies in extracted/decompressed trees are pruned (when enabled).
