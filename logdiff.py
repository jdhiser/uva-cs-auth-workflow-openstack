#!/usr/bin/env python3
"""
logdiff.py
-----------

A self-contained module and CLI that turns a baseline+steps log capture tree into
compact, append-aware diffs.

Policy:
- Baseline (steps/baseline) is stored in full (as originally captured).
- For each later step (e.g., steps/after-01-workflow-foo), per node:
  * Unpack archive to a working area
  * Convert binary logs (e.g., EVTX) to human-readable, line-oriented text
  * Compare each file against the cumulative prior state for that node
  * Apply append-aware policy: remove the longest suffix of the prior file that matches
    the head (prefix) of the current file; store only the remaining tail
  * For no-overlap or rotation/rewrite cases, store the full text version
  * Always compress the step’s diff bundle into diff/<node>.diff.tgz
- Optionally retain unpacked and patched (prior-state) trees on disk.

CLI:
    logdiff build -i RUN_ROOT [-o DIFF_ROOT] [-k] [-v]
    logdiff apply -i RUN_ROOT -o RECONSTRUCT_ROOT [-s STEP] [-v]

Importable API:
    from logdiff import build_diffs, apply_diffs
    build_diffs(run_root="/path/to/run", out_root="/path/to/out", keep_unpacked=False, verbose=False)

Notes:
- Conversion for EVTX uses python-evtx if available. If not installed, the converter will
  fall back to storing the binary as a full-file replacement (with a warning).
- Supports both .zip and .tar.gz per-node archives.
- No prune/ignore patterns.

Author: ChatGPT
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# -----------------------------
# Utilities & helpers
# -----------------------------

def _is_zip(path: Path) -> bool:
    return path.suffix.lower() == ".zip"


def _is_targz(path: Path) -> bool:
    s = "".join(path.suffixes).lower()
    return s.endswith(".tar.gz") or s.endswith(".tgz")


def _norm_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _read_text_file(p: Path) -> str:
    data = p.read_bytes()
    try:
        s = data.decode("utf-8", errors="replace")
    except Exception:
        s = data.decode("latin-1", errors="replace")
    return _norm_newlines(s)


def _write_text_file(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_norm_newlines(content), encoding="utf-8")


# -----------------------------
# Archive unpacking
# -----------------------------

def unpack_archive(archive_path: Path, dst_dir: Path) -> None:
    dst_dir.mkdir(parents=True, exist_ok=True)
    if _is_zip(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dst_dir)
    elif _is_targz(archive_path):
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(dst_dir)
    else:
        raise ValueError(f"Unsupported archive format: {archive_path}")


# -----------------------------
# EVTX conversion (best effort)
# -----------------------------

def _try_import_evtx():
    try:
        import Evtx  # type: ignore
        return Evtx
    except Exception:
        return None


def convert_evtx_file_to_lines(evtx_path: Path) -> Optional[str]:
    Evtx = _try_import_evtx()
    if Evtx is None:
        sys.stderr.write(f"[logdiff] WARN: python-evtx not available; treating EVTX as binary: {evtx_path}\n")
        return None

    try:
        from Evtx.Evtx import Evtx as EvtxReader  # type: ignore
        from Evtx.Views import evtx_file_xml_view  # type: ignore
    except Exception:
        # Fallback to basic record iteration if views unavailable
        try:
            from Evtx.Evtx import Evtx as EvtxReader  # type: ignore
            ev = EvtxReader(str(evtx_path))
            lines: List[str] = []
            for record in ev.records():  # type: ignore
                try:
                    xml = record.xml()
                    if not isinstance(xml, str):
                        xml = str(xml)
                except Exception:
                    xml = str(record)
                lines.append(" ".join(xml.split()))
            return ("\n".join(lines) + "\n") if lines else ""
        except Exception:
            sys.stderr.write(f"[logdiff] WARN: EVTX conversion failed for: {evtx_path}\n")
            return None

    try:
        xml_text = evtx_file_xml_view(str(evtx_path))  # type: ignore
        flat = " ".join(xml_text.split())
        flat = flat.replace("</Event><Event", "</Event>\n<Event")
        return flat + ("" if flat.endswith("\n") else "\n")
    except Exception:
        sys.stderr.write(f"[logdiff] WARN: EVTX conversion via views failed for: {evtx_path}\n")
        return None


def convert_tree_binaries_to_text(src_dir: Path, dst_dir: Path) -> None:
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)

    for root, dirs, files in os.walk(src_dir):
        root_p = Path(root)
        rel_root = root_p.relative_to(src_dir)
        out_root = dst_dir / rel_root
        out_root.mkdir(parents=True, exist_ok=True)

        for fn in files:
            sp = root_p / fn
            dp = out_root / fn

            if sp.suffix.lower() == ".evtx":
                converted = convert_evtx_file_to_lines(sp)
                if converted is not None:
                    _write_text_file(dp.with_suffix(dp.suffix + ".txt"), converted)
                else:
                    shutil.copy2(sp, dp)
                continue

            # Try text copy; else binary copy
            try:
                s = _read_text_file(sp)
                _write_text_file(dp, s)
            except Exception:
                shutil.copy2(sp, dp)


# -----------------------------
# Append-aware diff policy
# -----------------------------

def longest_suffix_prefix_overlap(prev_text: str, curr_text: str) -> int:
    """
    Return length of the longest suffix of prev_text that equals the prefix of curr_text.
    KMP-style prefix on combined string: curr + \x00 + prev_tail
    """
    s = curr_text + "\x00" + prev_text[-len(curr_text):]
    pi = [0] * len(s)
    for i in range(1, len(s)):
        j = pi[i - 1]
        while j > 0 and s[i] != s[j]:
            j = pi[j - 1]
        if s[i] == s[j]:
            j += 1
        pi[i] = j
    return min(pi[-1], len(curr_text))


@dataclass
class FileAction:
    action: str   # 'append', 'full', 'delete'
    path: str     # relative posix path
    size: int     # payload size (bytes)


def compute_file_delta(prev_file: Optional[Path], curr_file: Path, work_dir: Path) -> Tuple[FileAction, Optional[Path]]:
    if prev_file is None:
        payload = work_dir / "full" / curr_file.name
        payload.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(curr_file, payload)
        return FileAction("full", curr_file.as_posix(), payload.stat().st_size), payload

    if not curr_file.exists():
        return FileAction("delete", prev_file.as_posix(), 0), None

    # Try as text
    try:
        prev_text = _read_text_file(prev_file)
        curr_text = _read_text_file(curr_file)
        k = longest_suffix_prefix_overlap(prev_text, curr_text)
        tail = curr_text[k:]
        if len(tail) == 0:
            return FileAction("append", curr_file.as_posix(), 0), None
        payload = work_dir / "append" / (curr_file.name + ".tail")
        payload.parent.mkdir(parents=True, exist_ok=True)
        _write_text_file(payload, tail)
        return FileAction("append", curr_file.as_posix(), len(tail.encode("utf-8"))), payload
    except Exception:
        payload = work_dir / "full" / curr_file.name
        payload.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(curr_file, payload)
        return FileAction("full", curr_file.as_posix(), payload.stat().st_size), payload


# -----------------------------
# Step processing & state
# -----------------------------

def discover_steps(steps_dir: Path) -> List[Path]:
    all_dirs = [p for p in steps_dir.iterdir() if p.is_dir()]
    baseline = [p for p in all_dirs if p.name == "baseline"]
    others = sorted([p for p in all_dirs if p.name != "baseline"])
    return baseline + others


def find_node_archives(step_dir: Path) -> Dict[str, Path]:
    mapping: Dict[str, Path] = {}
    for p in step_dir.iterdir():
        if not p.is_file():
            continue
        name = p.name
        if re.match(r".+\.logs\.(zip|tar\.gz)$", name) or re.match(r".+\.after\d{2}\.logs\.(zip|tar\.gz)$", name):
            node = name.split(".", 1)[0]
            mapping[node] = p
    return mapping


def build_diffs(run_root: str | Path, out_root: Optional[str | Path] = None, keep_unpacked: bool = False, verbose: bool = False) -> None:
    run_root = Path(run_root).resolve()
    steps_dir = run_root / "steps"
    if not steps_dir.is_dir():
        raise RuntimeError(f"No steps/ directory at: {run_root}")

    out_root = Path(out_root).resolve() if out_root else run_root
    out_root.mkdir(parents=True, exist_ok=True)

    state_root = out_root / ".state"
    state_root.mkdir(parents=True, exist_ok=True)

    steps = discover_steps(steps_dir)
    if not steps or steps[0].name != "baseline":
        raise RuntimeError("Baseline step missing or not first")

    for si, step in enumerate(steps):
        step_rel = step.relative_to(steps_dir).as_posix()
        if verbose:
            print(f"[logdiff] Processing step: {step_rel}")

        node_archives = find_node_archives(step)
        diff_dir = step / "diff"
        unpack_dir = step / "unpacked"
        patched_dir = step / "patched"
        diff_dir.mkdir(exist_ok=True)
        if keep_unpacked:
            unpack_dir.mkdir(exist_ok=True)
            patched_dir.mkdir(exist_ok=True)

        for node, archive_path in sorted(node_archives.items()):
            if verbose:
                print(f"[logdiff]  node={node} archive={archive_path.name}")
            node_state = state_root / node
            node_state_text = node_state / "text"
            if si == 0:
                if node_state.exists():
                    shutil.rmtree(node_state)
                node_state_text.mkdir(parents=True, exist_ok=True)

            # Unpack
            node_unpack_src = (unpack_dir / node) if keep_unpacked else Path(tempfile.mkdtemp(prefix=f"logdiff-unpack-{node}-"))
            if node_unpack_src.exists():
                shutil.rmtree(node_unpack_src)
            node_unpack_src.mkdir(parents=True, exist_ok=True)
            unpack_archive(archive_path, node_unpack_src)

            # Convert to text
            node_curr_text = Path(tempfile.mkdtemp(prefix=f"logdiff-text-{node}-"))
            convert_tree_binaries_to_text(node_unpack_src, node_curr_text)

            if not node_state_text.exists():
                node_state_text.mkdir(parents=True, exist_ok=True)

            payload_tmp = Path(tempfile.mkdtemp(prefix=f"logdiff-payload-{node}-"))
            actions: List[dict] = []

            # Collect prior and current relative file paths
            prior_paths = set()
            for root, _, files in os.walk(node_state_text):
                for fn in files:
                    prior_paths.add((Path(root) / fn).relative_to(node_state_text).as_posix())

            curr_paths = set()
            for root, _, files in os.walk(node_curr_text):
                for fn in files:
                    curr_paths.add((Path(root) / fn).relative_to(node_curr_text).as_posix())

            # Deletions
            for rel in sorted(prior_paths - curr_paths):
                actions.append({"action": "delete", "path": rel, "size": 0})
                if verbose:
                    print(f"[logdiff]    delete {rel}")
                (node_state_text / rel).unlink(missing_ok=True)
                parent = (node_state_text / rel).parent
                while parent != node_state_text and parent.exists() and not any(parent.iterdir()):
                    parent.rmdir()
                    parent = parent.parent

            # Appends/Full for existing/new files
            for rel in sorted(curr_paths):
                prev_file = (node_state_text / rel) if (node_state_text / rel).exists() else None
                curr_file = node_curr_text / rel
                rel_work = payload_tmp / Path(rel).parent
                rel_work.mkdir(parents=True, exist_ok=True)

                action, payload_path = compute_file_delta(prev_file, curr_file, rel_work)
                actions.append({"action": action.action, "path": rel, "size": action.size})
                if verbose:
                    print(f"[logdiff]    {action.action:6} {rel} ({action.size} bytes)")

                # Apply to state
                if action.action == "append":
                    if payload_path and payload_path.exists():
                        tail_text = _read_text_file(payload_path)
                        if prev_file is None:
                            _write_text_file(node_state_text / rel, tail_text)
                        else:
                            with (node_state_text / rel).open("a", encoding="utf-8") as f:
                                f.write(tail_text)
                elif action.action == "full":
                    dst = node_state_text / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(payload_path, dst) if payload_path else shutil.copy2(curr_file, dst)

            # Bundle & compress
            manifest = {"node": node, "step": step.name, "actions": actions}
            bundle_dir = Path(tempfile.mkdtemp(prefix=f"logdiff-bundle-{node}-"))
            (bundle_dir / "payloads").mkdir(parents=True, exist_ok=True)

            if payload_tmp.exists():
                for root, dirs, files in os.walk(payload_tmp):
                    root_p = Path(root)
                    rel_root = root_p.relative_to(payload_tmp)
                    for d in dirs:
                        (bundle_dir / "payloads" / rel_root / d).mkdir(parents=True, exist_ok=True)
                    for fn in files:
                        sp = root_p / fn
                        dp = bundle_dir / "payloads" / rel_root / fn
                        dp.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(sp), str(dp))

            (bundle_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            out_tgz = diff_dir / f"{node}.diff.tgz"
            with tarfile.open(out_tgz, "w:gz") as tf:
                tf.add(bundle_dir, arcname=".")

            if verbose:
                total_bytes = sum(a.get("size", 0) for a in actions)
                print(f"[logdiff]  node={node} wrote {out_tgz.name} with {len(actions)} actions, {total_bytes} bytes payload")

            # Per-step meta
            meta_path = step / "diff.meta.json"
            meta = {"step": step.name, "nodes": sorted(node_archives.keys())}
            meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

            if keep_unpacked:
                patched_dir.mkdir(exist_ok=True)
                patched_node_dir = patched_dir / node
                if patched_node_dir.exists():
                    shutil.rmtree(patched_node_dir)
                shutil.copytree(node_state_text, patched_node_dir)

            if not keep_unpacked and node_unpack_src.exists():
                shutil.rmtree(node_unpack_src)
            shutil.rmtree(node_curr_text, ignore_errors=True)
            shutil.rmtree(payload_tmp, ignore_errors=True)
            shutil.rmtree(bundle_dir, ignore_errors=True)


def apply_diffs(run_root: str | Path, out_root: str | Path, upto_step: Optional[str] = None, verbose: bool = False) -> None:
    run_root = Path(run_root).resolve()
    steps_dir = run_root / "steps"
    out_root = Path(out_root).resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    steps = discover_steps(steps_dir)
    if upto_step is not None:
        steps = [s for s in steps if s.name <= upto_step]

    for si, step in enumerate(steps):
        node_archives = find_node_archives(step)
        for node, archive in node_archives.items():
            node_out = out_root / step.name / node
            node_out.mkdir(parents=True, exist_ok=True)
            if si == 0:
                tmp = Path(tempfile.mkdtemp(prefix="apply-baseline-"))
                unpack_archive(archive, tmp)
                convert_tree_binaries_to_text(tmp, node_out)
                shutil.rmtree(tmp, ignore_errors=True)
            else:
                diff_tgz = step / "diff" / f"{node}.diff.tgz"
                if not diff_tgz.exists():
                    continue
                if verbose:
                    print(f"[logdiff]  apply node={node} step={step.name} from {diff_tgz.name}")
                with tarfile.open(diff_tgz, "r:gz") as tf:
                    with tempfile.TemporaryDirectory(prefix="apply-bundle-") as bdir:
                        tf.extractall(bdir)
                        bdirp = Path(bdir)
                        manifest = json.loads((bdirp / "manifest.json").read_text(encoding="utf-8"))
                        payloads = bdirp / "payloads"
                        prev_step_dir = out_root / steps[si-1].name / node
                        if not prev_step_dir.exists():
                            raise RuntimeError(f"Missing prior reconstruction for {node} at {steps[si-1].name}")
                        if node_out.exists():
                            shutil.rmtree(node_out)
                        shutil.copytree(prev_step_dir, node_out)

                        for act in manifest.get("actions", []):
                            apath = node_out / act["path"]
                            if act["action"] == "delete":
                                if verbose:
                                    print(f"[logdiff]    delete {act['path']}")
                                apath.unlink(missing_ok=True)
                                parent = apath.parent
                                while parent != node_out and parent.exists() and not any(parent.iterdir()):
                                    parent.rmdir()
                                    parent = parent.parent
                            elif act["action"] == "full":
                                # find payload
                                found = None
                                for root, _, files in os.walk(payloads):
                                    for fn in files:
                                        if fn == Path(act["path"]).name and not fn.endswith(".tail"):
                                            cand = Path(root) / fn
                                            found = cand
                                            break
                                    if found:
                                        break
                                if found is None:
                                    raise RuntimeError(f"Payload missing for 'full': {act['path']}")
                                if verbose:
                                    print(f"[logdiff]    full   {act['path']}")
                                apath.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(found, apath)
                            elif act["action"] == "append":
                                tail_file = None
                                for root, _, files in os.walk(payloads):
                                    for fn in files:
                                        if fn == Path(act["path"]).name + ".tail":
                                            tail_file = Path(root) / fn
                                            break
                                    if tail_file:
                                        break
                                if tail_file and tail_file.exists():
                                    tail_text = _read_text_file(tail_file)
                                    if verbose:
                                        print(f"[logdiff]    append {act['path']} (+{len(tail_text.encode('utf-8'))} bytes)")
                                    apath.parent.mkdir(parents=True, exist_ok=True)
                                    with apath.open("a", encoding="utf-8") as f:
                                        f.write(tail_text)


# -----------------------------
# CLI
# -----------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="logdiff", description="Append-aware log diff builder")
    sub = p.add_subparsers(dest="cmd")

    p_build = sub.add_parser("build", help="Build diffs (default)")
    p_build.add_argument("-i", "--in", dest="in_path", required=True, help="Run root containing steps/")
    p_build.add_argument("-o", "--out", dest="out_path", default=None, help="Output root (defaults to --in)")
    p_build.add_argument("-k", "--keep-unpacked", action="store_true", help="Keep unpacked and patched views")
    p_build.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    p_apply = sub.add_parser("apply", help="Apply diffs to reconstruct text snapshots")
    p_apply.add_argument("-i", "--in", dest="in_path", required=True, help="Run root containing steps/")
    p_apply.add_argument("-o", "--out", dest="out_path", required=True, help="Output root for reconstructed trees")
    p_apply.add_argument("-s", "--step", dest="upto_step", default=None, help="Apply diffs up to and including this step name")
    p_apply.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    ns = parse_args(argv)
    if ns.cmd in (None, "build"):
        try:
            build_diffs(run_root=ns.in_path, out_root=ns.out_path, keep_unpacked=ns.keep_unpacked, verbose=getattr(ns, "verbose", False))
            return 0
        except Exception as e:
            sys.stderr.write(f"[logdiff] ERROR: {e}\n")
            return 2
    elif ns.cmd == "apply":
        try:
            apply_diffs(run_root=ns.in_path, out_root=ns.out_path, upto_step=ns.upto_step, verbose=getattr(ns, "verbose", False))
            return 0
        except Exception as e:
            sys.stderr.write(f"[logdiff] ERROR: {e}\n")
            return 2
    else:
        sys.stderr.write("Unknown command\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
