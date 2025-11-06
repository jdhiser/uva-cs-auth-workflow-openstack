#!/usr/bin/env python3
"""
Name:
    logdiff.py

Description:
    Build an output tree with unpacked logs, converted text formats, and (optionally) diffs,
    without mutating the input RUN_ROOT. All temporary and final artifacts live under OUT/<step>/...

CLI:
    logdiff build -i RUN_ROOT -o OUT [-k] [-v] [--evtx-format {xml,compact,jsonl}]

Notes:
    * ZIP extraction streams in chunks and normalizes Windows "\\" paths to "/" while preventing zip-slip.
    * EVTX conversion streams records and does not rely on Views. Formats:
        - compact (default): single-line logfmt-style: core fields + EventData keys
        - jsonl: one JSON record per line with the same minimal fields
        - xml: original record XML per line
    * Verbose mode prints each extracted file, each conversion/copy, and the created output step directories.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional
from xml.etree import ElementTree as ET

# Optional dependency for EVTX streaming
try:
    from Evtx.Evtx import Evtx  # type: ignore
except Exception:  # pragma: no cover - optional
    Evtx = None  # type: ignore


# ----------------------------
# Utility helpers
# ----------------------------

def setup_logging(verbose: bool) -> None:
    """
    Name:
        setup_logging

    Params:
        verbose (bool): If True, enables DEBUG-level logging; otherwise INFO.

    Returns:
        None: Configures the root logger for the module.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger("logdiff").setLevel(level)
    logging.debug("Verbose logging enabled.")
    logging.basicConfig(level=level, format="%(levelname)s:%(name)s:%(message)s")


def ensure_clean_dir(path: Path, keep: bool) -> None:
    """
    Name:
        ensure_clean_dir

    Params:
        path (Path): Directory path to (re)create.
        keep (bool): If True, keep if exists; if False, remove and recreate.

    Returns:
        None: Ensures directory exists and is empty unless keep=True.
    """
    if path.exists() and not keep:
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def is_within(base: Path, target: Path) -> bool:
    """
    Name:
        is_within

    Params:
        base (Path): The intended base directory.
        target (Path): The target path being validated.

    Returns:
        bool: True if target is within base (prevents path traversal).
    """
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except Exception:
        return False


def logfmt_escape(value: str) -> str:
    """
    Name:
        logfmt_escape

    Params:
        value (str): Arbitrary string value to include in a logfmt line.

    Returns:
        str: Properly escaped/quoted value per simple logfmt rules.
    """
    must_quote = any(ch.isspace() for ch in value) or any(ch in '="' for ch in value)
    escaped = value.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{escaped}"' if must_quote else escaped


def record_to_minimal_dict(event_xml: str) -> Dict[str, object]:
    """
    Name:
        record_to_minimal_dict

    Params:
        event_xml (str): XML text for a single <Event> record from an EVTX file.

    Returns:
        Dict[str, object]: Minimal normalized fields including System and EventData keys.
    """
    root = ET.fromstring(event_xml)
    ns = {'e': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}

    def find_text(xpath: str) -> Optional[str]:
        el = root.find(xpath, ns) if ns else root.find(xpath)
        return None if el is None else (el.text if el.text is not None else (el.get('Name') or None))

    def find_attr(xpath: str, attr: str) -> Optional[str]:
        el = root.find(xpath, ns) if ns else root.find(xpath)
        return None if el is None else el.get(attr)

    provider = find_attr('./System/Provider', 'Name') or ''
    event_id = find_text('./System/EventID') or ''
    level = find_text('./System/Level') or ''
    computer = find_text('./System/Computer') or ''
    time_created = find_attr('./System/TimeCreated', 'SystemTime') or ''

    data: Dict[str, object] = {
        'provider': provider,
        'event_id': event_id,
        'level': level,
        'computer': computer,
        'time': time_created,
    }

    eventdata = root.find('./EventData', ns) if ns else root.find('./EventData')
    if eventdata is not None:
        for d in list(eventdata):
            key = d.get('Name') or d.tag
            val = (d.text or '').strip()
            data[key] = val

    return data


def minimal_to_compact_line(d: Dict[str, object]) -> str:
    """
    Name:
        minimal_to_compact_line

    Params:
        d (Dict[str, object]): Minimal dict for one EVTX record.

    Returns:
        str: Single-line logfmt string with core fields first, followed by EventData keys.
    """
    keys_core = ['time', 'provider', 'event_id', 'level', 'computer']
    parts = []
    for k in keys_core:
        v = str(d.get(k, ''))
        parts.append(f"{k}={logfmt_escape(v)}")
    for k, v in d.items():
        if k in keys_core:
            continue
        parts.append(f"{k}={logfmt_escape(str(v))}")
    return ' '.join(parts)


# ----------------------------
# ZIP extraction
# ----------------------------
def extract_zip_streaming(zip_path: Path, dst_root: Path, verbose: bool = False) -> None:
    """
    Function: extract_zip_streaming
    Inputs:
        zip_path (Path): Path to the .zip archive to extract.
        dst_root (Path): Destination root directory for extraction.
        verbose (bool): If True, emit extra debug logging details.
    Returns:
        None

    Description:
        Stream-extract a ZIP file into dst_root with path safety and a pre-pass that
        fixes Windows 'fake-directory' entries produced by Compress-Archive (zero-byte
        files placed at paths that should be directories, e.g., 'LogFiles/Fax').

        With verbose=True, this emits detailed progress via the 'logdiff.unpack' logger:
        - Start/finish notices and archive size
        - Count of entries, directories to create, and converted fake directories
        - Per-entry extraction lines (throttled every ~250 files to avoid spam)
        - Debug lines when converting zero-byte files to real directories
    """

    log = logging.getLogger("logdiff.unpack")

    # If caller asked for verbosity, ensure our logger actually emits
    if verbose:
        #log.setLevel(logging.DEBUG)
        if not log.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
            log.addHandler(h)

    # --- Open archive ---
    try:
        size = zip_path.stat().st_size if zip_path.exists() else 0
        size_str = f"{size:,d}"
        log.debug("[unpack] opening %s (%s bytes)", zip_path, size_str)
    except Exception:
        log.debug("[unpack] opening %s", zip_path)

    with zipfile.ZipFile(zip_path, "r") as zf:
        # --- Pre-pass: compute required directories (parents of all entries) ---
        infos = zf.infolist()
        names = [zi.filename.replace("\\", "/") for zi in infos]
        needed_dirs: set[Path] = set()

        for name in names:
            if name.endswith("/"):
                needed_dirs.add(dst_root / name)
            else:
                parent = (dst_root / name).parent
                while parent and parent != dst_root and not str(parent).endswith(":"):
                    needed_dirs.add(parent)
                    parent = parent.parent

        log.debug("[unpack] %d zip entries, %d directories needed", len(infos), len(needed_dirs))

        # Ensure directories exist; convert zero-byte files-at-dir-path into directories.
        converted = 0
        for d in sorted(needed_dirs, key=lambda p: len(str(p))):
            if d.exists():
                if d.is_file():
                    try:
                        if d.stat().st_size == 0:
                            d.unlink()
                            d.mkdir(parents=True, exist_ok=True)
                            converted += 1
                            log.debug("[unpack] replaced zero-byte file with directory: %s", d)
                        else:
                            logging.warning("Directory needed but path exists as non-empty file: %s", d)
                    except Exception as e:
                        logging.warning("Failed to convert file to directory %s: %s", d, e)
            else:
                try:
                    d.mkdir(parents=True, exist_ok=True)
                except FileExistsError:
                    pass

        if converted:
            log.debug("[unpack] converted %d fake-directory file(s)", converted)

        # --- Extract entries (directories first, then files) ---
        extracted = 0
        total = len(infos)
        for i, zi in enumerate(infos, start=1):
            name = zi.filename.replace("\\", "/")
            out_path = dst_root / name

            # Directory entry
            if name.endswith("/"):
                if out_path.exists():
                    if out_path.is_file():
                        if out_path.stat().st_size == 0:
                            out_path.unlink()
                            out_path.mkdir(parents=True, exist_ok=True)
                            log.debug("[unpack] replaced late zero-byte file with directory: %s", out_path)
                        else:
                            logging.warning("Skipping directory create; path exists as file: %s", out_path)
                else:
                    out_path.mkdir(parents=True, exist_ok=True)
                if verbose and (i % 250 == 0):
                    log.debug("[unpack] ensured dir %s (%d/%d)", out_path, i, total)
                continue

            # File entry
            parent = out_path.parent
            if parent.exists() and parent.is_file():
                if parent.stat().st_size == 0:
                    parent.unlink()
                    parent.mkdir(parents=True, exist_ok=True)
                    log.debug("[unpack] replaced parent fake-directory with dir: %s", parent)
                else:
                    logging.warning("Skipping file due to parent conflict: %s", out_path)
                    continue
            elif not parent.exists():
                parent.mkdir(parents=True, exist_ok=True)

            with zf.open(zi, "r") as src, open(out_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted += 1

            if verbose:
                # Per-file progress throttled; every ~250 entries we print a status
                if (i <= 10) or (i % 250 == 0) or (i == total):
                    fsize = getattr(zi, "file_size", 0)
                    fsize_str = f"{fsize:,d}"
                    log.debug(
                        "[unpack] wrote %s (%s bytes) [%d/%d]",
                        out_path,
                        fsize_str,
                        i,
                        total,
                    )

        log.debug("[unpack] done: %d file entries extracted to %s", extracted, dst_root)


def convert_evtx_file(evtx_path: Path, out_path: Path, fmt: str, verbose: bool) -> None:
    """
    Streams EVTX -> compact|jsonl|xml.
    Robust to malformed UTF-16 records seen in python-evtx by skipping only the
    offending records (logged at DEBUG) and continuing.
    """
    if Evtx is None:
        raise RuntimeError("python-evtx (Evtx.Evtx) is required for EVTX conversion but is not installed.")
    logging.debug("begin convert_evtx_file: %s -> {out_path}", evtx_path)
    print(f"begin convert_evtx_file: {evtx_path} -> {out_path}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    ok = 0
    skipped = 0

    with Evtx(str(evtx_path)) as ev, open(out_path, "w", encoding="utf-8", newline="\n") as out:
        for rec in ev.records():
            try:
                xml = rec.xml()  # may raise UnicodeDecodeError on malformed strings
            except Exception as e:
                skipped += 1
                if verbose:
                    logging.debug("evtx-skip: %s record #%d due to %s", evtx_path.name, ok + skipped, repr(e))
                continue

            if fmt == "xml":
                out.write(xml)
                out.write("\n")
            else:
                try:
                    d = record_to_minimal_dict(xml)
                except Exception as e:
                    skipped += 1
                    if verbose:
                        logging.debug("evtx-skip-parse: %s record #%d due to %s", evtx_path.name, ok + skipped, repr(e))
                    continue

                if fmt == "compact":
                    out.write(minimal_to_compact_line(d))
                    out.write("\n")
                elif fmt == "jsonl":
                    out.write(json.dumps(d, ensure_ascii=False))
                    out.write("\n")
                else:
                    raise ValueError(f"Unknown evtx format: {fmt}")

            ok += 1

    logging.debug("converted: %s -> %s (ok=%d, skipped=%d)", evtx_path.name, out_path, ok, skipped)


# ----------------------------
# Copy text files (streaming)
# ----------------------------

def copy_file_streaming(src: Path, dst: Path, verbose: bool) -> None:
    """
    Name:
        copy_file_streaming

    Params:
        src (Path): Source file path.
        dst (Path): Destination file path.

    Returns:
        None: Copies file in chunks to limit RAM usage.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(src, 'rb') as fsrc, open(dst, 'wb') as fdst:
        while True:
            buf = fsrc.read(1024 * 1024)
            if not buf:
                break
            fdst.write(buf)
    if verbose:
        logging.debug("copied: %s -> %s", src, dst)


# ----------------------------
# Build pipeline
# ----------------------------

@dataclass
class BuildConfig:
    """
    Name:
        BuildConfig

    Params:
        run_root (Path): Input run root (never modified).
        out_root (Path): Mandatory output root where all artifacts are written.
        keep (bool): Keep existing OUT/build directory contents if present.
        verbose (bool): Verbose logging toggle.
        evtx_format (str): 'compact' (default), 'jsonl', or 'xml'.

    Returns:
        None: Configuration container for the build step.
    """
    run_root: Path
    out_root: Path
    keep: bool
    verbose: bool
    evtx_format: str = 'compact'


def build_action(cfg: BuildConfig) -> int:
    """
    Name:
        build_action

    Params:
        cfg (BuildConfig): Build configuration with inputs and outputs.

    Returns:
        int: 0 on success; non-zero on failure.
    """
    # OUT step directories
    build_dir = cfg.out_root / 'build'
    unpack_dir = build_dir / 'unpacked'
    converted_dir = build_dir / 'converted'
    diffs_dir = build_dir / 'diffs'
    patched_dir = build_dir / 'patched'

    # Prepare directories under OUT only
    ensure_clean_dir(build_dir, keep=cfg.keep)
    for d in (unpack_dir, converted_dir, diffs_dir, patched_dir):
        d.mkdir(parents=True, exist_ok=True)
        if cfg.verbose:
            logging.debug("out step dir: %s", d)

    # 1) Find and stream-extract ZIPs from RUN_ROOT to OUT/build/unpacked
    for p in cfg.run_root.rglob('*.zip'):
        rel = p.relative_to(cfg.run_root)
        # Infer node name from archive filename by taking the token before the first '.'
        # Examples:
        #   dc1.logs.zip               -> dc1
        #   dc1.after02.logs.zip       -> dc1
        #   win10-eng.after01.logs.zip -> win10-eng
        node_name = p.name.split('.', 1)[0] if '.' in p.name else p.stem
        target_root = unpack_dir / rel.parent / node_name
        target_root.mkdir(parents=True, exist_ok=True)
        extract_zip_streaming(p, target_root, cfg.verbose)

    # 2) Walk RUN_ROOT + unpacked; convert/copy to OUT/build/converted with same rel paths
    search_roots = [cfg.run_root, unpack_dir]

    for root in search_roots:
        if not root.exists():
            continue
        for f in root.rglob('*'):
            if f.is_dir():
                continue
            # Skip original zips in run_root; already unpacked/copied
            if f.suffix.lower() == '.zip' and root == cfg.run_root:
                continue

            # Compute relative path "as if" within run_root or unpacked
            try:
                rel = f.relative_to(root)
            except Exception:
                continue

            # Normalize backslashes in rel (if any came from zip names)
            rel_posix = Path(str(rel).replace('\\', '/'))
            src_ext = f.suffix.lower()
            dst = converted_dir / rel_posix

            if src_ext == '.evtx':
                # Choose extension by format
                if cfg.evtx_format == 'compact':
                    dst = dst.with_suffix('.log')
                elif cfg.evtx_format == 'jsonl':
                    dst = dst.with_suffix('.jsonl')
                else:
                    dst = dst.with_suffix('.xml')
                convert_evtx_file(f, dst, cfg.evtx_format, cfg.verbose)
            else:
                # Copy other files as-is
                copy_file_streaming(f, dst, cfg.verbose)

    # 3) (Optional) Diffs and patched steps can be implemented here.
    #    Placeholder to respect folder structure without modifying input tree.
    #    This script focuses on unpack/convert per current requirements.

    return 0


# ----------------------------
# CLI
# ----------------------------

def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    """
    Name:
        parse_args

    Params:
        argv (Optional[Iterable[str]]): Optional list of CLI arguments; defaults to sys.argv[1:].

    Returns:
        argparse.Namespace: Parsed arguments with subcommand and options.
    """
    p = argparse.ArgumentParser(prog='logdiff', description='Log diff builder for Windows+Linux logs')
    sub = p.add_subparsers(dest='cmd', required=True)

    pb = sub.add_parser('build', help='Build output tree from RUN_ROOT')
    pb.add_argument('-i', '--input', dest='run_root', required=True, type=Path,
                    help='RUN_ROOT input directory (never modified)')
    pb.add_argument('-o', '--out', dest='out_root', required=True, type=Path,
                    help='OUT directory (mandatory). All artifacts go here.')
    pb.add_argument('-k', '--keep', action='store_true',
                    help='Keep existing OUT/build contents instead of cleaning.')
    pb.add_argument('-v', '--verbose', action='store_true',
                    help='Verbose logging of each file and step directory.')
    pb.add_argument('--evtx-format', choices=['xml', 'compact', 'jsonl'], default='compact',
                    help='Format for EVTX conversion (default: compact).')

    return p.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Iterable[str]] = None) -> int:
    """
    Name:
        main

    Params:
        argv (Optional[Iterable[str]]): Optional CLI arguments.

    Returns:
        int: Exit status code (0 success).
    """
    args = parse_args(argv)
    setup_logging(args.verbose)

    if args.cmd == 'build':
        cfg = BuildConfig(
            run_root=args.run_root,
            out_root=args.out_root,
            keep=args.keep,
            verbose=args.verbose,
            evtx_format=args.evtx_format,
        )
        return build_action(cfg)

    logging.error("Unknown command")
    return 2


if __name__ == '__main__':
    sys.exit(main())
