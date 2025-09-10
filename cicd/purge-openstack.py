#!/usr/bin/env python3
"""
purge_all_servers_and_zones.py

Purges ALL Nova servers and ALL Designate zones in the current OpenStack project,
then waits until zero remain. No prompts, no flags.

- Servers: tries normal delete, then force-delete on stubborn ones.
- Zones: deletes all zones and waits for them to disappear.
"""

from __future__ import annotations

import sys
import time
from typing import Iterable, Set, Tuple

try:
	# type: ignore
	import openstack
except Exception as e:
	print(f"[ERROR] openstacksdk not available: {e}", file=sys.stderr)
	sys.exit(2)


POLL_START_SEC = 2
POLL_MAX_SEC = 15


def log(msg: str) -> None:
	"""Print a simple progress line."""
	print(msg, flush=True)


def connect() -> openstack.connection.Connection:
	"""
	Function: connect
	Parameters: none
	Returns: OpenStack connection using OS_* or clouds.yaml
	"""
	return openstack.connect()  # type: ignore


def list_servers(conn: openstack.connection.Connection) -> Iterable[Tuple[str, str, str]]:
	"""
	Function: list_servers
	Parameters:
		conn: OpenStack connection
	Returns:
		Iterator of (id, name, status)
	"""
	for s in conn.compute.servers(details=True):  # type: ignore[attr-defined]
		yield (getattr(s, "id", ""), getattr(s, "name", ""), (getattr(s, "status", "") or "").upper())


def purge_servers(conn: openstack.connection.Connection) -> None:
	"""
	Function: purge_servers
	Parameters:
		conn: OpenStack connection
	Returns:
		None; blocks until no servers remain
	"""
	log("[INFO] Purging ALL servers in project…")
	attempted: Set[str] = set()
	poll = POLL_START_SEC
	cycle = 0

	while True:
		srvs = list(list_servers(conn))
		if not srvs:
			log("[INFO] No servers remain.")
			return

		log(f"[INFO] Servers remaining: {len(srvs)}")
		# First pass: issue delete for any not yet attempted
		for sid, name, status in srvs:
			if sid in attempted:
				continue
			try:
				log(f"[INFO] delete_server: {name} ({sid}) status={status}")
				conn.compute.delete_server(sid, ignore_missing=True)  # type: ignore[attr-defined]
				attempted.add(sid)
			except Exception as exc:
				log(f"[WARN] delete_server failed {sid} ({name}): {exc}")

		# Every few cycles, try force delete on stubborn instances
		cycle += 1
		if cycle % 3 == 0:
			for sid, name, status in srvs:
				try:
					log(f"[INFO] force_delete_server: {name} ({sid}) status={status}")
					# openstacksdk supports force=True; if not, this is a no-op.
					conn.compute.delete_server(sid, ignore_missing=True, force=True)  # type: ignore[attr-defined]
				except Exception as exc:
					log(f"[WARN] force_delete failed {sid} ({name}): {exc}")

		time.sleep(poll)
		poll = min(POLL_MAX_SEC, poll + 1)


def dns_available(conn: openstack.connection.Connection) -> bool:
	"""
	Function: dns_available
	Parameters:
		conn: OpenStack connection
	Returns:
		True if Designate proxy works, else False
	"""
	try:
		_ = next(iter(conn.dns.zones(limit=1)), None)  # type: ignore[attr-defined]
		return True
	except Exception:
		return False


def list_zones(conn: openstack.connection.Connection):
	"""
	Function: list_zones
	Parameters:
		conn: OpenStack connection
Returns:
		Iterator of zone objects with .id, .name, .status
	"""
	# type: ignore[attr-defined]
	return conn.dns.zones()


def purge_zones(conn: openstack.connection.Connection) -> None:
	"""
	Function: purge_zones
	Parameters:
		conn: OpenStack connection
	Returns:
		None; blocks until no zones remain (or skips if Designate unavailable)
	"""
	if not dns_available(conn):
		log("[INFO] Designate (DNS) not available in this cloud/project; skipping zones.")
		return

	log("[INFO] Purging ALL DNS zones in project…")
	poll = POLL_START_SEC

	# Issue delete for all existing zones once, then poll until none remain.
	issued: Set[str] = set()
	while True:
		zones = list(list_zones(conn))
		if not zones:
			log("[INFO] No zones remain.")
			return

		log(f"[INFO] Zones remaining: {len(zones)}")
		for z in zones:
			zid = getattr(z, "id", "")
			zname = getattr(z, "name", "")
			zstatus = (getattr(z, "status", "") or "").upper()
			if zid in issued:
				continue
			try:
				log(f"[INFO] delete_zone: {zname} ({zid}) status={zstatus}")
				# type: ignore[attr-defined]
				conn.dns.delete_zone(zid, ignore_missing=True)
				issued.add(zid)
			except Exception as exc:
				log(f"[WARN] delete_zone failed {zid} ({zname}): {exc}")

		time.sleep(poll)
		poll = min(POLL_MAX_SEC, poll + 1)


def main() -> None:
	"""
	Function: main
	Parameters: none
	Returns: None
	"""
	conn = connect()
	purge_servers(conn)
	purge_zones(conn)
	log("[INFO] Purge complete: no servers or zones remain.")


if __name__ == "__main__":
	main()

