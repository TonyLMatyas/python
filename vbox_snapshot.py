#!/usr/bin/env python3
"""
VirtualBox Snapshot Automation Script

Automates snapshot management for a specified VirtualBox VM:
  1. Validates that the VM exists and is not currently running.
  2. Retains only the latest 2 snapshots (by creation date) and deletes older ones.
  3. Creates a new snapshot with a timestamped name (e.g., Backup_2026-03-18_14-30-00).

All actions are logged to ~/vbox_backup.log for a full audit trail.
Compatible with Windows, macOS, and Debian-based Linux.

Usage:
    python3 vbox_snapshot.py -v "My VM Name"
    python3 vbox_snapshot.py -l
"""

import argparse
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Number of existing snapshots to retain before creating a new one.
# After the script runs you will have up to MAX_SNAPSHOTS_TO_KEEP + 1
# snapshots (the retained ones plus the newly created one).
MAX_SNAPSHOTS_TO_KEEP = 2

# Log file location — placed in the user's home directory for easy access.
LOG_FILE = Path.home() / "vbox_backup.log"

# Prefix used when naming new snapshots.
SNAPSHOT_PREFIX = "Backup"

# Maximum time (seconds) to wait for a single VBoxManage command.
# Snapshot deletion and creation can be slow for large disk images.
COMMAND_TIMEOUT = 600


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging():
    """
    Configures dual logging: console output for real-time feedback and a
    persistent log file (~/vbox_backup.log) for auditing every action the
    script takes — especially snapshot deletions.
    """
    logger = logging.getLogger("vbox_snapshot")
    logger.setLevel(logging.DEBUG)

    # Timestamp + level + message so every entry is self-describing.
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler — shows INFO and above so the user sees progress.
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # File handler — captures DEBUG and above for full troubleshooting detail.
    file_handler = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


# ---------------------------------------------------------------------------
# Locate VBoxManage
# ---------------------------------------------------------------------------

def find_vboxmanage():
    """
    Locates the VBoxManage executable across Windows, macOS, and Linux.

    Search order:
      1. System PATH (covers most standard installations).
      2. Platform-specific default installation directories as a fallback.

    Returns the absolute path to VBoxManage.
    Exits with a clear error message if it cannot be found.
    """
    # Check PATH first — works when the VirtualBox installer registered it.
    vboxmanage = shutil.which("VBoxManage")
    if vboxmanage:
        return vboxmanage

    # Fall back to well-known installation directories per OS.
    system = platform.system()
    candidate_paths = []

    if system == "Windows":
        candidate_paths = [
            r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
            r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe",
        ]
    elif system == "Darwin":  # macOS
        candidate_paths = [
            "/usr/local/bin/VBoxManage",
            "/Applications/VirtualBox.app/Contents/MacOS/VBoxManage",
        ]
    elif system == "Linux":
        candidate_paths = [
            "/usr/bin/VBoxManage",
            "/usr/local/bin/VBoxManage",
        ]

    for path in candidate_paths:
        if os.path.isfile(path):
            return path

    print(
        "ERROR: VBoxManage was not found on your system.\n"
        "Please install VirtualBox or add VBoxManage to your PATH.",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Run VBoxManage commands safely
# ---------------------------------------------------------------------------

def run_vboxmanage(vboxmanage_path, args, logger):
    """
    Executes a VBoxManage command and returns the CompletedProcess result.

    Important safety note: this function only *runs* what it is given.  The
    callers are responsible for ensuring only snapshot-level commands (list,
    delete, take) are executed — never VM-level destructive commands.

    Parameters:
        vboxmanage_path: Absolute path to the VBoxManage executable.
        args:            List of CLI arguments (e.g. ["snapshot", "MyVM", "list"]).
        logger:          Logger for recording the executed command and output.

    Returns:
        subprocess.CompletedProcess with stdout and stderr captured as strings.
    """
    cmd = [vboxmanage_path] + args
    logger.debug("Running command: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
        )
    except FileNotFoundError:
        logger.error("VBoxManage executable not found at: %s", vboxmanage_path)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logger.error(
            "Command timed out after %d seconds: %s",
            COMMAND_TIMEOUT,
            " ".join(cmd),
        )
        sys.exit(1)

    logger.debug("stdout: %s", result.stdout.strip())
    if result.stderr.strip():
        logger.debug("stderr: %s", result.stderr.strip())

    return result


# ---------------------------------------------------------------------------
# List registered VMs
# ---------------------------------------------------------------------------

def get_vm_snapshots_for_display(vboxmanage, vm_name, logger):
    """
    Retrieves snapshots for a single VM, intended for the -l/--list display.

    Unlike get_snapshots(), this function does not exit on errors — it returns
    None on failure so the caller can continue listing other VMs.

    Returns a list of snapshot dicts on success, or None on error.
    """
    result = run_vboxmanage(
        vboxmanage, ["snapshot", vm_name, "list"], logger
    )

    if result.returncode != 0:
        combined_output = result.stdout + result.stderr
        if "does not have any snapshots" in combined_output:
            return []
        return None

    name_pattern = re.compile(
        r"Name:\s+(.+?)\s+\(UUID:\s+([a-f0-9-]+)\)"
    )
    time_pattern = re.compile(r"Time taken:\s+(.+)")

    snapshots = []
    lines = result.stdout.splitlines()

    i = 0
    while i < len(lines):
        name_match = name_pattern.search(lines[i])
        if name_match:
            snap_name = name_match.group(1)
            snap_uuid = name_match.group(2)
            snap_time = None

            for j in range(i + 1, min(i + 5, len(lines))):
                time_match = time_pattern.search(lines[j])
                if time_match:
                    snap_time = parse_timestamp(time_match.group(1))
                    break

            snapshots.append({
                "name": snap_name,
                "uuid": snap_uuid,
                "timestamp": snap_time,
            })
        i += 1

    # Sort by timestamp when available.
    if snapshots and all(s["timestamp"] is not None for s in snapshots):
        snapshots.sort(key=lambda s: s["timestamp"])

    return snapshots


def list_vms(vboxmanage, logger):
    """
    Lists all VMs registered in VirtualBox along with their current snapshots.

    Parses the output of 'VBoxManage list vms', which produces lines like:
        "My VM Name" {12345678-abcd-1234-abcd-123456789abc}

    For each VM, also queries and displays its existing snapshots with
    creation timestamps, giving a full overview of the VirtualBox environment.
    """
    logger.info("Retrieving list of registered VMs...")

    result = run_vboxmanage(vboxmanage, ["list", "vms"], logger)

    if result.returncode != 0:
        logger.error(
            "Failed to list VMs: %s", result.stderr.strip()
        )
        sys.exit(1)

    output = result.stdout.strip()

    if not output:
        print("No VMs are currently registered in VirtualBox.")
        return

    # Each line is: "VM Name" {uuid}
    vm_pattern = re.compile(r'^"(.+?)"\s+\{[a-f0-9-]+\}', re.MULTILINE)
    vm_names = vm_pattern.findall(output)

    if not vm_names:
        print("No VMs are currently registered in VirtualBox.")
        return

    print(f"Registered VirtualBox VMs ({len(vm_names)}):")
    print("=" * 50)

    for name in vm_names:
        print(f"\n  {name}")

        # Retrieve snapshots for this VM.
        snapshots = get_vm_snapshots_for_display(vboxmanage, name, logger)

        if snapshots is None:
            print("    Snapshots: (unable to retrieve)")
        elif not snapshots:
            print("    Snapshots: (none)")
        else:
            print(f"    Snapshots ({len(snapshots)}):")
            for snap in snapshots:
                if snap["timestamp"]:
                    time_str = snap["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                    print(f"      - {snap['name']}  ({time_str})")
                else:
                    print(f"      - {snap['name']}")

    print("\n" + "=" * 50)
    print("Use: python3 vbox_snapshot.py -v \"<VM Name>\"")


# ---------------------------------------------------------------------------
# VM validation
# ---------------------------------------------------------------------------

def check_vm_exists(vboxmanage, vm_name, logger):
    """
    Confirms the specified VM is registered in VirtualBox.

    Uses 'showvminfo --machinereadable' which returns exit code 0 on success.
    Exits with an error if the VM does not exist or cannot be accessed.

    Returns the raw machine-readable VM info string (reused by the state check).
    """
    logger.info("Checking if VM '%s' exists...", vm_name)

    result = run_vboxmanage(
        vboxmanage, ["showvminfo", vm_name, "--machinereadable"], logger
    )

    if result.returncode != 0:
        logger.error(
            "VM '%s' does not exist or cannot be accessed.", vm_name
        )
        logger.error("VBoxManage output: %s", result.stderr.strip())
        sys.exit(1)

    logger.info("VM '%s' found.", vm_name)
    return result.stdout


def check_vm_not_running(vboxmanage, vm_name, vm_info, logger):
    """
    Ensures the VM is powered off before snapshot operations proceed.

    The user has requested the script exit with an error if the VM is active.
    This prevents potential issues with manipulating snapshots on a live VM.
    """
    logger.info("Checking power state of VM '%s'...", vm_name)

    # Machine-readable output contains a line like: VMState="poweroff"
    state_match = re.search(r'^VMState="(.+?)"', vm_info, re.MULTILINE)

    if not state_match:
        logger.error("Could not determine the state of VM '%s'.", vm_name)
        sys.exit(1)

    vm_state = state_match.group(1)
    logger.info("VM '%s' state: %s", vm_name, vm_state)

    # Any state other than these safe, non-active states should block execution.
    safe_states = {"poweroff", "saved", "aborted"}

    if vm_state.lower() not in safe_states:
        logger.error(
            "VM '%s' is currently in state '%s'. "
            "Please power off the VM before running this script.",
            vm_name,
            vm_state,
        )
        sys.exit(1)

    logger.info("VM '%s' is not running — safe to proceed.", vm_name)


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def parse_timestamp(time_string):
    """
    Parses a timestamp string from VBoxManage's human-readable output.

    VirtualBox formats timestamps differently depending on the host locale
    and VBox version, so we try several common formats.

    Returns a datetime object on success, or None if no format matched.
    """
    time_string = time_string.strip()

    # Ordered from most common to least common across platforms.
    formats = [
        "%m/%d/%Y %H:%M:%S",       # US: 03/18/2026 14:30:00
        "%m/%d/%Y, %H:%M:%S",      # US with comma
        "%d/%m/%Y %H:%M:%S",       # European: 18/03/2026 14:30:00
        "%d/%m/%Y, %H:%M:%S",      # European with comma
        "%Y-%m-%dT%H:%M:%SZ",      # ISO 8601 with Z
        "%Y-%m-%dT%H:%M:%S",       # ISO 8601 without Z
        "%Y-%m-%d %H:%M:%S",       # ISO-like with space separator
        "%b %d, %Y %H:%M:%S %p",   # Long US: Mar 18, 2026 02:30:00 PM
        "%b %d, %Y %H:%M:%S",      # Long US without AM/PM
        "%d %b %Y %H:%M:%S",       # Long European: 18 Mar 2026 14:30:00
        "%d. %b %Y %H:%M:%S",      # German-style: 18. Mär 2026 14:30:00
    ]

    for fmt in formats:
        try:
            return datetime.strptime(time_string, fmt)
        except ValueError:
            continue

    # Handle ISO 8601 with fractional seconds (e.g. 2026-03-18T14:30:00.123456789Z).
    # Python's %f only supports up to 6 digits, so we strip the fractional part.
    iso_frac = re.match(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+Z?", time_string
    )
    if iso_frac:
        try:
            return datetime.strptime(iso_frac.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass

    return None


# ---------------------------------------------------------------------------
# Snapshot listing
# ---------------------------------------------------------------------------

def get_snapshots(vboxmanage, vm_name, logger):
    """
    Retrieves all snapshots for the specified VM with their creation dates.

    Uses the human-readable output of 'VBoxManage snapshot <vm> list' because
    only this format includes the "Time taken" timestamp field (the
    --machinereadable format omits it).

    Returns a list of dicts sorted by creation date (oldest first):
        [{"name": str, "uuid": str, "timestamp": datetime | None}, ...]
    """
    logger.info("Retrieving snapshots for VM '%s'...", vm_name)

    result = run_vboxmanage(vboxmanage, ["snapshot", vm_name, "list"], logger)

    # Exit code 1 with "does not have any snapshots" is normal for a VM with none.
    if result.returncode != 0:
        combined_output = result.stdout + result.stderr
        if "does not have any snapshots" in combined_output:
            logger.info("VM '%s' has no existing snapshots.", vm_name)
            return []
        logger.error(
            "Failed to list snapshots for VM '%s': %s",
            vm_name,
            result.stderr.strip(),
        )
        sys.exit(1)

    # Regex patterns for snapshot entries in the human-readable output.
    # Example line: "   Name: Daily_Backup (UUID: 12345678-abcd-...) *"
    name_pattern = re.compile(
        r"Name:\s+(.+?)\s+\(UUID:\s+([a-f0-9-]+)\)"
    )
    # Example line: "      Time taken: 03/18/2026 14:30:00"
    time_pattern = re.compile(r"Time taken:\s+(.+)")

    snapshots = []
    lines = result.stdout.splitlines()

    i = 0
    while i < len(lines):
        name_match = name_pattern.search(lines[i])
        if name_match:
            snap_name = name_match.group(1)
            snap_uuid = name_match.group(2)
            snap_time = None

            # The "Time taken:" line follows within the next few lines.
            for j in range(i + 1, min(i + 5, len(lines))):
                time_match = time_pattern.search(lines[j])
                if time_match:
                    snap_time = parse_timestamp(time_match.group(1))
                    if snap_time is None:
                        logger.warning(
                            "Could not parse timestamp '%s' for snapshot '%s'. "
                            "Will fall back to listing order.",
                            time_match.group(1),
                            snap_name,
                        )
                    break

            snapshots.append({
                "name": snap_name,
                "uuid": snap_uuid,
                "timestamp": snap_time,
            })
            logger.debug(
                "Found snapshot: name='%s', uuid='%s', timestamp='%s'",
                snap_name,
                snap_uuid,
                snap_time,
            )
        i += 1

    # Sort by creation timestamp (oldest first) when all timestamps are available.
    # For a linear chain the listing order is already chronological, so the
    # fallback is safe for the user's typical setup.
    if snapshots and all(s["timestamp"] is not None for s in snapshots):
        snapshots.sort(key=lambda s: s["timestamp"])
        logger.info(
            "Found %d snapshot(s), sorted by creation date.", len(snapshots)
        )
    elif snapshots:
        logger.warning(
            "Some timestamps could not be parsed. "
            "Using listing order (chronological for linear chains)."
        )
        logger.info("Found %d snapshot(s).", len(snapshots))
    else:
        logger.info("No snapshots found.")

    return snapshots


# ---------------------------------------------------------------------------
# Snapshot deletion
# ---------------------------------------------------------------------------

def delete_old_snapshots(vboxmanage, vm_name, snapshots, logger):
    """
    Deletes all but the latest MAX_SNAPSHOTS_TO_KEEP snapshots.

    SAFETY: This function exclusively calls 'VBoxManage snapshot <vm> delete',
    which removes snapshot metadata and merges its differential disk image
    into the parent.  It does NOT delete the virtual machine itself.

    Every deletion is logged to ~/vbox_backup.log with the snapshot name,
    UUID, and timestamp so there is always a clear audit trail.

    Parameters:
        snapshots: List of snapshot dicts sorted oldest-first.
    """
    if len(snapshots) <= MAX_SNAPSHOTS_TO_KEEP:
        logger.info(
            "VM '%s' has %d snapshot(s) — within the retention limit of %d. "
            "No deletions needed.",
            vm_name,
            len(snapshots),
            MAX_SNAPSHOTS_TO_KEEP,
        )
        return

    # The oldest snapshots are at the front of the list; those are the ones to remove.
    num_to_delete = len(snapshots) - MAX_SNAPSHOTS_TO_KEEP
    snapshots_to_delete = snapshots[:num_to_delete]
    snapshots_to_keep = snapshots[num_to_delete:]

    logger.info(
        "VM '%s' has %d snapshot(s). Retention policy keeps the latest %d.",
        vm_name,
        len(snapshots),
        MAX_SNAPSHOTS_TO_KEEP,
    )
    logger.info(
        "Deleting %d old snapshot(s), keeping %d.",
        num_to_delete,
        len(snapshots_to_keep),
    )

    # Log what will be kept for the audit trail.
    for snap in snapshots_to_keep:
        logger.info(
            "  KEEPING: '%s' (UUID: %s, Created: %s)",
            snap["name"],
            snap["uuid"],
            snap["timestamp"] or "unknown",
        )

    # Delete each old snapshot one at a time, starting from the oldest.
    # Uses the UUID to avoid any ambiguity if multiple snapshots share a name.
    for snap in snapshots_to_delete:
        logger.info(
            "DELETING snapshot: '%s' (UUID: %s, Created: %s)",
            snap["name"],
            snap["uuid"],
            snap["timestamp"] or "unknown",
        )

        result = run_vboxmanage(
            vboxmanage,
            ["snapshot", vm_name, "delete", snap["uuid"]],
            logger,
        )

        if result.returncode != 0:
            logger.error(
                "Failed to delete snapshot '%s' (UUID: %s): %s",
                snap["name"],
                snap["uuid"],
                result.stderr.strip(),
            )
            logger.error(
                "Aborting script to prevent further issues. "
                "Please investigate before re-running."
            )
            sys.exit(1)

        logger.info("Successfully deleted snapshot '%s'.", snap["name"])


# ---------------------------------------------------------------------------
# Snapshot creation
# ---------------------------------------------------------------------------

def create_snapshot(vboxmanage, vm_name, logger):
    """
    Creates a new snapshot with a timestamped name.

    Naming format: Backup_YYYY-MM-DD_HH-MM-SS
    Example:       Backup_2026-03-18_14-30-00

    Also attaches a human-readable description to the snapshot.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    snapshot_name = f"{SNAPSHOT_PREFIX}_{timestamp}"

    logger.info(
        "Creating new snapshot '%s' for VM '%s'...", snapshot_name, vm_name
    )

    result = run_vboxmanage(
        vboxmanage,
        [
            "snapshot", vm_name, "take", snapshot_name,
            "--description",
            f"Automated backup created on {timestamp}",
        ],
        logger,
    )

    if result.returncode != 0:
        logger.error(
            "Failed to create snapshot '%s': %s",
            snapshot_name,
            result.stderr.strip(),
        )
        sys.exit(1)

    logger.info("Successfully created snapshot '%s'.", snapshot_name)
    return snapshot_name


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    """
    Orchestrates the full snapshot-management workflow:
      1. Parse command-line arguments (-v for VM name, -l to list VMs).
      2. If -l is given, list all registered VMs and exit.
      3. Set up dual logging (console + ~/vbox_backup.log).
      4. Locate the VBoxManage executable.
      5. Verify the VM exists.
      6. Verify the VM is powered off.
      7. List existing snapshots and sort by creation date.
      8. Delete old snapshots beyond the retention limit.
      9. Create a new timestamped snapshot.
    """
    # --- Parse command-line arguments ---
    parser = argparse.ArgumentParser(
        description=(
            "VirtualBox Snapshot Automation — retains the latest 2 snapshots "
            "and creates a new timestamped backup snapshot."
        ),
    )
    parser.add_argument(
        "-v",
        "--vm-name",
        help="Name of the VirtualBox VM to manage snapshots for.",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="List all registered VirtualBox VMs and exit.",
    )
    args = parser.parse_args()

    # --- Validate that at least one action flag was provided ---
    if not args.list and not args.vm_name:
        parser.error("one of the arguments -v/--vm-name or -l/--list is required")

    # --- Set up logging (needed for both -l and -v paths) ---
    logger = setup_logging()

    # --- Locate the VBoxManage executable ---
    vboxmanage = find_vboxmanage()

    # --- If -l/--list was requested, print VMs and exit ---
    if args.list:
        list_vms(vboxmanage, logger)
        sys.exit(0)

    vm_name = args.vm_name

    # --- Log the session header ---
    logger.info("=" * 60)
    logger.info("VirtualBox Snapshot Automation — Starting")
    logger.info("Target VM: '%s'", vm_name)
    logger.info("Log file:  %s", LOG_FILE)
    logger.info(
        "Retention policy: keep latest %d snapshot(s)", MAX_SNAPSHOTS_TO_KEEP
    )
    logger.info("=" * 60)
    logger.info("VBoxManage found at: %s", vboxmanage)

    # --- Verify the VM exists in VirtualBox ---
    vm_info = check_vm_exists(vboxmanage, vm_name, logger)

    # --- Verify the VM is NOT running ---
    check_vm_not_running(vboxmanage, vm_name, vm_info, logger)

    # --- Retrieve existing snapshots sorted by creation date ---
    snapshots = get_snapshots(vboxmanage, vm_name, logger)

    # --- Delete snapshots that exceed the retention limit ---
    delete_old_snapshots(vboxmanage, vm_name, snapshots, logger)

    # --- Create a fresh timestamped snapshot ---
    new_snapshot = create_snapshot(vboxmanage, vm_name, logger)

    # --- Summary ---
    logger.info("=" * 60)
    logger.info("Snapshot automation complete for VM '%s'.", vm_name)
    logger.info("New snapshot created: '%s'", new_snapshot)
    logger.info("Full log saved to: %s", LOG_FILE)
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
