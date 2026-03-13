#!/usr/bin/env python3
"""
Organize files in a directory into subdirectories
by modification date and extension.

Files are moved into: <source_dir>/YYYY/MM/<extension>/
Files with no extension are moved into: <source_dir>/YYYY/MM/misc/

Usage:
    python3 organize_files.py -d /path/to/directory
    python3 organize_files.py -d /path/to/directory --dry-run
"""

import argparse
import logging
import platform
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def detect_os() -> str:
    """Detect and return a human-friendly OS name."""
    system_map = {
        "Linux": "Linux",
        "Darwin": "MacOS",
        "Windows": "Windows",
    }
    system = platform.system()
    return system_map.get(system, system)


def get_file_details(filepath: Path) -> tuple[str, str, str]:
    """
    Extract the year, month, and extension from a file's modification time.

    Returns:
        A tuple of (year, month, extension).
        Extension is "misc" when the file has none.
    """
    mtime_timestamp = filepath.stat().st_mtime
    mtime = datetime.fromtimestamp(mtime_timestamp)
    year = mtime.strftime("%Y")
    month = mtime.strftime("%m")

    extension = filepath.suffix.lstrip(".").lower()
    if not extension:
        extension = "misc"

    return year, month, extension


def sanitize_filename(name: str) -> str:
    """Replace consecutive whitespace in a filename with underscores."""
    return re.sub(r"\s+", "_", name)


def resolve_duplicate(
    destination: Path, planned_destinations: set[Path]
) -> Path:
    """
    Return a non-colliding destination path.

    Checks both the filesystem and a set of already-planned destinations
    (needed for accurate dry-run output when multiple source files
    would map to the same target).

    Duplicates are resolved by appending _1, _2, etc. before the extension.
    """
    not_planned = destination not in planned_destinations
    if not_planned and not destination.exists():
        return destination

    stem = destination.stem
    suffix = destination.suffix
    parent = destination.parent
    counter = 1

    while True:
        new_name = f"{stem}_{counter}{suffix}"
        candidate = parent / new_name
        not_planned = candidate not in planned_destinations
        if not_planned and not candidate.exists():
            return candidate
        counter += 1


def build_destination(
    source_dir: Path,
    filename: str,
    year: str,
    month: str,
    extension: str,
) -> Path:
    """Build destination: source_dir/YEAR/MONTH/EXT/filename."""
    return source_dir / year / month / extension / filename


def gather_files(source_dir: Path) -> list[Path]:
    """
    Return all regular, non-hidden files directly inside source_dir.

    Directories, hidden files (starting with '.'), and symlinks
    are excluded. Sorted by name for deterministic output.
    """
    return sorted(
        item
        for item in source_dir.iterdir()
        if item.is_file()
        and not item.is_symlink()
        and not item.name.startswith(".")
    )


def organize_files(
    source_dir: Path, dry_run: bool = False
) -> dict[str, int]:
    """
    Scan source_dir and move files into dated/extension subfolders.

    Returns:
        A dict with counts: {"moved": N, "skipped": N}
    """
    files = gather_files(source_dir)

    if not files:
        logger.info("No eligible files found in '%s'.", source_dir)
        return {"moved": 0, "skipped": 0}

    logger.info(
        "Found %d eligible file(s) in '%s'.",
        len(files),
        source_dir,
    )

    moved = 0
    skipped = 0
    planned_destinations: set[Path] = set()

    for filepath in files:
        try:
            year, month, extension = get_file_details(filepath)
            sanitized_name = sanitize_filename(filepath.name)
            destination = build_destination(
                source_dir, sanitized_name, year, month, extension
            )
            destination = resolve_duplicate(destination, planned_destinations)
            planned_destinations.add(destination)

            if dry_run:
                logger.info("[DRY RUN] %s -> %s", filepath, destination)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(filepath), str(destination))
                logger.info("Moved: %s -> %s", filepath, destination)

            moved += 1

        except OSError as exc:
            logger.error("Failed to process '%s': %s", filepath, exc)
            skipped += 1

    return {"moved": moved, "skipped": skipped}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Organize files into subdirectories "
            "by modification date and extension."
        ),
    )
    parser.add_argument(
        "-d",
        "--directory",
        type=Path,
        required=True,
        help="Path to the source directory to organize.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview file moves without making any changes.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse arguments, detect OS, and run the organizer."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    args = parse_args(argv)
    source_dir = args.directory.expanduser().resolve()

    if not source_dir.is_dir():
        logger.error("'%s' is not a valid directory.", source_dir)
        return 1

    os_name = detect_os()
    logger.info("Operating system: %s", os_name)
    logger.info("Source directory:  %s", source_dir)

    if args.dry_run:
        logger.info("Mode: DRY RUN (no files will be moved)")

    results = organize_files(source_dir, dry_run=args.dry_run)

    action = "Would move" if args.dry_run else "Moved"
    logger.info(
        "Done. %s %d file(s), skipped %d file(s).",
        action,
        results["moved"],
        results["skipped"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
