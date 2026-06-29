#!/usr/bin/env python3
"""
logreduce.py — Sumo Logic LogReduce® equivalent for local log files
--------------------------------------------------------------------
Clusters log lines into signatures using the Drain algorithm.
Variable fields (IPs, timestamps, numbers, hashes) are replaced
with wildcard placeholders so you see the pattern, not the noise.

Usage:
  python3 logreduce.py [OPTIONS] <logfile> [logfile2 ...]

  Read from stdin:
  cat /var/log/syslog | python3 logreduce.py -

Examples:
  python3 logreduce.py /var/log/syslog
  python3 logreduce.py /var/log/zabbix/zabbix_agentd.log --top 20
  python3 logreduce.py /var/log/auth.log --min-count 5 --no-color
  python3 logreduce.py /var/log/syslog --since "2025-06-20" --until "2025-06-28"
  journalctl -u zabbix-agent --since "2 weeks ago" | python3 logreduce.py -
  python3 logreduce.py /var/log/syslog --grep "error" --output report.txt

Options:
  -t, --top N          Show only top N signatures by count (default: all)
  -m, --min-count N    Hide signatures with fewer than N messages (default: 1)
  -s, --similarity F   Clustering threshold 0.0-1.0 (default: 0.4, lower=broader)
  -d, --depth N        Drain tree depth (default: 4)
  --since DATE         Filter lines on/after date (e.g. 2025-06-20 or "yesterday")
  --until DATE         Filter lines up to date
  --grep PATTERN       Pre-filter lines containing PATTERN (case-insensitive)
  --no-color           Disable ANSI color output
  --no-strip-ts        Do not strip leading timestamps from log lines
  --output FILE        Write report to FILE in addition to stdout
  --show-examples N    Show N example lines per signature (default: 1)

No external dependencies required. Python 3.6+.
"""

import sys
import re
import os
import math
import argparse
import textwrap
from collections import defaultdict, OrderedDict
from datetime import datetime, timedelta
from typing import List, Optional, Tuple, Dict


# ─────────────────────────────────────────────
# ANSI colours
# ─────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"
    BG_DARK= "\033[48;5;235m"

USE_COLOR = True

def col(code: str, text: str) -> str:
    return f"{code}{text}{C.RESET}" if USE_COLOR else text

def bold(t):   return col(C.BOLD,   t)
def dim(t):    return col(C.DIM,    t)
def red(t):    return col(C.RED,    t)
def yellow(t): return col(C.YELLOW, t)
def cyan(t):   return col(C.CYAN,   t)
def green(t):  return col(C.GREEN,  t)
def gray(t):   return col(C.GRAY,   t)
def blue(t):   return col(C.BLUE,   t)


# ─────────────────────────────────────────────
# Pre-processing: mask known variable patterns
# ─────────────────────────────────────────────
MASKS = [
    # IPv4
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b'), '<IP>'),
    # IPv6
    (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b'), '<IPv6>'),
    # MAC address
    (re.compile(r'\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b'), '<MAC>'),
    # UUID
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), '<UUID>'),
    # Hex numbers (0x...)
    (re.compile(r'\b0x[0-9a-fA-F]+\b'), '<HEX>'),
    # Long hex strings (hashes, tokens)
    (re.compile(r'\b[0-9a-fA-F]{16,}\b'), '<HASH>'),
    # Paths with variable parts (/proc/1234 etc)
    (re.compile(r'(?<=/)\d{3,}(?=/|$|\s|:|\))'), '<NUM>'),
    # Port numbers after colon
    (re.compile(r'(?<=:)\d{4,5}\b'), '<PORT>'),
    # Standalone integers (3+ digits)  — keep 1-2 digit nums readable
    (re.compile(r'\b\d{3,}\b'), '<NUM>'),
    # Floating point
    (re.compile(r'\b\d+\.\d+\b'), '<FLOAT>'),
    # Quoted strings
    (re.compile(r'"[^"]{4,}"'), '"<STR>"'),
    (re.compile(r"'[^']{4,}'"), "'<STR>'"),
    # Email
    (re.compile(r'\b[\w.+-]+@[\w.-]+\.\w+\b'), '<EMAIL>'),
    # URLs
    (re.compile(r'https?://\S+'), '<URL>'),
]

# Timestamp patterns to strip from the front of log lines
TS_PATTERNS = [
    # ISO 8601: 2025-06-20T14:33:01.123456+00:00
    re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s*'),
    # syslog: Jun 20 14:33:01
    re.compile(r'^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+'),
    # epoch float: 1718886781.123
    re.compile(r'^\d{10,13}(?:\.\d+)?\s+'),
]


def strip_timestamp(line: str) -> str:
    for pat in TS_PATTERNS:
        line = pat.sub('', line, count=1)
    return line


def tokenize(line: str, strip_ts: bool = True) -> Tuple[List[str], str]:
    """Return (tokens, masked_line). Tokens drive clustering; masked_line is displayed."""
    if strip_ts:
        line = strip_timestamp(line)
    masked = line
    for pat, placeholder in MASKS:
        masked = pat.sub(placeholder, masked)
    tokens = masked.split()
    return tokens, masked


# ─────────────────────────────────────────────
# Drain algorithm (pure Python, no deps)
# ─────────────────────────────────────────────
WILDCARD = '<*>'

class LogCluster:
    __slots__ = ('template_tokens', 'count', 'examples')
    def __init__(self, template_tokens: List[str]):
        self.template_tokens = template_tokens
        self.count = 0
        self.examples: List[str] = []   # raw original lines

    @property
    def signature(self) -> str:
        return ' '.join(self.template_tokens)

    def add(self, raw_line: str):
        self.count += 1
        if len(self.examples) < 5:
            self.examples.append(raw_line.rstrip())


class DrainParser:
    def __init__(self, depth: int = 4, sim_threshold: float = 0.4, max_clusters: int = 1000):
        self.depth = depth
        self.sim_threshold = sim_threshold
        self.max_clusters = max_clusters
        # prefix tree: root → length_bucket → token_prefix... → [clusters]
        self.root: Dict = {}
        self.clusters: "OrderedDict[int, LogCluster]" = OrderedDict()
        self._next_id = 1

    # ── Tree navigation ───────────────────────────────────────────────
    def _get_or_create(self, d: dict, key) -> dict:
        if key not in d:
            d[key] = {}
        return d[key]

    def _find_candidates(self, tokens: List[str]) -> List[LogCluster]:
        n = len(tokens)
        node = self.root.get(n)
        if node is None:
            return []
        # Walk down the prefix tree using first (depth-1) tokens
        for i, tok in enumerate(tokens[:self.depth - 1]):
            key = tok if not re.fullmatch(r'<\w+>', tok) else WILDCARD
            if key not in node:
                if WILDCARD in node:
                    node = node[WILDCARD]
                else:
                    return []
            else:
                node = node[key]
        # Leaf: list of cluster ids
        return [self.clusters[cid] for cid in node.get('__clusters__', [])
                if cid in self.clusters]

    def _add_to_tree(self, tokens: List[str], cluster_id: int):
        n = len(tokens)
        node = self._get_or_create(self.root, n)
        for tok in tokens[:self.depth - 1]:
            key = tok if not re.fullmatch(r'<\w+>', tok) else WILDCARD
            node = self._get_or_create(node, key)
        node.setdefault('__clusters__', []).append(cluster_id)

    # ── Similarity ────────────────────────────────────────────────────
    @staticmethod
    def _similarity(tokens: List[str], template: List[str]) -> float:
        if len(tokens) != len(template):
            return 0.0
        matches = sum(
            1 for t, tmpl in zip(tokens, template)
            if t == tmpl or tmpl == WILDCARD
        )
        return matches / len(tokens)

    @staticmethod
    def _merge_template(tokens: List[str], template: List[str]) -> List[str]:
        return [
            t if t == tmpl else WILDCARD
            for t, tmpl in zip(tokens, template)
        ]

    # ── Main entry point ──────────────────────────────────────────────
    def add_line(self, raw_line: str, strip_ts: bool = True) -> LogCluster:
        tokens, _ = tokenize(raw_line, strip_ts)
        if not tokens:
            tokens = [WILDCARD]

        candidates = self._find_candidates(tokens)

        best_cluster: Optional[LogCluster] = None
        best_sim = -1.0
        for cluster in candidates:
            sim = self._similarity(tokens, cluster.template_tokens)
            if sim > best_sim:
                best_sim = sim
                best_cluster = cluster

        if best_sim >= self.sim_threshold and best_cluster is not None:
            # Update existing cluster template (merge wildcards)
            best_cluster.template_tokens = self._merge_template(
                tokens, best_cluster.template_tokens
            )
            best_cluster.add(raw_line)
            # Move to end (LRU)
            self.clusters.move_to_end(
                next(k for k, v in self.clusters.items() if v is best_cluster)
            )
            return best_cluster
        else:
            # Create new cluster
            if len(self.clusters) >= self.max_clusters:
                # Evict LRU
                evict_id, _ = self.clusters.popitem(last=False)
                # NOTE: tree still holds the id but that's fine — next lookup
                # finds no cluster and creates a new one naturally.
            cid = self._next_id
            self._next_id += 1
            cluster = LogCluster(list(tokens))
            cluster.add(raw_line)
            self.clusters[cid] = cluster
            self._add_to_tree(tokens, cid)
            return cluster

    def sorted_clusters(self) -> List[Tuple[int, LogCluster]]:
        """Return clusters sorted by count descending."""
        return sorted(self.clusters.items(), key=lambda x: x[1].count, reverse=True)


# ─────────────────────────────────────────────
# Date filtering
# ─────────────────────────────────────────────
DATE_FORMATS = [
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d',
]

def parse_date_arg(s: str) -> Optional[datetime]:
    s = s.strip().lower()
    if s == 'yesterday':
        d = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        return d - timedelta(days=1)
    if s == 'today':
        return datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    if s.startswith('-') and s[1:].isdigit():
        return datetime.now() - timedelta(days=int(s[1:]))
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    print(f"[warn] Could not parse date: {s!r} — ignoring filter", file=sys.stderr)
    return None


TS_EXTRACT = [
    # ISO
    re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'),
    # syslog (assumes current year)
    re.compile(r'((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
]

def extract_line_date(line: str) -> Optional[datetime]:
    for pat in TS_EXTRACT:
        m = pat.search(line)
        if m:
            for fmt in DATE_FORMATS:
                try:
                    return datetime.strptime(m.group(1)[:19], fmt)
                except ValueError:
                    pass
            # syslog without year
            try:
                dt = datetime.strptime(m.group(1), '%b %d %H:%M:%S')
                return dt.replace(year=datetime.now().year)
            except ValueError:
                pass
    return None


# ─────────────────────────────────────────────
# Bar chart helper
# ─────────────────────────────────────────────
def make_bar(count: int, max_count: int, width: int = 30) -> str:
    if max_count == 0:
        return ' ' * width
    filled = max(1, round(count / max_count * width))
    bar = '█' * filled + '░' * (width - filled)
    return bar


# ─────────────────────────────────────────────
# Report rendering
# ─────────────────────────────────────────────
def render_signature(sig: str) -> str:
    """Colorize wildcards in a signature string."""
    if not USE_COLOR:
        return sig
    return re.sub(r'<[^>]+>', lambda m: col(C.YELLOW, m.group()), sig)


def print_report(
    clusters: List[Tuple[int, LogCluster]],
    total_lines: int,
    skipped: int,
    args,
    outfile=None,
):
    lines_in_clusters = sum(c.count for _, c in clusters)
    n_sigs = len(clusters)
    max_count = clusters[0][1].count if clusters else 1
    try:
        term_width = min(os.get_terminal_size().columns, 160)
    except OSError:
        term_width = 120

    def emit(s=''):
        print(s)
        if outfile:
            # strip ANSI for file output
            clean = re.sub(r'\033\[[0-9;]*m', '', s)
            outfile.write(clean + '\n')

    sep = '─' * term_width

    emit()
    emit(bold(cyan('╔══ LogReduce — Log Signature Report ══╗')))
    emit(bold(f'  Input lines : {total_lines:,}'))
    if skipped:
        emit(dim(f'  Skipped (filter): {skipped:,}'))
    emit(bold(f'  Clustered   : {lines_in_clusters:,}  ({100*lines_in_clusters/max(total_lines,1):.1f}%)'))
    emit(bold(f'  Signatures  : {n_sigs}'))
    emit(bold(f'  Sim threshold: {args.similarity}   Depth: {args.depth}'))
    emit()
    emit(sep)
    emit()

    # Header row
    count_w = max(5, len(str(max_count)))
    pct_w   = 7
    bar_w   = 28
    sig_label = 'SIGNATURE  (wildcards shown as <*> or <TYPE>)'
    header = (
        bold('  #  ') +
        bold(f'{"COUNT":>{count_w}}') + '  ' +
        bold(f'{"  %":>{pct_w}}') + '  ' +
        bold(f'{"FREQUENCY BAR":<{bar_w}}') + '  ' +
        bold(sig_label)
    )
    emit(header)
    emit(sep)

    for rank, (cid, cluster) in enumerate(clusters, 1):
        pct = 100.0 * cluster.count / max(total_lines, 1)
        bar = make_bar(cluster.count, max_count, bar_w)

        # Color the bar by relative frequency
        if cluster.count == max_count:
            bar_str = col(C.RED, bar)
        elif pct > 5:
            bar_str = col(C.YELLOW, bar)
        elif pct > 1:
            bar_str = col(C.CYAN, bar)
        else:
            bar_str = col(C.BLUE, bar)

        rank_str = gray(f'{rank:>3}. ')
        count_str = bold(f'{cluster.count:>{count_w},}')
        pct_str = f'{pct:>{pct_w}.2f}%'
        sig_str = render_signature(cluster.signature)

        emit(f'{rank_str}{count_str}  {pct_str}  {bar_str}  {sig_str}')

        # Show example lines
        if args.show_examples > 0:
            for ex in cluster.examples[:args.show_examples]:
                truncated = ex[:term_width - 8]
                if len(ex) > term_width - 8:
                    truncated += '…'
                emit(dim(f'           ↳ {truncated}'))

        emit()

    emit(sep)
    emit(dim(f'  Signatures shown: {n_sigs}  |  Total lines processed: {total_lines:,}'))
    emit()


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description='LogReduce — cluster log lines into signatures (Drain algorithm)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(__doc__.split('No external')[0])
    )
    p.add_argument('files', nargs='*', default=['-'], metavar='FILE',
                   help='Log file(s) to process, or - for stdin')
    p.add_argument('-t', '--top', type=int, default=None, metavar='N',
                   help='Show only top N signatures')
    p.add_argument('-m', '--min-count', type=int, default=1, metavar='N',
                   help='Minimum message count to show a signature (default: 1)')
    p.add_argument('-s', '--similarity', type=float, default=0.4, metavar='F',
                   help='Similarity threshold 0.0-1.0 (default: 0.4)')
    p.add_argument('-d', '--depth', type=int, default=4, metavar='N',
                   help='Drain tree depth (default: 4)')
    p.add_argument('--since', default=None, metavar='DATE',
                   help='Include lines on/after this date')
    p.add_argument('--until', default=None, metavar='DATE',
                   help='Include lines up to this date')
    p.add_argument('--grep', default=None, metavar='PATTERN',
                   help='Only process lines matching this regex (case-insensitive)')
    p.add_argument('--no-color', action='store_true',
                   help='Disable ANSI color output')
    p.add_argument('--no-strip-ts', action='store_true',
                   help='Do not strip leading timestamps before clustering')
    p.add_argument('--output', default=None, metavar='FILE',
                   help='Write report to this file (plain text, no ANSI)')
    p.add_argument('--show-examples', type=int, default=1, metavar='N',
                   help='Show N example log lines per signature (default: 1, 0=none)')
    p.add_argument('--max-clusters', type=int, default=2000, metavar='N',
                   help='Max number of cluster templates tracked (default: 2000)')
    return p.parse_args()


def open_source(path: str):
    if path == '-':
        return sys.stdin
    return open(path, 'r', errors='replace')


def main():
    global USE_COLOR
    args = parse_args()

    if args.no_color or not sys.stdout.isatty():
        USE_COLOR = False

    # Date filters
    since_dt = parse_date_arg(args.since) if args.since else None
    until_dt = parse_date_arg(args.until) if args.until else None

    # Grep filter
    grep_re = re.compile(args.grep, re.IGNORECASE) if args.grep else None

    drain = DrainParser(
        depth=args.depth,
        sim_threshold=args.similarity,
        max_clusters=args.max_clusters,
    )

    total_lines = 0
    skipped = 0
    strip_ts = not args.no_strip_ts

    for path in args.files:
        try:
            fh = open_source(path)
        except FileNotFoundError:
            print(red(f'[error] File not found: {path}'), file=sys.stderr)
            continue

        try:
            for raw in fh:
                raw = raw.rstrip('\n')
                if not raw.strip():
                    continue

                # Grep pre-filter
                if grep_re and not grep_re.search(raw):
                    skipped += 1
                    continue

                # Date filter
                if since_dt or until_dt:
                    line_dt = extract_line_date(raw)
                    if line_dt:
                        if since_dt and line_dt < since_dt:
                            skipped += 1
                            continue
                        if until_dt and line_dt > until_dt:
                            skipped += 1
                            continue
                    # If no date found in line and filter is set, include anyway

                drain.add_line(raw, strip_ts=strip_ts)
                total_lines += 1

                # Progress indicator every 50k lines
                if total_lines % 50000 == 0:
                    print(dim(f'  … processed {total_lines:,} lines …'), file=sys.stderr)
        finally:
            if fh is not sys.stdin:
                fh.close()

    if total_lines == 0:
        print(yellow('[warn] No log lines were processed.'))
        sys.exit(0)

    # Apply filters and sort
    results = drain.sorted_clusters()
    results = [(cid, c) for cid, c in results if c.count >= args.min_count]
    if args.top:
        results = results[:args.top]

    # Open output file if requested
    outfile = None
    if args.output:
        try:
            outfile = open(args.output, 'w', encoding='utf-8')
        except IOError as e:
            print(red(f'[error] Cannot open output file: {e}'), file=sys.stderr)

    try:
        print_report(results, total_lines, skipped, args, outfile=outfile)
    finally:
        if outfile:
            outfile.close()
            print(green(f'  Report saved to: {args.output}'))


if __name__ == '__main__':
    main()
