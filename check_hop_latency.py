#!/usr/bin/env python3
"""
Check TCP connection latency to a specified hostname/IP and port.

Measures the time to complete a TCP handshake (SYN → SYN-ACK),
which gives a reliable round-trip latency measurement without
requiring elevated privileges (unlike ICMP ping).

Optionally saves results to a log file when -l/--log is specified
with a directory path. The log file is named:
    latency_check-<Host/IP>-<Port>.<YYYYMMDDHHSS>.log

Works on Windows, Mac, and Linux with no third-party dependencies.

Usage:
    python3 check_latency.py google.com 443
    python3 check_latency.py 8.8.8.8 53 -c 10 -t 3
    python3 check_latency.py example.com 80 -l /var/log
"""

# "import" loads a built-in Python library, similar to "source" in Bash.
# Each library provides tools the script uses later:
#   argparse -- parses command-line flags (-c, -t, -i, -l), like getopts
#   io       -- I/O base classes, used here for the TextIOBase type
#   math     -- mathematical functions (sqrt), like bc in Bash
#   datetime -- works with dates/times, like the "date" command
#   os       -- OS-level operations (path joining), like dirname/basename
#   socket   -- network connections (TCP/UDP), like nc (netcat)
#   sys      -- access to exit codes, like "exit 0" or "exit 1"
#   time     -- timing and delays, like the "sleep" and "date" commands
import argparse
import io
import math
import os
import socket
import sys
import time
from datetime import datetime


# TeeWriter sends every print() call to both the terminal AND a log
# file at the same time, like the "tee" command in Bash:
#   some_command | tee output.log
# By replacing sys.stdout with an instance of this class, all
# print() output is automatically duplicated — no need to change
# any of the existing print() calls.
class TeeWriter(io.TextIOBase):
    """Write to both the terminal and a log file simultaneously."""

    def __init__(self, terminal: io.TextIOBase, logfile: io.TextIOBase):
        # Store references to both output destinations.
        # "self" is like "this" in other languages — it refers to the
        # current object instance. Python requires it explicitly.
        self.terminal = terminal
        self.logfile = logfile

    def write(self, message: str) -> int:
        """Write the message to both the terminal and the log file."""
        # Write to the terminal (so the user sees output as usual).
        self.terminal.write(message)
        # Write the same output to the log file.
        self.logfile.write(message)
        # Flush the log file immediately so nothing is lost if the
        # script is interrupted. Like writing with: echo "msg" >> file
        # (which flushes after each line by default in Bash).
        self.logfile.flush()
        # Return the number of characters written, which is what
        # Python's I/O interface expects.
        return len(message)

    def flush(self) -> None:
        """Flush both outputs to ensure all data is written to disk."""
        self.terminal.flush()
        self.logfile.flush()


# "def" defines a function, like a Bash function: my_func() { ... }
# "-> float" is a type hint — it tells the reader this function
# returns a floating-point number. Python doesn't enforce it;
# it's just documentation.
def measure_latency(host: str, port: int, timeout: float) -> float:
    """
    Measure TCP handshake latency to host:port.

    Returns the round-trip time in milliseconds.
    Raises OSError or socket.timeout on failure.
    """
    # socket.socket() creates a new network socket, similar to
    # opening a connection with: exec 3<>/dev/tcp/host/port
    #   AF_INET     = use IPv4 addressing
    #   SOCK_STREAM = use TCP (reliable, connection-oriented)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set how long to wait before giving up on the connection.
    # Like: timeout 5 nc -z host port
    sock.settimeout(timeout)

    # "try/finally" ensures the socket is always closed, even if
    # connect() throws an error. Like a Bash trap:
    #   trap 'exec 3>&-' EXIT
    try:
        # time.perf_counter() returns a high-resolution timestamp
        # (in seconds) for measuring short intervals. Like:
        #   start=$(date +%s%N)  (nanosecond-precision timer)
        start = time.perf_counter()

        # .connect() performs the TCP three-way handshake:
        #   Client sends SYN → Server replies SYN-ACK → Client sends ACK
        # The time this takes is essentially the network round-trip.
        # Equivalent to: nc -z host port (just open and immediately close)
        sock.connect((host, port))

        # Calculate elapsed time. Subtracting two perf_counter() calls
        # gives the duration in seconds with sub-millisecond precision.
        elapsed = time.perf_counter() - start

        # Convert seconds to milliseconds (* 1000) for readability.
        return elapsed * 1000.0
    finally:
        # Always close the socket to free the file descriptor,
        # like: exec 3>&-  (close fd 3 in Bash)
        sock.close()


def resolve_host(host: str) -> str:
    """Resolve hostname to IP address, or validate an IP literal."""
    # "try/except" is Python's error handling, like a Bash trap.
    # If gethostbyname() fails, execution jumps to "except"
    # instead of crashing the script.
    try:
        # gethostbyname() does a DNS lookup, like:
        #   dig +short example.com
        #   nslookup example.com
        # If "host" is already an IP (e.g. "8.8.8.8"), it returns
        # it unchanged.
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        # socket.gaierror ("get address info" error) means DNS
        # resolution failed — the hostname doesn't exist or DNS
        # is unreachable.
        # SystemExit immediately stops the script with an error
        # message, like: echo "error" >&2; exit 1
        raise SystemExit(f"Failed to resolve '{host}': {exc}") from exc


# This function takes several parameters and returns None (it only
# prints output). "list[float]" is a list of decimal numbers — like
# a Bash array of floating-point values.
def print_statistics(
    host: str, port: int, latencies: list[float], failed: int
) -> None:
    """Print summary statistics for the completed probes."""
    # len() returns the number of items in a list, like ${#array[@]}
    total = len(latencies) + failed
    # f"..." is a format string — variables inside {} get replaced.
    # Like Bash: echo "--- ${host}:${port} latency statistics ---"
    print(f"\n--- {host}:{port} latency statistics ---")
    print(
        f"{total} probes sent, {len(latencies)} succeeded, "
        f"{failed} failed"
    )

    # "if not latencies" is True when the list is empty (no
    # successful probes). Like: if [ ${#latencies[@]} -eq 0 ]; then
    if not latencies:
        return

    # min() / max() / sum() are built-in functions that work on
    # any list of numbers. Like piping numbers through sort:
    #   min: echo "${latencies[@]}" | tr ' ' '\n' | sort -n | head -1
    #   max: echo "${latencies[@]}" | tr ' ' '\n' | sort -n | tail -1
    lat_min = min(latencies)
    lat_max = max(latencies)

    # Average = sum of all values / count.
    # Like: echo "${latencies[@]}" | awk '{s+=$1} END {print s/NR}'
    lat_avg = sum(latencies) / len(latencies)

    # Standard deviation measures how spread out the values are.
    # Low stddev = consistent latency; high stddev = jittery connection.
    # Only meaningful with 2+ samples.
    if len(latencies) > 1:
        # Variance = average of squared differences from the mean.
        # The "for x in latencies" inside sum() is a generator
        # expression — it loops through each latency value and
        # computes (value - average)^2, then sums them all up.
        variance = sum((x - lat_avg) ** 2 for x in latencies) / len(latencies)
        # math.sqrt() computes the square root, like: echo "sqrt(N)" | bc
        lat_stddev = math.sqrt(variance)
    else:
        # With only one sample, stddev is zero (no spread).
        lat_stddev = 0.0

    # :.3f formats the number with 3 decimal places.
    # Like: printf "%.3f" $value
    print(
        f"min/avg/max/stddev = "
        f"{lat_min:.3f}/{lat_avg:.3f}/{lat_max:.3f}/{lat_stddev:.3f} ms"
    )


# This function returns a "tuple" — two values bundled together:
# (list of latencies, number of failures). Like a function that
# sets two variables at once in Bash.
def run_probes(
    host: str,
    ip: str,
    port: int,
    count: int,
    timeout: float,
    interval: float,
) -> tuple[list[float], int]:
    """
    Send *count* TCP probes and return (latencies, fail_count).

    Handles KeyboardInterrupt so the user can stop early with Ctrl+C
    and still see statistics.
    """
    print(f"Checking latency to {host} ({ip}) on port {port}")

    # A list to collect successful latency measurements.
    # Like declaring an empty array: latencies=()
    latencies: list[float] = []
    failed = 0

    # The outer try/except catches Ctrl+C (KeyboardInterrupt) so
    # we can print partial statistics instead of just crashing.
    # Like: trap 'print_stats; exit' INT
    try:
        # range(1, count + 1) generates numbers 1 through count.
        # Like: for seq in $(seq 1 $count); do ...
        for seq in range(1, count + 1):
            # Inner try/except handles per-probe errors (timeout,
            # connection refused, etc.) without stopping the loop.
            try:
                ms = measure_latency(ip, port, timeout)
                # .append() adds the value to the end of the list.
                # Like: latencies+=($ms)
                latencies.append(ms)
                print(
                    f"[{seq}] {host}:{port} ({ip}) "
                    f"tcp_seq={seq} time={ms:.3f} ms"
                )
            except socket.timeout:
                # The connection attempt exceeded the timeout.
                # The server may be down or a firewall is dropping
                # packets silently.
                print(f"[{seq}] {host}:{port} ({ip}) tcp_seq={seq} timed out")
                failed += 1
            except OSError as exc:
                # OSError covers other network failures: connection
                # refused, network unreachable, host unreachable, etc.
                print(
                    f"[{seq}] {host}:{port} ({ip}) "
                    f"tcp_seq={seq} error: {exc}"
                )
                failed += 1

            # Wait between probes, but not after the last one.
            # Like: [ $seq -lt $count ] && sleep $interval
            if seq < count:
                time.sleep(interval)

    except KeyboardInterrupt:
        # User pressed Ctrl+C — stop probing but don't crash.
        # The caller will still print statistics for whatever
        # probes completed before the interruption.
        print("\n--- interrupted ---")

    return latencies, failed


# "list[str] | None" means this parameter accepts either a list
# of strings or None. When None, argparse reads from sys.argv
# (the actual command-line arguments), just like "$@" in Bash.
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and return command-line arguments."""
    # argparse is Python's built-in flag parser. It works like
    # getopts in Bash but with automatic --help generation.
    #
    # RawDescriptionHelpFormatter tells argparse to keep the exact
    # whitespace/newlines in our epilog text instead of reflowing it
    # into a single paragraph. This lets us show nicely formatted
    # usage examples in the -h / --help output.
    parser = argparse.ArgumentParser(
        description=(
            "Measure TCP connection latency to a hostname/IP and port.\n"
            "\n"
            "Opens a TCP connection (handshake only) to the target and\n"
            "measures the round-trip time. This works without elevated\n"
            "privileges, unlike ICMP ping, and runs on Windows, Mac,\n"
            "and Linux with no third-party dependencies.\n"
            "\n"
            "Use -l/--log to save results to a log file in the specified\n"
            "directory: latency_check-<host>-<port>.<YYYYMMDDHHSS>.log"
        ),
        epilog=(
            "examples:\n"
            "  %(prog)s google.com 443              "
            "# 5 probes to google.com on HTTPS port\n"
            "  %(prog)s 8.8.8.8 53 -c 10            "
            "# 10 probes to Google DNS\n"
            "  %(prog)s example.com 80 -t 2 -i 0.5  "
            "# 2s timeout, 0.5s between probes\n"
            "  %(prog)s example.com 443 -l /var/log  "
            "# save log to /var/log/\n"
            "\n"
            "common port numbers:\n"
            "  22 = SSH, 53 = DNS, 80 = HTTP, 443 = HTTPS,\n"
            "  3306 = MySQL, 5432 = PostgreSQL, 6379 = Redis"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Positional argument: the target host. Positional means it
    # doesn't need a flag — it's identified by its position on
    # the command line. Like $1 in Bash.
    parser.add_argument(
        "host",
        help="Target hostname or IP address (e.g. google.com, 8.8.8.8).",
    )
    # Positional argument: the target port. type=int tells argparse
    # to automatically convert the string input to an integer.
    # Like: port=$(( $2 + 0 ))  to force numeric conversion.
    parser.add_argument(
        "port",
        type=int,
        help="Target TCP port number (1-65535).",
    )
    # Optional flag: -c / --count. "default=5" means if the user
    # doesn't provide this flag, it defaults to 5.
    # Like: count=${count:-5}  in Bash.
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=5,
        help="Number of probes to send (default: %(default)s).",
    )
    # Optional flag: -t / --timeout. Controls how long each
    # individual probe waits before giving up.
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout per probe in seconds (default: %(default)s).",
    )
    # Optional flag: -i / --interval. Controls the pause between
    # consecutive probes, like "sleep $interval" in a Bash loop.
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=1.0,
        help="Interval between probes in seconds (default: %(default)s).",
    )
    # Optional flag: -l / --log. When provided, results are written
    # to a log file inside the given directory. The log file is named
    # latency_check-<host>-<port>.<YYYYMMDDHHSS>.log. When omitted,
    # output goes only to the terminal. "default=None" means "no
    # logging" if the flag isn't used.
    # Like: [ -n "$log_dir" ] && enable_logging
    parser.add_argument(
        "-l",
        "--log",
        metavar="DIR",
        default=None,
        help=(
            "Directory to save the log file in. Creates a file named "
            "latency_check-<host>-<port>.<YYYYMMDDHHSS>.log inside DIR."
        ),
    )
    # .parse_args() reads the command-line input and returns an
    # object where each flag is an attribute: args.host, args.port,
    # args.count, etc. Like accessing $1, $2 after getopts.
    args = parser.parse_args(argv)

    # --- Input validation ---
    # argparse handles type conversion but not range checking,
    # so we validate the values manually.
    # parser.error() prints a message and exits with code 2,
    # like: echo "error: ..." >&2; exit 2
    if not 1 <= args.port <= 65535:
        parser.error(f"port must be between 1 and 65535, got {args.port}")
    if args.count < 1:
        parser.error(f"count must be at least 1, got {args.count}")
    if args.timeout <= 0:
        parser.error(f"timeout must be positive, got {args.timeout}")
    if args.interval < 0:
        parser.error(f"interval must be non-negative, got {args.interval}")
    # Validate the log directory exists and is actually a directory.
    # Like: [ -d "$log_dir" ] || echo "error" >&2; exit 2
    if args.log is not None and not os.path.isdir(args.log):
        parser.error(f"log directory does not exist: {args.log}")

    return args


# Returns an int (the exit code), like "return 0" or "return 1" in Bash.
def main(argv: list[str] | None = None) -> int:
    """Entry point: resolve host, run probes, print results."""
    args = parse_args(argv)

    # Resolve the hostname to an IP address before starting probes.
    # This way DNS resolution time isn't included in the latency
    # measurements, and we can show the IP in the output.
    ip = resolve_host(args.host)

    # If -l/--log was specified, build the full path for the log file.
    # The filename includes the target host, port, and a timestamp:
    #   latency_check-google.com-443.202604021530.log
    # datetime.now().strftime() formats the current date/time, like:
    #   date +"%Y%m%d%H%S"  in Bash.
    # os.path.join() combines directory + filename, like:
    #   log_path="${log_dir}/${log_name}"
    log_path = None
    if args.log is not None:
        timestamp = datetime.now().strftime("%Y%m%d%H%S")
        log_name = f"latency_check-{args.host}-{args.port}.{timestamp}.log"
        log_path = os.path.join(args.log, log_name)

    # _run_with_optional_log() handles the "tee" logic: if a log
    # path is given, output goes to both the terminal and the file;
    # otherwise output goes only to the terminal.
    latencies, failed = _run_with_optional_log(args, ip, log_path)

    # Print the summary statistics (min/avg/max/stddev).
    print_statistics(args.host, args.port, latencies, failed)

    # If we wrote a log file, tell the user where it is.
    if log_path is not None:
        print(f"\nResults saved to {log_path}")

    # Exit code 1 if every single probe failed (nothing reached
    # the target), 0 otherwise. Like: [ ${#latencies[@]} -eq 0 ]
    if not latencies:
        return 1
    return 0


def _run_with_optional_log(
    args: argparse.Namespace, ip: str, log_path: str | None
) -> tuple[list[float], int]:
    """
    Run probes, optionally teeing output to a log file.

    If log_path is None, output goes only to the terminal.
    If log_path is a file path, output goes to both the terminal
    and that file (like the Unix "tee" command).
    """
    if log_path is None:
        # No logging requested — just run the probes normally.
        return run_probes(
            host=args.host,
            ip=ip,
            port=args.port,
            count=args.count,
            timeout=args.timeout,
            interval=args.interval,
        )

    # open() creates/opens a file for writing, like: exec 4>file.log
    # "w" means write mode (creates the file or truncates if it
    # already exists). The "with" statement ensures the file is
    # automatically closed when the block ends, even if an error
    # occurs. Like a Bash trap: trap 'exec 4>&-' EXIT
    with open(log_path, "w") as logfile:
        # Replace sys.stdout (where print() sends output) with our
        # TeeWriter so every print() goes to both the screen and
        # the log file. Like running the whole script through:
        #   script_output | tee latency_check.12345.log
        original_stdout = sys.stdout
        sys.stdout = TeeWriter(original_stdout, logfile)

        # "try/finally" guarantees we restore sys.stdout even if
        # something goes wrong. Without this, a crash could leave
        # stdout permanently redirected.
        try:
            return run_probes(
                host=args.host,
                ip=ip,
                port=args.port,
                count=args.count,
                timeout=args.timeout,
                interval=args.interval,
            )
        finally:
            # Restore the original stdout so subsequent output
            # (like the statistics summary) goes only to the
            # terminal. Like: exec 1>&3  (restore fd 1)
            sys.stdout = original_stdout


# This is Python's version of the Bash idiom for "only run this code
# if the script is executed directly" (not imported by another script).
# Bash equivalent: if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main; fi
# sys.exit() passes the return value as the process exit code,
# so the shell sees it via $? after the script finishes.
if __name__ == "__main__":
    sys.exit(main())
