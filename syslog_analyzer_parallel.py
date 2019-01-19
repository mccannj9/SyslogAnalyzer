#! /usr/bin/env python3

from datetime import datetime
import re

from multiprocessing import Process, Manager
from multiprocessing import JoinableQueue as Queue
from itertools import zip_longest


# Faster to compile the regex, rather than just using raw string
REGEX = re.compile(
    r"^<(?P<pri>[0-9]+)>"  # priority group
    r"(?P<timestamp>[A-Za-z]{3}\s{1,2}[0-9]{1,2}\s"  # timestamp group
    r"[0-9]{2}:[0-9]{2}:[0-9]{2})\s"  # timestamp group
    r"(?P<host>\S+)\s"  # host group
    r"(?P<msg>.*)$"  # message group
)


# SOME HELPER FUNCTIONS FOR PROCESSING DATA
def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def flatten_list(l):
    return [item for sublist in l for item in sublist]


def worker(q, r):

    stats = ["alerts", "oldest", "newest", "msg_len", "count", "msg_avg"]
    inits = [
        0, datetime.strptime("Dec 31 23:59:59", "%b %d %H:%M:%S"),
        datetime.strptime("Jan 01 00:00:00", "%b %d %H:%M:%S"), 0, 0
    ]
    overall = dict(zip(stats,inits))
    per_host = {}

    while True:
        lines = q.get()
        if lines is None:
            r.append((overall, per_host))
            break
        for line in lines:
            if line is None:
                break
            pri, timestamp, host, msg = extract_data_from_line(line)
            update_dictionary_data(overall, pri, timestamp, msg)
            per_host[host] = per_host.get(host, dict(zip(stats, inits)))
            update_dictionary_data(per_host[host], pri, timestamp, msg)
        q.task_done()

    return 0


def update_dictionary_data(d, pri, timestamp, msg):
    d['alerts'] += pri
    if timestamp < d['oldest']:
        d['oldest'] = timestamp
    # Have to check both in case of a single msg for a host
    # Would otherwise output the initialized date in inits var
    if timestamp > d['newest']:
        d['newest'] = timestamp
    d['msg_len'] += msg
    d['count'] += 1
    d['msg_avg'] = d['msg_len']/d['count']


def extract_data_from_line(line):
    match = REGEX.match(line)
    groups = match.groupdict()
    pri = (int(groups['pri']) & 7) < 2
    timestamp = datetime.strptime(
        groups['timestamp'], "%b %d %H:%M:%S"
    )
    host = groups['host']
    msg = match.end('msg') - match.start('msg')
    return pri, timestamp, host, msg


def concatenate_results_from_processes(results_list):
    stats = ["alerts", "oldest", "newest", "msg_len", "count", "msg_avg"]
    inits = [
        0, datetime.strptime("Dec 31 23:59:59", "%b %d %H:%M:%S"),
        datetime.strptime("Jan 01 00:00:00", "%b %d %H:%M:%S"), 0, 0
    ]
    overall = dict(zip(stats,inits))

    dates = []
    for val in results_list:
        overall["alerts"] += val["alerts"]
        overall["msg_len"] += val["msg_len"]
        overall["count"] += val["count"]
        dates.append(val["oldest"])
        dates.append(val["newest"])
    dates.sort()
    overall["oldest"] = dates[0]
    overall["newest"] = dates[-1]
    overall["msg_avg"] = overall["msg_len"]/overall["count"]
    return overall


def main():

    import argparse as ap
    import sys

    desc = """
                A program for analyzing old RFC3164 standard syslog files.
                Prints statistics on severity, oldest and newest
                messages, plus the average message length over all hosts
                in a tab-delimited text output file.

    """

    parser = ap.ArgumentParser(
        prog='syslog_analyzer_parallel.py', description=desc
    )
    parser.add_argument(
        '-i', "--logfile", nargs='?',
        help="input logfile to be analyzed, default=stdin",
        type=ap.FileType('r'), default=sys.stdin
    )
    parser.add_argument(
        '-o', "--outfile", nargs='?',
        help="outfile for log statistics, default=stdout",
        type=ap.FileType('w'), default=sys.stdout
    )
    parser.add_argument(
        '-n', "--number-of-processes",
        help="number of processes to use, default=1",
        type=int, default=1
    )
    parser.add_argument(
        '-c', "--chunk-size",
        help="number of lines to queue per queued item",
        type=int, default=10000
    )
    args = parser.parse_args()

    # NOTE: Oldest and Newest assume we are in the following year
    # NOTE: So, the newest a message can be is 31/12 23:59:59
    # NOTE: and the oldest a message can be is 01/01 00:00:00

    # NEW CODE FOR MULTIPROCESSING ########
    # Setting max queue size to reduce memory load
    q = Queue(maxsize=32767)
    processes = []

    manager = Manager()
    results = manager.list()

    count = 1
    print(f"\nSpawning {args.number_of_processes} workers", file=sys.stderr)
    for i in range(args.number_of_processes):
        p = Process(target=worker, args=(q, results,))
        p.start()
        print(f"Starting Process: {count} PID={p.pid}")

        processes.append(p)
        count += 1

    # Break the file in to iterable chunks and queue each chunk
    with args.logfile as f:
        print(f"\nReading data from '{args.logfile.name}'", file=sys.stderr)
        chunks = grouper(f, args.chunk_size, fillvalue=None)
        count = 0
        for c in chunks:
            q.put(c)
            count += 1
        print(f"\nBroke input file into {count} chunks", file=sys.stderr)
    q.join()

    count = 0
    for p in processes:
        count += p.is_alive()
        q.put(None)

    count = 1
    for p in processes:
        p.join()
        print(
            (f"Process {count} with pid: {p.pid}"
                f" finished, exit code: {p.exitcode}"),
            file=sys.stderr
        )
        count += 1

    print(
        (f"\nConcatenating data from the"
            f" {args.number_of_processes} spawned processes"),
        file=sys.stderr
    )
    overalls = [res[0] for res in results]
    overall = concatenate_results_from_processes(overalls)
    per_host_results = [res[1] for res in results]
    per_host_keys = [res[1].keys() for res in results]

    # Extract unique keys from all result dictionaries
    per_host_keys_unique = set(flatten_list(per_host_keys))

    per_host = {}
    for host in per_host_keys_unique:
        results = []
        for res in per_host_results:
            if host in res:
                results.append(res[host])
        per_host_result_all = concatenate_results_from_processes(results)
        per_host[host] = per_host_result_all

    # Print out statistics in tab-delimited format
    useful_stats = ["alerts", "oldest", "newest", "msg_avg"]
    header = [
        "Emergency_Alert", "Oldest_Msg",
        "Newest_Msg", "Avg_Msg_Length"
    ]
    print(f"\nExporting data to '{args.outfile.name}'\n", file=sys.stderr)
    with args.outfile as out:
        # Could subclass datetime to make __str__ print w/o year
        # But it is 1 sec or more slower per million lines
        overall['newest'] = overall['newest'].strftime("%m/%d %H:%M:%S")
        overall['oldest'] = overall['oldest'].strftime("%m/%d %H:%M:%S")

        print("\t".join(["Host"] + header), file=out)
        print("\t".join(
            ["Overall"] + [str(overall[x]) for x in useful_stats]
        ), file=out)

        for host in per_host:
            per_host[host]['newest'] = per_host[host]['newest'].strftime(
                "%m/%d %H:%M:%S"
            )
            per_host[host]['oldest'] = per_host[host]['oldest'].strftime(
                "%m/%d %H:%M:%S"
            )
            print("\t".join(
                [host] + [str(per_host[host][x]) for x in useful_stats]
            ), file=out)

    return 0


if __name__ == '__main__':
    main()
