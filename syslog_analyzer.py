#! /usr/bin/env python3

from datetime import datetime
import re

# Faster to compile the regex, rather than just using raw string
REGEX = re.compile(
    r"^<(?P<pri>[0-9]+)>"  # priority group
    r"(?P<timestamp>[A-Za-z]{3}\s{1,2}[0-9]{1,2}\s"  # timestamp group
    r"[0-9]{2}:[0-9]{2}:[0-9]{2})\s"  # timestamp group
    r"(?P<host>\S+)\s"  # host group
    r"(?P<msg>.*)$"  # message group
)


def update_dictionary_data(data_dict, pri, timestamp, msg):
    data_dict['alerts'] += pri
    if timestamp < data_dict['oldest']:
        data_dict['oldest'] = timestamp
    # Have to check both in case of a single msg for a host
    # Would otherwise output the initialized date in inits var
    if timestamp > data_dict['newest']:
        data_dict['newest'] = timestamp
    data_dict['msg_len'] += msg
    data_dict['count'] += 1
    data_dict['msg_avg'] = data_dict['msg_len']/data_dict['count']


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


def main():

    import argparse as ap
    import sys

    parser = ap.ArgumentParser(prog='syslog_analyzer.py')
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
    args = parser.parse_args()

    # NOTE: Oldest and Newest assume we are in the following year
    # NOTE: So, the newest a message can be is 31/12 23:59:59
    # NOTE: and the oldest a message can be is 01/01 00:00:00

    stats = ["alerts", "oldest", "newest", "msg_len", "count", "msg_avg"]
    inits = [
        0, datetime.strptime("Dec 31 23:59:59", "%b %d %H:%M:%S"),
        datetime.strptime("Jan 01 00:00:00", "%b %d %H:%M:%S"), 0, 0
    ]

    overall = dict(zip(stats, inits))
    per_host = {}

    with args.logfile as f:
        for line in f:
            pri, timestamp, host, msg = extract_data_from_line(line)
            update_dictionary_data(overall, pri, timestamp, msg)
            per_host[host] = per_host.get(host, dict(zip(stats, inits)))
            update_dictionary_data(per_host[host], pri, timestamp, msg)

    # Print out statistics in tab-delimited format
    useful_stats = ["alerts", "oldest", "newest", "msg_avg"]
    header = [
        "Emergency_Alert", "Oldest_Msg",
        "Newest_Msg", "Avg_Msg_Length"
    ]

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
