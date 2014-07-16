#!/usr/bin/env python

import argparse
import collections
import json
import os
import re
import urllib2


DEFAULT_FILE_PATH = os.path.join(os.path.dirname(__file__), 'samples/apache/access_log')
NAMED_GROUPS = ('client', 'timestamp', 'method', 'uri', 'version', 'response_code', 'size', 'args', 'protocol')

# TODO: Will not match lines using HTTP basic auth
apache_access_regex = re.compile(r'^(?P<client>[\d\.\w-]+)'
                                 r' - - '
                                 r'\[(?P<timestamp>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] '
                                 r'"((?P<method>\w{3,}) '
                                 r'(?P<uri>/[\w\d\-\./]*|\*)'
                                 r'\??(?P<args>[^\s]*) '
                                 r'(?P<protocol>\w+)/(?P<version>[0,1]\.\d)|-)" '
                                 r'(?P<response_code>\d{3}) '
                                 r'(?P<size>\d+|-)$')


def count_unique(lines, key):
  sorted_lines = sorted([line[key] for line in lines])
  return collections.Counter(sorted_lines)


def parse_line(line):
  """Parses out the components of the log line."""

  matches = apache_access_regex.match(line)
  parsed = dict([(name, matches.group(name)) for name in NAMED_GROUPS])

  # Special case handling for things that should be lists
  args = parsed['args']
  if args:
    parsed['args'] = urllib2.urlparse.parse_qs(args)
  return parsed


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Process Apache2 logs')
  parser.add_argument('file', nargs='?', default=DEFAULT_FILE_PATH,
                      help='Path to the apache log file. Defaults to "{}"'.format(DEFAULT_FILE_PATH))
  parser.add_argument('-o', '--output',
                      help='Export the parsed logs as JSON to the specified file')
  parser.add_argument('-c', '--count', choices=NAMED_GROUPS,
                      help='Print a count of the specified value')
  parser.add_argument('-n', type=int, default=10, dest='number',
                      help='When used with --count, the number of entries to print')
  args = parser.parse_args()

  parsed_lines = []
  with open(args.file, 'r') as fd:
    while True:
      try:
        parsed_lines.append(parse_line(fd.next()))
      except StopIteration:
        break

  # Save the parsed logs if requested
  if args.output:
    with open(args.output, 'w') as fd:
      json.dump(parsed_lines, fd)

  if args.count:
    print count_unique(parsed_lines, args.count).most_common(args.number)
