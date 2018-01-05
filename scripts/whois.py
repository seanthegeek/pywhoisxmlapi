#!/usr/bin/env python3

# -*- coding: utf-8 -*-

"""
whois.py - A CLI for WhoisXMLAPI

Usage:
  whois.py balances
  whois.py [-d | --debug] [--verbose] <domain> [--output=<output_file>]
  whois.py bulk [-d | --debug] (<domain>... | --input <input_file>) [--csv] [--output=<output_file>]
  whois.py reverse [-d | --debug] [-y | --yes] [--historic] <term>... [--exclude <exclude_term>... --since=<since> --days-back=<days_back> --output=<output_file>]
  whois.py brand [-d | --debug] <term>... [--exclude <exclude_term>... --since=<since> --days-back=<days_back>  --output=<output_file>]
  whois.py -h | --help
  whois.py --version

Options:
  -h --help                    Show this screen
  -d --debug                   Enable debug output
  -i --input=<input_file>      A path to a file containing one domain per line
  -o --output=<output_file>    Output to a file with this file name; the file extension is added automatically
  -y --yes                     Confirm action without additional prompts
  --since=<since>              Only include results since this date YYY-MM0DD format
  --days-back=<days_back>      Search back through this number of days (12 maximum)
  --historic                   Include historic results
  --csv                        Output in CSV format instead of JSON
  --verbose                    Return verbose data
  --version                    Show version
"""

from __future__ import print_function, unicode_literals

import logging
import json

from docopt import docopt

from pywhoisxmlapi import __version__, WhoisXMLAPI


"""Copyright 2017 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""


if __name__ == '__main__':
    logger = logging.getLogger()
    arguments = docopt(__doc__, version=__version__)
    if arguments["--debug"]:
        logger.setLevel(logging.DEBUG)
    logging.debug(arguments)
    api = WhoisXMLAPI()
    results = ""
    if arguments["bulk"]:
        if arguments["--input"]:
            with open(arguments["--input"]) as input_file:
                domains = list(map(lambda line: line.rstrip(), input_file.readlines()))
                results = api.bulk_whois(domains)
                if arguments["--csv"]:
                    results = results["csv"]
                else:
                    results = results["structured"]
    elif arguments["reverse"]:
        search_type = "current"
        mode = "preview"
        if arguments["--historic"]:
            search_type = "historic"
        if arguments["--yes"]:
            mode = "purchase"
        results = api.reverse_whois(arguments["<term>"], exclude_terms=arguments["<exclude_term>"],
                                    search_type=search_type,
                                    mode=mode)
    elif arguments["brand"]:
        results = api.brand_alert(arguments["<term>"], exclude_terms=arguments["<exclude_term>"],
                                  since_date=arguments["--since"], days_back=arguments["--days-back"])
    elif arguments["balances"]:
        results = api.get_account_balances()
    else:
        thin_whois = True
        if arguments["--verbose"]:
            thin_whois = False
        results = api.whois(arguments["<domain>"][0], thin_whois=thin_whois)
    if arguments["--output"]:
        if arguments["--csv"]:
            filename = "{0}.csv".format(arguments["--output"])
        else:
            filename = "{0}.json".format(arguments["--output"])
        with open(filename, "wb") as output_file:
            if arguments["--csv"]:
                output_file.write(results.encode("utf-8"))
            else:
                output_file.write(json.dumps(results, indent=2, ensure_ascii=False).encode("utf-8"))
    else:
        if arguments["--csv"]:
            print(results)
        else:
            print(json.dumps(results, indent=2, ensure_ascii=False))
