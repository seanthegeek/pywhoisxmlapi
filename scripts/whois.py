#!/usr/bin/env python3

# -*- coding: utf-8 -*-

"""
whois.py - A CLI for WhoisXMLAPI

Usage:
  whois.py balances
  whois.py [-d | --debug] [--verbose] <domain> [-o | --output=<output_file>]
  whois.py bulk [-d | --debug] (<domain>... | [-i |--input <input_file>]) [--csv] [ -o | --output=<output_file>]
  whois.py reverse [-d | --debug] [-p | --purchase] [--historic] <term>... [--exclude <exclude_term>... --since=<since> --days-back=<days_back> [-o | --output=<output_file>]]
  whois.py history [-d | --debug] [-p | --purchase] <domain> [--since=<since>  [-o | --output=<output_file>]]
  whois.py brand [-d | --debug] [-p | --purchase] <term>... [--exclude <exclude_term>... --since=<since>  [-o | --output=<output_file>]]
  whois.py registrant [-d | --debug] [-p | --purchase] <term>... [--exclude <exclude_term>... --since=<since>  [-o |--output=<output_file>]]
  whois.py mx [-d | --debug] [--verbose] <mx> [-o | --output=<output_file>]
  whois.py ns [-d | --debug] [--verbose] <ns> [-o | --output=<output_file>]
  whois.py -h | --help
  whois.py --version

Options:
  -h --help                    Show this screen
  -d --debug                   Enable debug output
  -i --input=<input_file>      A path to a file containing one domain per line
  -o --output=<output_file>    Output to a file with this file name; the file extension is added automatically
  -p --purchase                Purchase the results with a Domain Research Suite (DRS) credit
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


def _main():
    logger = logging.getLogger()
    arguments = docopt(__doc__, version=__version__)
    if arguments["--debug"]:
        logger.setLevel(logging.DEBUG)
    logging.debug(arguments)
    api = WhoisXMLAPI()
    results = ""
    search_type = "current"
    mode = "preview"
    if arguments["--historic"]:
        search_type = "historic"
    if arguments["--purchase"]:
        mode = "purchase"
    if arguments["bulk"]:
        if arguments["--input"]:
            with open(arguments["--input"]) as input_file:
                domains = list(map(lambda line: line.rstrip(),
                                   input_file.readlines()))
                results = api.bulk_whois(domains)
                if arguments["--csv"]:
                    results = results["csv"]
                else:
                    results = results["structured"]
                    results = dict(results=results)
    elif arguments["reverse"]:
        results = api.reverse_whois(arguments["<term>"],
                                    exclude_terms=arguments["<exclude_term>"],
                                    search_type=search_type,
                                    mode=mode)
    elif arguments["history"]:
        results = api.whois_history(arguments["<domain>"][0],
                                    since_date=arguments["--since"],
                                    mode=mode)
        if arguments["--purchase"]:
            results = dict(results=results)

    elif arguments["brand"]:
        results = api.brand_alert(arguments["<term>"],
                                  exclude_terms=arguments["<exclude_term>"],
                                  since_date=arguments["--since"],
                                  mode=mode)
        if arguments["--purchase"]:
            results = dict(results=results)
    elif arguments["registrant"]:
        results = api.registrant_alert(
            arguments["<term>"],
            exclude_terms=arguments["<exclude_term>"],
            since_date=arguments["--since"], mode=mode)
        if arguments["--purchase"]:
            results = dict(results=results)
    elif arguments["mx"]:
        results = api.reverse_mx(arguments["<mx>"][0])
    elif arguments["ns"]:
        results = api.reverse_mx(arguments["<ns>"][0])
    elif arguments["balances"]:
        results = api.get_account_balances()
    else:
        # The default action is a WHOIS lookup
        thin_whois = True
        if arguments["--verbose"]:
            thin_whois = False
        results = api.whois(arguments["<domain>"][0], thin_whois=thin_whois)

    # Format output
    if type(results) is dict:
        results = json.dumps(results, indent=2,
                             ensure_ascii=False)
    elif type(results) is list:
        results = "\n".join(results)
    if arguments["--output"]:
        filename = arguments["--output"]
        with open(filename, "wb") as output_file:
            output_file.write(results.encode("utf-8"))
    else:
        print(results)


if __name__ == '__main__':
    try:
        _main()
    except Exception as e:
        logging.error(e.__str__())
        exit(1)
