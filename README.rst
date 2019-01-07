=============
pywhoisxmlapi
=============

|Build Status|

An unofficial client for WhoisXMLAPI

Features
========

- Python 2 and 3 support
- ``whois.py`` CLI utility for common queries
  with JSON and CSV output
- Pythonic access to every WhoisXMLAPI service

CLI help
========

::

    whois.py - A CLI for WhoisXMLAPI

    Usage:
      whois.py balances
      whois.py [-d | --debug] [--verbose] <domain> [-o | --output=<output_file>]
      whois.py bulk [-d | --debug] (<domain>... | [-i |--input <input_file>]) [--csv] [ -o | --output=<output_file>]
      whois.py reverse [-d | --debug] [-p | --purchase] [--historic] <term>... [--exclude <exclude_term>... --since=<since> --days-back=<days_back> [-o | --output=<output_file>]]
      whois.py history [-d | --debug] [-p | --purchase] <domain> [--since=<since>  [-o | --output=<output_file>]]
      whois.py brand [-d | --debug] [-p | --purchase] <term>... [--exclude <exclude_term>... --since=<since> [--csv]  [-o | --output=<output_file>]]
      whois.py registrant [-d | --debug] [-p | --purchase] <term>... [--exclude <exclude_term>... --since=<since> [--csv] [-o |--output=<output_file>]]
      whois.py reverse-ip [-d | --debug] [--verbose] <ip> [--csv] [-o | --output=<output_file>]
      whois.py reverse-mx [-d | --debug] [--verbose] <mx> [--csv] [-o | --output=<output_file>]
      whois.py reverse-ns [-d | --debug] [--verbose] <ns> [--csv] [-o | --output=<output_file>]
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
      --csv                        Output in CSV format
      --verbose                    Return verbose data
      --version                    Show version

.. note::

    The ``whois.py`` CLI utility expects the API key to be stored in an
    environment variable called ``WHOIS_KEY``.

.. |Build Status| image:: https://travis-ci.org/seanthegeek/pywhoisxmlapi.svg?branch=master
   :target: https://travis-ci.org/seanthegeek/pywhoisxmlapi
