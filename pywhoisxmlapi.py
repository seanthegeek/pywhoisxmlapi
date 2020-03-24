# -*- coding: utf-8 -*-

"""An unofficial client for WhoisXMLAPI"""

import os
import time
import logging
from datetime import datetime
from io import StringIO
from csv import DictWriter

from requests import session

"""Copyright 2018 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

__version__ = "2.1.5"

logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(message)s'
    )


def epoch_to_datetime(epoch_seconds):
    """
    Converts a UNIX epoch timestamp to a python DateTime object

    Args:
        epoch_seconds: A UNIX epoch value

    Returns:
        DateTime: A Python DateTime representation of the epoch value

    """
    return datetime.fromtimestamp(int(epoch_seconds))


def datetime_to_string(dt):
    """
    Converts a datetime object to a human readable string

    Args:
        dt (datetime): The datetime to convert

    Returns:

    str: formatted ``YYYY-MM-DD HH:MM:SS``
    """

    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')


class WhoisXMLAPIError(RuntimeError):
    """
    Raised when an error is returned by WhoisXMLAPI
    """
    pass


def flatten_whois(whois_record):
    """
    Flattens a whois record result
    Args:
        whois_record (dict): A WHOIS record

    Returns:
        dict: A flattened WHOIS result
    """
    flat_whois = dict()
    flat_whois["domainName"] = whois_record["domainName"]
    if "createdDate" in whois_record:
        flat_whois["createdDate"] = whois_record["createdDate"]
    if "updatedDate" in whois_record:
        flat_whois["updatedDate"] = whois_record["updatedDate"]
    if "expiresDate" in whois_record:
        flat_whois["expiresDate"] = whois_record["expiresDate"]
    if "registrant" in whois_record:
        for key in whois_record["registrant"]:
            flat_whois["registrant_{0}".format(key)] = whois_record["registrant"][key]
        del flat_whois["registrant_rawText"]
    if "administrativeContact" in whois_record:
        for key in whois_record["administrativeContact"]:
            flat_whois["administrativeContact_{0}".format(key)] = whois_record["administrativeContact"][key]
        del flat_whois["administrativeContact_rawText"]
    if "technicalContact" in whois_record:
        for key in whois_record["technicalContact"]:
            flat_whois["technicalContact_{0}".format(key)] = whois_record["technicalContact"][key]
        del flat_whois["technicalContact_rawText"]
    if "nameServers" in whois_record:
        flat_whois["nameServers"] = "|".join(whois_record["nameServers"]["hostNames"])
    if "status" in whois_record:
        flat_whois["status"] = whois_record["status"]
    if "registrarName" in whois_record:
        flat_whois["registrarName"] = whois_record["registrarName"]
    if "estimatedDomainAge" in whois_record:
        flat_whois["estimatedDomainAge"] = whois_record["estimatedDomainAge"]
    if "ips" in whois_record:
        flat_whois["ips"] = "|".join(whois_record["ips"])

    return flat_whois


def whois_to_csv(whois_results):
    """
    Returns CSV content given a list of WHOIS results

    Args:
        whois_results (list): A list of WHOIS results

    Returns:
        str: results as a CSV string

    """
    fields = ['domainName', 'createdDate', 'updatedDate', 'expiresDate',
              'registrant_name', 'registrant_organization',
              'registrant_street1', 'registrant_street2', 'registrant_city',
              'registrant_state', 'registrant_postalCode',
              'registrant_country', 'registrant_countryCode',
              'registrant_email', 'registrant_telephone', 'registrant_fax',
              'administrativeContact_name',
              'administrativeContact_organization',
              'administrativeContact_street1',
              'administrativeContact_street2',
              'administrativeContact_city',
              'administrativeContact_state',
              'administrativeContact_postalCode',
              'administrativeContact_country',
              'administrativeContact_countryCode',
              'administrativeContact_email',
              'administrativeContact_telephone',
              'administrativeContact_fax',
              'technicalContact_name',
              'technicalContact_organization',
              'technicalContact_street1', 'technicalContact_street2',
              'technicalContact_city',
              'technicalContact_state',
              'technicalContact_postalCode',
              'technicalContact_country',
              'technicalContact_countryCode',
              'technicalContact_email',
              'technicalContact_telephone',
              'technicalContact_fax',
              'nameServers',
              'status',
              'registrarName',
              'estimatedDomainAge',
              'ips']

    output_file = StringIO(newline="\n")
    writer = DictWriter(output_file, fieldnames=fields)
    writer.writeheader()
    whois_results = list(map(lambda x: flatten_whois(x), whois_results))
    writer.writerows(whois_results)
    output_file.seek(0)

    return output_file.read()


class WhoisXMLAPI(object):
    """
    A Python interface to WhoisXMLAPI

    .. note::

     ``api_key`` can be overridden by the
     ``WHOIS_KEY`` environment variable
    ..
    """
    _root = "https://www.whoisxmlapi.com"

    def __init__(self, api_key=None):
        """
        Configures the API client

        Args:
            api_key (str): WhoisXMLAPI API key; overridden by the
            ``WHOIS_KEY`` environment variable
        """
        if "WHOIS_KEY" in os.environ:
            api_key = os.environ["WHOIS_KEY"]
        if api_key is None:
            raise ValueError(
                "API key must provided as the api_key parameter, or the "
                "WHOIS_KEY environment variable")

        self._api_key = api_key
        self._session = session()
        self._session.headers.update(
            {"User-Agent": "pywhoisxmlapi/{0}".format(__version__)})

    def _request(self, endpoint, params=None, post=False, parse_json=True):
        """
        Makes an API request

        Args:
            endpoint: The API endpoint to request
            params: The parameters to pass
            post (bool): If True make a ``POST`` request instead of ``GET``

        Returns:
            dict: The API call results
        """
        if params is None:
            params = dict()
        params["outputFormat"] = "json"
        params["format"] = "JSON"
        params["apiKey"] = self._api_key

        if endpoint.lower().startswith("http"):
            endpoint = endpoint
        else:
            endpoint = "{0}/{1}".format(WhoisXMLAPI._root, endpoint)
        endpoint.lstrip("/")
        logging.debug("Params: {0}".format(params))
        if post:
            response = self._session.post(endpoint, json=params)
        else:
            response = self._session.get(endpoint, params=params)
        logging.debug("Response {0}".format(response.content))
        response.raise_for_status()
        if "callback" in params.keys() and params["callback"]:
            parse_json = False
        if parse_json:
            response = response.json()
            if "ErrorMessage" in response:
                error = response["ErrorMessage"]["msg"]
                raise WhoisXMLAPIError(error)
        else:
            response = response.text

        return response

    def get_account_balances(self):
        """
        Get all account balances

        Returns:
            Dict: Account balances
        """
        endpoint = "/accountServices.php"

        params = dict(servicetype="accountbalance", output_format="JSON")

        return self._request(endpoint, params)

    def set_account_balance_warnings(self, warn_threshold=10,
                                     warn_threshold_enabled=True,
                                     warn_empty_enabled=True):
        """
        Sets account settings for balance warnings

        Args:
            warn_threshold: The value at which account balance warnings are
                            sent
            warn_threshold_enabled (bool): Enable low balance warnings
            warn_empty_enabled (bool): Enable empty balance warnings

        Returns:
            dict: Acknowledgement

        """
        endpoint = "/accountServices.php"

        if warn_threshold_enabled:
            warn_empty_enabled = 1
        else:
            warn_threshold_enabled = 0
        if warn_empty_enabled:
            warn_empty_enabled = 1
        else:
            warn_empty_enabled = 0

        params = dict(servicetype="accountUpdate",
                      output_format="JSON",
                      warn_threshold=warn_threshold,
                      warn_threshold_enabled=warn_threshold_enabled,
                      warn_empty_enabled=warn_empty_enabled)

        return self._request(endpoint, params)

    def whois(self, domain_name, prefer_fresh=False, da=0, ip=True,
              check_proxy_data=True, thin_whois=False, callback=None,
              parse=False, registry_raw_text=None, registrar_raw_text=None):
        """
        Returns parsed WHOIS data

        Args:
            domain_name (str): A domain name or IP address
            prefer_fresh (bool): Get the latest WHOIS record even if it's
                                incomplete
            da (int): 0 - Do not check for domain amiability; 1 - quick check;
                      2  - slower, but most accurate
            ip (bool): Resolve IP addresses
            check_proxy_data (bool):  Check if registration matches known
                                      proxies
            thin_whois (bool):  Only return data on the registrant, not the
                                registrar
            callback (str): JSONP callback
            parse (bool): Parse the provided raw WHOIS data
            registry_raw_text (str): Optional raw WHOIS registration data to
                                     parse, rather than fetching it via the API
            registrar_raw_text (str): Optional raw WHOIS registration data to
                                     parse, rather than fetching it via the API

        Returns:
            dict: Parsed WHOIS data
            str: WHOIS data wrapped in JSONP if ``callback`` was specified
        """
        endpoint = "/whoisserver/WhoisService"

        params = dict(domainName=domain_name, da=da)
        if prefer_fresh:
            params["preferFresh"] = 1
        if da:
            params["da"] = 1
        if ip:
            params["ip"] = 1
        if check_proxy_data:
            params["checkProxyData"] = 1
        if thin_whois:
            params["thinWhois"] = 1
        if callback:
            params["callback"] = callback
        if parse:
            params["_parse"] = 1
        if registry_raw_text:
            params["registryRawText"] = registry_raw_text
        if registrar_raw_text:
            params["RegistrarRawText"] = registrar_raw_text

        response = self._request(endpoint, params)
        if type(response) == dict:
            response = response["WhoisRecord"]

        return response

    def bulk_whois(self, domains):
        """
        Retrieves WHOIS data for multiple domains, in bulk.

        Args:
            domains (list): A list of domains to get WHOIS records for

        Returns:
            dict: A dictionary with  keys:
                - ``structured`` - parsed data in a dictionary
                - ``csv``: results in CSV format
        """
        if type(domains) != list:
            raise ValueError("domains must be a list")

        endpoint = "/BulkWhoisLookup/bulkServices/bulkWhois"
        params = dict(domains=domains)
        response = self._request(endpoint, params, post=True)
        del params["domains"]
        params["requestId"] = response["requestId"]
        params["searchType"] = "all"
        params["maxRecords"] = len(domains)
        params["startIndex"] = 1

        endpoint = "/BulkWhoisLookup/bulkServices/getRecords"
        records_left = len(domains)
        while records_left > 0:
            time.sleep(15)
            response = self._request(endpoint, params, post=True)
            records_left = response["recordsLeft"]

        structured = response["whoisRecords"]

        for result in structured:
            result["domainFetchedTime"] = epoch_to_datetime(
                float(result["domainFetchedTime"]) / 1000)

        endpoint = "https://www.whoisxmlapi.com/BulkWhoisLookup/" \
                   "bulkServices/download"
        csv = ""
        time.sleep(15)
        response = self._session.post(endpoint, json=params).text
        for line in response.split("\n"):
            # remove blank lines
            if line != '':
                csv += line

        return dict(structured=structured, csv=csv)

    def reverse_whois(self, terms, exclude_terms=None,
                      search_type="current", mode="preview",
                      created_date_to=None, created_date_from=None,
                      updated_date_to=None, updated_date_from=None,
                      expired_date_to=None, expired_date_from=None):
        """
        Conducts a reverse WHOIS search

        Args:
            terms (list): Terms to search for
            exclude_terms (list): Terms to filter by
            search_type (str): ``current`` or ``historic``
            mode (str): ``preview`` or ``purchase``
            created_date_to (str): Search through domains created before the
                                   given date (``YYYY-MM-DD`` format)
            created_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            updated_date_to (str): Search through domains created before the
                                   given date (``YYYY-MM-DD`` format)
            updated_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            expired_date_to (str): Search through domains created before the
                                    given date (``YYYY-MM-DD`` format)
            expired_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)

        Returns:
            dict: A dictionary of preview data
            list: A list of results
        """
        endpoint = "https://reverse-whois-api.whoisxmlapi.com/api/v2"
        params = dict(mode=mode.lower())
        if created_date_to:
            params["createdDateTo"] = created_date_to
        if created_date_from:
            params["createdDateFrom"] = created_date_from
        if updated_date_from:
            params["updatedDateFrom"] = updated_date_from
        if updated_date_to:
            params["updatedDateTo"] = updated_date_to
        if expired_date_from:
            params["expiredDateFrom"] = expired_date_from
        if expired_date_to:
            params["expiredDateTo"] = expired_date_to

        if exclude_terms is None:
            exclude_terms = []
        search_type = search_type.lower()
        mode = mode.lower()
        if len(terms) > 4:
            raise ValueError("Number of terms cannot be greater than 4")
        if len(exclude_terms) > 4:
            raise ValueError(
                "Number of excluded terms cannot be greater than 4")
        if search_type not in ["current", "historic"]:
            raise ValueError("Search type must be current or historic")
        if mode not in ["preview", "purchase"]:
            raise ValueError("mode must be preview or purchase")

        params["searchType"] = search_type
        params["basicSearchTerms"] = dict(include=terms,
                                          exclude=exclude_terms)

        results = self._request(endpoint, params, post=True)
        drs_credit_cost = 1

        if mode == "preview":
            results["DRSCreditCost"] = drs_credit_cost
        elif "domainslist" in results:
            results = results["domainsList"]

        return results

    def whois_history(self, domain,
                      since_date=None,
                      created_date_from=None,
                      created_date_to=None,
                      updated_date_from=None,
                      updated_date_to=None,
                      expired_date_from=None,
                      expired_date_to=None,
                      mode="preview"):
        """
        Returns WHOIS history for a given domains

        Args:
            domain (str): The domain
            since_date (str): Only return domains created or deleted since
                              this date, (``YYYY-MM-DD`` format)
            created_date_to (str): Search through domains created before the
                                   given date (``YYYY-MM-DD`` format)
            created_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            updated_date_to (str): Search through domains created before the
                                   given date (``YYYY-MM-DD`` format)
            updated_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            expired_date_to (str): Search through domains created before the
                                    given date (``YYYY-MM-DD`` format)
            expired_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            mode (str): ``preview`` or ``purchase``

        Returns:
            dict: A dictionary of preview data
            list: A list of parsed historic WHOIS records, starting with the
            current record

        """

        endpoint = "https://whois-history-api.whoisxmlapi.com/api/v1"
        mode = mode.lower()
        params = dict(domainName=domain, mode=mode)
        if since_date:
            params["sinceDate"] = since_date
        if created_date_from:
            params["createdDateFrom"] = created_date_from
        if created_date_to:
            params["createdDateTo"] = created_date_to
        if updated_date_from:
            params["updatedDateFrom"] = updated_date_from
        if updated_date_to:
            params["updatedDateTo"] = updated_date_to
        if expired_date_from:
            params["expiredDateFrom"] = expired_date_from
        if expired_date_to:
            params["expiredDateTo"] = expired_date_to

        results = self._request(endpoint, params, post=True)
        drs_credit_cost = 50

        if mode == "preview":
            results["DRSCreditCost"] = drs_credit_cost
        elif "records" in results:
            results = results["records"]

        return results

    def brand_alert(self,
                    terms,
                    exclude_terms=None,
                    since_date=None,
                    created_date_from=None,
                    created_date_to=None,
                    updated_date_from=None,
                    updated_date_to=None,
                    expired_date_from=None,
                    expired_date_to=None,
                    mode="preview"):
        """
        Lists newly created or deleted domains based on brand terms

        Args:
            terms (list): Brand terms to include in the search (max 4)
            exclude_terms (list): Terms to exclude (max 4)
            since_date (str): Only return domains created or deleted since
                              this date, (``YYYY-MM-DD`` format)
            created_date_to (str): Search through domains created before the
                                   given date (``YYYY-MM-DD`` format)
            created_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            updated_date_to (str): Search through domains created before the
                                   given date (``YYYY-MM-DD`` format)
            updated_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            expired_date_to (str): Search through domains created before the
                                    given date (``YYYY-MM-DD`` format)
            expired_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            mode (str): ``preview`` or ``purchase``

        Returns:
            dict: A dictionary of preview data
            list: A list of dictionaries containing the ``domainName``,
            and its ``action`` (i.e. ``added`` or ``dropped``)
        """
        endpoint = "https://brand-alert-api.whoisxmlapi.com/api/v2"
        params = dict(apiKey=self._api_key, includeSearchTerms=terms,
                      mode=mode)
        if exclude_terms is None:
            exclude_terms = []
        if len(terms) > 4:
            raise ValueError("Number of terms cannot be greater than 4")
        if len(exclude_terms) > 4:
            raise ValueError(
                "Number of excluded terms cannot be greater than 4")
        mode = mode.lower()
        if mode not in ["preview", "purchase"]:
            raise ValueError("mode must be preview or purchase")
        params["excludeTerms"] = exclude_terms
        if since_date:
            params["sinceDate"] = since_date
        if created_date_from:
            params["createdDateFrom"] = created_date_from
        if created_date_to:
            params["createdDateTo"] = created_date_to
        if updated_date_from:
            params["updatedDateFrom"] = updated_date_from
        if updated_date_to:
            params["updatedDateTo"] = updated_date_to
        if expired_date_from:
            params["expiredDateFrom"] = expired_date_from
        if expired_date_to:
            params["expiredDateTo"] = expired_date_to

        results = self._request(endpoint, params, post=True)

        drs_credit_cost = 10

        if mode == "preview":
            results["DRSCreditCost"] = drs_credit_cost
        elif "domainslist" in results:
            results = results["domainsList"]

        return results

    def registrant_alert(self, terms, exclude_terms=None,
                         since_date=None,
                         created_date_from=None,
                         created_date_to=None,
                         updated_date_from=None,
                         updated_date_to=None,
                         expired_date_from=None,
                         expired_date_to=None,
                         mode="preview"):
        """
        Lists newly created or deleted domains based on registrant

        Args:
            terms (list): Brand terms to include in the search (max 4)
            exclude_terms (list): Terms to exclude (max 4)
            since_date (str): Only return domains created or deleted since
                              this date, (``YYYY-MM-DD`` format)
            created_date_to (str): Search through domains created before the
                                   given date (``YYYY-MM-DD`` format)
            created_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            updated_date_to (str): Search through domains created before the
                                   given date (``YYYY-MM-DD`` format)
            updated_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            expired_date_to (str): Search through domains created before the
                                    given date (``YYYY-MM-DD`` format)
            expired_date_from (str): Search through domains created after the
                                     given date (``YYYY-MM-DD`` format)
            mode (str): ``preview`` or ``purchase``

        Returns:
            dict: A dictionary of preview data
            list: A list of dictionaries containing the ``domainName``,
            and its ``action`` (i.e. ``added`` or ``dropped``)
        """
        endpoint = "https://registrant-alert-api.whoisxmlapi.com/api/v2"
        if exclude_terms is None:
            exclude_terms = []
        if len(terms) > 4:
            raise ValueError("Number of terms cannot be greater than 4")
        if len(exclude_terms) > 4:
            raise ValueError(
                "Number of excluded terms cannot be greater than 4")
        mode = mode.lower()
        params = dict(mode=mode)
        if mode not in ["preview", "purchase"]:
            raise ValueError("mode must be preview or purchase")
        params["basicSearchTerms"] = dict(include=terms,
                                          exclude=exclude_terms)
        if since_date:
            params["sinceDate"] = since_date
        if created_date_from:
            params["createdDateFrom"] = created_date_from
        if created_date_to:
            params["createdDateTo"] = created_date_to
        if updated_date_from:
            params["updatedDateFrom"] = updated_date_from
        if updated_date_to:
            params["updatedDateTo"] = updated_date_to
        if expired_date_from:
            params["expiredDateFrom"] = expired_date_from
        if expired_date_to:
            params["expiredDateTo"] = expired_date_to

        results = self._request(endpoint, params, post=True)

        drs_credit_cost = 10

        if mode == "preview":
            results["DRSCreditCost"] = drs_credit_cost
        elif "domainslist" in results:
            results = results["domainsList"]

        return results

    def dns_lookup(self, domain_name, record_type="_all", callback=None):
        """
        Preforms a DNS lookup

        Args:
            domain_name (str): The domain name or sub-domain to lookup
            record_type (str): The DNS resource record type to query for, or
                              ``_all`` for all record types
            callback (str): A JSONP callback

        Returns:
            dict: Lookup results
            str: lookup results data wrapped in JSONP if ``callback`` was
            specified

        """
        endpoint = "/whoisserver/DNSService"
        params = dict(domainName=domain_name, recordType=record_type,
                      callback=callback)

        return self._request(endpoint, params)

    def domain_availability(self, domain_name, mode="DNS_ONLY"):
        """
        Check domain name availability

        Args:
            domain_name (str): The domain name to check
            mode (str):  ``DNS_ONLY`` or ``DNS_AND_WHOIS``

        Returns:
            bool: The availability of the domain name
        """
        endpoint = "/whoisserver/WhoisService"
        params = dict(cmd="GET_DN_AVAILABILITY", getMode=mode.upper(),
                      domainName=domain_name)

        if mode.upper() not in ["DNS_ONLY", "DNS_AND_WHOIS"]:
            raise ValueError("Mode must be DNS_ONLY or DNS_AND_WHOIS")

        results = self._request(endpoint, params)

        return results["domainAvailability"] == "AVAILABLE"

    def verify_email(self, email_address):
        """
        Returns metadata about an email address

        Args:
            email_address (str): The email address to verify

        Returns:
            dict: email verification results
        """

        endpoint = "https://emailverification.whoisxmlapi.com/api/v1"
        params = dict(emailAddress=email_address)
        response = self._request(endpoint, params=params)

        return response

    def reverse_mx(self, mx):
        """
        Performs a reverse MX query

        Args:
            mx (str): A MX hostname

        Returns:
            list: A list of results
        """
        def transform(result):
            result["first_seen"] = epoch_to_datetime(
                result["first_seen"])
            result["last_visit"] = epoch_to_datetime(
                result["last_visit"])
            return result
        endpoint = "https://reverse-mx-api.whoisxmlapi.com/api/v1"
        results = []
        params = dict(mx=mx)
        response = self._request(endpoint, params=params)

        _results = response["result"]
        results += _results
        while len(_results) >= 300:
            params["from"] = results[-1]["name"]
            response = self._request(endpoint, params=params)

            _results = response["result"]

            results += _results

        results = list(map(transform, results))

        return results

    def reverse_ns(self, ns):
        """
        Performs a reverse MX query

        Args:
            ns (str): A nameserver hostname

        Returns:
            list: A list of results
        """
        def transform(result):
            result["first_seen"] = epoch_to_datetime(
                result["first_seen"])
            result["last_visit"] = epoch_to_datetime(
                result["last_visit"])
            return result
        endpoint = "https://reverse-ns-api.whoisxmlapi.com/api/v1"
        results = []
        params = dict(ns=ns)
        response = self._request(endpoint, params=params)

        _results = response["result"]
        results += _results
        while len(_results) >= 300:
            params["from"] = results[-1]["name"]
            response = self._request(endpoint, params=params)

            _results = response["result"]

            results += _results

        results = list(map(transform, results))

        return results

    def reverse_ip(self, ip):
        """
        Performs a reverse IP/DNS query

        Args:
            ip (str): An IPv4 or IPv6 address

        Returns:
            list: A list of results
        """
        def transform(result):
            result["first_seen"] = epoch_to_datetime(
                result["first_seen"])
            result["last_visit"] = epoch_to_datetime(
                result["last_visit"])
            return result
        endpoint = "https://reverse-ip-api.whoisxmlapi.com/api/v1"
        results = []
        params = dict(ip=ip)
        response = self._request(endpoint, params=params)

        _results = response["result"]
        results += _results
        while len(_results) >= 300:
            params["from"] = results[-1]["name"]
            response = self._request(endpoint, params=params)

            _results = response["result"]

            results += _results

        results = list(map(transform, results))

        return results

    def domain_reputation(self, domain, mode="fast"):
        """
        Checks a domain's reputation

        Args:
            domain (str): The domain to check
            mode (str):  ``fast`` - some heavy tests and data collectors will
                          be disabled (1 credit) or
                          ``full`` - all the data and the tests will be
                          processed (3 credits)

        Returns:
            float: A number ranging from 0.0 being most malicious to 100.0
            being most safe
        """

        endpoint = "https://domain-reputation-api.whoisxmlapi.com/api/v1"

        mode = mode.lower()
        if mode not in ["fast", "full"]:
            raise ValueError("Mode must be fast or full")

        params = dict(domainName=domain, mode=mode)

        return self._request(endpoint, params)["reputationScore"]

    def ip_geolocation(self, ip):
        """
        Returns geolocation information about an IP address

        Args:
            ip (str): An IPv4  or IPv6 address

        Returns:
            dict: Geolocation information

        """
        endpoint = "https://geoipify.whoisxmlapi.com/api/v1"
        params = dict(ipAddress=ip)

        return self._request(endpoint, params)["location"]

    def netblocks(self, ip=None, mask=None, org=None, limit=10000):
        """
        Returns netblock information about a given IP or organisation

        .. note::
            You must specify ``ip`` or ``org``, but not both

        Args:
            ip (str): An IP address
            mask (int): A subnet bask integer
            org (list): A list os organisation strings
            limit (int): Max number of records to return (1-10000)

        Returns:
            list: A list of netblocks
        """
        if (not ip and not org) or (ip and org):
            raise ValueError("ip or org must be specified")
        params = dict(ip=ip, mask=mask, org=org, limit=limit)
        endpoint = "https://ip-netblocks-api.whoisxmlapi.com/api/v1"
        return self._request(endpoint, params)
