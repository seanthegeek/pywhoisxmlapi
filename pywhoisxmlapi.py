# -*- coding: utf-8 -*-

"""An unofficial client for WhoisXMLAPI"""

import os
import json
import base64
import hashlib
import hmac
import time
import datetime
import logging

from requests import session
from requests.utils import quote


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

__version__ = "1.0.0"

logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(message)s'
    )


def epoch_to_datetime(epoch):
    """
    Converts a UNIX epoch timestamp to a python DateTime object
    
    Args:
        epoch: A UNIX epoch value

    Returns:
        DateTime: A Python DateTime representation of the epoch value

    """
    epoch_seconds = int(epoch) / 1000.0
    return datetime.datetime.fromtimestamp(epoch_seconds).strftime('%Y-%m-%d %H:%M:%S.%f')


class WhoisXMLAPIError(RuntimeError):
    """
    Raised when an error is returned by WhoisXMLAPI
    """
    pass


class WhoisXMLAPI(object):
    """
    A Python interface to WhoisXMLAPI
    """
    _root = "https://www.whoisxmlapi.com"

    def __init__(self, username=None, password=None, api_key=None, secret=None, email_key=None):
        """
        Configures the API client
        
        Args:
            username (str): WhoisXMLAPI username; overridden by the ``WHOIS_USERNAME`` environment variable 
            password (str): WhoisXMLAPI password; overridden by the ``WHOIS_PASSWORD`` environment variable 
            api_key (str): WhoisXMLAPI key; overridden by the ``WHOIS_KEY`` environment variable 
            secret (str): WhoisXMLAPI key secret; overridden by the ``WHOIS_SECRET`` environment variable
            email_key (str): API key for the WhoisXMLAPI email verification API;; overridden by the
            ``WHOIS_EMAIL_KEY`` environment variable 
            
        Warning:
            Currently, only a few WHOISXMLAPI actions support API keys.
            For now, you must yse username/password authentication instead to use the full API.  
        """
        if "WHOIS_USERNAME" in os.environ:
            username = os.environ["WHOIS_USERNAME"]
        if "WHOIS_PASSWORD" in os.environ:
            password = os.environ["WHOIS_PASSWORD"]
        if "WHOIS_KEY" in os.environ:
            api_key = os.environ["WHOIS_KEY"]
        if "WHOIS_SECRET" in os.environ:
            secret = os.environ["WHOIS_SECRET"]
        if "WHOIS_EMAIL_KEY" in os.environ:
            email_key = os.environ["WHOIS_EMAIL_KEY"]

        self._username = username
        self._password = password
        self._api_key = api_key
        self._secret = secret
        self._email_key = email_key
        self._session = session()
        self._session.headers.update({"User-Agent": "pywhoisxmlapi/{0}".format(__version__)})

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
        api_key_missing_secret = self._api_key and self._secret is None
        no_password_or_api_key = self._api_key is None and self._password is None

        if self._username is None or api_key_missing_secret or no_password_or_api_key:
            raise ValueError("You must provide either an API key and secret, or a username and password")

        if params is None:
            params = dict()
        params["outputFormat"] = "json"
        if self._username and self._api_key is None:
            params["username"] = self._username
        if self._password:
            params["password"] = self._password
        if self._api_key:
            _time = int(round(time.time() * 1000))
            req = base64.b64encode(json.dumps(dict(t=str(_time), u=self._username)).encode("ascii"))
            msg = "{0}{1}{2}".format(self._username, str(_time), self._api_key).encode("ascii")
            digest = hmac.new(self._secret.encode("ascii"), msg, hashlib.md5).hexdigest()
            params["requestObject"] = req
            params["digest"] = digest

        url = "{0}/{1}".format(WhoisXMLAPI._root, endpoint.lstrip("/"))
        logging.debug("Params: {0}".format(params))
        if post:
            response = self._session.post(url, json=params)
        else:
            response = self._session.get(url, params=params)
        logging.debug("Response {0}".format(response.content))
        response.raise_for_status()
        redacted_url = response.url
        if "callback" in params.keys() and params["callback"]:
            parse_json = False
        if self._username:
            redacted_url = redacted_url.replace(quote(self._username.encode("utf-8")), "REDACTED")
        if self._password:
            redacted_url = redacted_url.replace(quote(self._password.encode("utf-8")), "REDACTED")
        if parse_json:
            response = response.json()
            if "ErrorMessage" in response:
                error = response["ErrorMessage"]
                raise WhoisXMLAPIError("{0}\nAttempted query: {1}".format(error["msg"], redacted_url))
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

    def set_account_balance_warnings(self, warn_threshold=10, warn_threshold_enabled=True, warn_empty_enabled=True):
        """
        Sets account settings for balance warnings
        
        Args:
            warn_threshold: The value at which account balance warnings are sent
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

    def whois(self, domain_name, da=0, ip=True, check_proxy_data=True, thin_whois=False, callback=None,
              parse=False, registry_raw_text=None, registrar_raw_text=None):
        """
        Returns parsed WHOIS data
        
        Args:
            domain_name (str): A domain name or IP address
            da (int): 0 - Do not check for domain amiability; 1 - quick check; 2   
            ip (bool): Resolve IP addresses
            check_proxy_data (bool):  Check if registration matches known proxies
            thin_whois (bool):  Only return data on the registrant, not the registrar                                                                                                                                                
            callback (str): JSONP callback 
            parse (bool): Parse the provided raw WHOIS data
            registry_raw_text (str): Optional raw WHOIS registration data to parse, rather than fetching it via the API 
            registrar_raw_text (str: Optional raw WHOIS registration data to parse, rather than fetching it via the API

        Returns:
            dict: Parsed WHOIS data
            str: WHOIS data wrapped in JSONP if ``callback`` was specified
        """
        endpoint = "/whoisserver/WhoisService"

        params = dict(domainName=domain_name, da=da)
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
            dict: keys: ``structured`` - parsed data in a dictionary, ``csv``: results in CSV format
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
            result["domainFetchedTime"] = epoch_to_datetime(result["domainFetchedTime"])

        url = "https://www.whoisxmlapi.com/BulkWhoisLookup/bulkServices/download"
        csv = ""
        time.sleep(15)
        response = self._session.post(url, json=params).text
        for line in response.split("\n"):
            # remove blank lines
            if line != '':
                csv += line

        return dict(structured=structured, csv=csv)

    def reverse_whois(self, terms, exclude_terms=None, search_type="current", mode="preview", since_date=None):
        """
        Conducts a reverse WHOIS search
        
        Args:
            terms (list): Terms to search for
            exclude_terms (list): Terms to filter by 
            search_type (str): current or historic 
            mode (str): preview or purchase
            since_date (str): Only return results for domains created/discovered after this date (``YYYY-MM-DD`` format)

        Returns:
            dict: A dictionary of preview data
            list: A list of results
        """
        endpoint = "/reverse-whois-api/search.php"
        params = dict(search_type=search_type.lower(), mode=mode.lower(), since_date=since_date)
        results = dict()

        if exclude_terms is None:
            exclude_terms = []
        if len(terms) > 4:
            raise ValueError("Number of terms cannot be greater than 4")
        if len(exclude_terms) > 4:
            raise ValueError("Number of excluded terms cannot be greater than 4")
        if search_type.lower() not in ["current", "historic"]:
            raise ValueError("Search type must be current or historic")
        if mode.lower() not in ["preview", "purchase"]:
            raise ValueError("mode must be preview or purchase")
        for i in range(len(terms)):
            param_name = "term{0}".format(i + 1)
            params[param_name] = terms[i]
        for i in range(len(exclude_terms)):
            param_name = "exclude_term{0}".format(i + 1)
            params[param_name] = terms[i]

        balance = self.get_account_balances()["reverse_whois_balance"]
        if balance is None:
            balance = 0

        response = self._request(endpoint, params)
        number_of_domains = response["stats"]["total_count"]
        credit_cost = number_of_domains / 10000
        if number_of_domains % 10000 != 0:
            credit_cost += 1

        results["number_of_domains"] = number_of_domains
        results["credit_cost"] = int(credit_cost)
        results["credit_balance"] = balance
        if "domains" in response:
            results["domains"] = response["domains"]

        return results

    def brand_alert(self, terms, exclude_terms=None, since_date=None, days_back=None):
        """
        Lists newly created or deleted domains based on brand terms
        
        Args:
            terms (list): Brand terms to include in the search
            exclude_terms (list): Terms to exclude 
            since_date (str): Only return domains created or deleted since this date, in YYYY-MM-DD format 
            days_back (int): The number of days back to search (12 maximum) 

        Returns:
            list: A list of dictionaries containing the domain, and its status (i.e. new or deleted)
        """
        endpoint = "/brand-alert-api/search.php"
        params = dict(since_date=since_date, days_back=days_back)
        if exclude_terms is None:
            exclude_terms = []
        if len(terms) > 4:
            raise ValueError("Number of terms cannot be greater than 4")
        if len(exclude_terms) > 4:
            raise ValueError("Number of excluded terms cannot be greater than 4")
        if days_back and days_back > 12:
            raise ValueError("days_back cannot be greater than 12")
        for i in range(len(terms)):
            param_name = "term{0}".format(i + 1)
            params[param_name] = terms[i]
        for i in range(len(exclude_terms)):
            param_name = "exclude_term{0}".format(i + 1)
            params[param_name] = terms[i]

        return self._request(endpoint, params)["alerts"]

    def registrant_alert(self, terms, exclude_terms=None, since_date=None, days_back=None):
        """
        Lists newly created or deleted domains based on registrant terms

        Args:
            terms (list): Registrant terms to include in the search
            exclude_terms (list): Terms to exclude 
            since_date (str): Only return domains created or deleted since this date, in YYYY-MM-DD format 
            days_back (int): The number of days back to search (12 maximum) 

        Returns:
            list: A list of dictionaries containing the domain, and its status (i.e. new or deleted)
        """
        endpoint = "/registrant-alert-api/search.php"
        params = dict(since_date=since_date, days_back=days_back)
        if exclude_terms is None:
            exclude_terms = []
        if len(terms) > 4:
            raise ValueError("Number of terms cannot be greater than 4")
        if len(exclude_terms) > 4:
            raise ValueError("Number of excluded terms cannot be greater than 4")
        if days_back and days_back > 12:
            raise ValueError("days_back cannot be greater than 12")
        for i in range(len(terms)):
            param_name = "term{0}".format(i + 1)
            params[param_name] = terms[i]
        for i in range(len(exclude_terms)):
            param_name = "exclude_term{0}".format(i + 1)
            params[param_name] = terms[i]

        return self._request(endpoint, params)["alerts"]

    def dns_lookup(self, domain_name, record_type="_all", callback=None):
        """
        Preforms a DNS lookup
        Args:
            domain_name (str): The domain name or sub-domain to lookup
            record_type (str): The DNS resource record type to query for, or ``_all`` for all record types
            callback (str): A JSONP callback 

        Returns:
            dict: Lookup results
            str: lookup results data wrapped in JSONP if ``callback`` was specified

        """
        endpoint = "/whoisserver/DNSService"
        params = dict(domainName=domain_name, recordType=record_type, callback=callback)

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
        params = dict(cmd="GET_DN_AVAILABILITY", getMode=mode.upper(), domainName=domain_name)

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
        if self._email_key is None:
            raise ValueError("Email verification API key is not set")

        url = "https://emailverification.whoisxmlapi.com/api/v1"
        params = dict(apiKey=self._email_key, emailAddress=email_address, format="JSON")
        response = self._session.get(url, params=params)
        response.raise_for_status()

        return response.json()
