import datetime
import json
import logging
import re
import sys
import time
import urllib.parse
import urllib3
import urllib3.exceptions
import pandas as pd
import requests
import requests.exceptions

from msf.config import CONFIG
from msf.core.templates import Templates

class Module(Templates):
    """ Determine the running software version of a remote F5 BIG-IP management interface. """

    # These are the static resources whose modification times (reflected in
    # ETag or Last-Modified header values) imply a specific version of BIG-IP.
    static_resources = [
        "/tmui/tmui/login/images/logo_f5.png",
        "/tmui/tmui/login/images/logo_f5_new.png",
    ]

    # The keys in this dictionary represent HTTP response headers that we're
    # looking for. Each of those headers maps to a function in this namespace
    # that knows how to decode that header value into a datetime.
    mtime_headers = {
        "ETag": "etag_to_datetime",
        "Last-Modified": "last_modified_to_datetime",
    }

    # Be sneaky.
    request_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.version = 1
        self.author = ['yrb']
        self.description = (
            f'CVE-2022-1388, a critical vulnerability in the F5 BIG-IP management interface'
        )
        self.detailed_description = (
            f'CVE-2022-1388, a critical vulnerability in the F5 BIG-IP management interface,'
            f' allows an attacker to bypass authentication and remotely execute arbitrary system commands.'
            f' Bishop Fox developed a BIG-IP scanner that you can use to determine:'
            f'- Which software version is running on a remote F5 BIG-IP management interface'
            f'- Whether a specific appliance is affected by any known vulnerabilities,'
            f' including CVE-2022-1388—all without sending any malicious traffic to the server (i.e., risking being blocked by a WAF)'
        )
        self.f5_version = None

        self.options.add_string('URL', 'Path scan')
        self.options.add_boolean(
            'ALL', 
            "request all resources; don't stop after an exact match", 
            required = False,
            default = False
        )
        self.options.add_path(
            'VERSION_TABLE', 
            'version table', 
            default = CONFIG.DATA_PATH + '/brute/version-table.csv'
        )

    def run(self, frmwk, args):
        self.frmwk = frmwk
        self.url = self.options['URL'] if self.options['URL'].endswith('/') else self.options['URL'] + '/'
        self.all = self.options['ALL']
        self.f5_version = pd.DataFrame(pd.read_csv(self.options['VERSION_TABLE'])) if self.options['VERSION_TABLE'] else []

        self.frmwk.print_status('Starting CVE-2022-1388 scanner')

        # Group, sort, serialize, and print results.
        matches = self.scan_target(self.url, self.all)
        if not matches.empty:
            self.frmwk.print_status(
                json.dumps(
                    matches.groupby(["version", "precision"])
                    .first()
                    .sort_values(
                        ["precision"], key=lambda x: x.map({"exact": 0, "approximate": 1})
                    )
                    .reset_index()
                    .to_dict("records")
                )
            )
        else:
            self.frmwk.print_status("[]")
    def get_mtime_headers(self, target: str, resource: str) -> dict:
        url = urllib.parse.urljoin(target, resource)
        self.frmwk.print_status(f"requesting {url}")
        try:
            resp = requests.get (
                url,
                headers=self.request_headers,
                timeout=5,
                verify=False,
                allow_redirects=True,
            )

            resp.raise_for_status()

            return {
                header_name: resp.headers[header_name].strip('"')
                for header_name in self.mtime_headers
                if header_name in resp.headers
            }
        # These errors are indicative of target-level issues. Don't continue
        # requesting other resources when encountering these; instead, bail.
        except (
            requests.exceptions.ConnectTimeout,
            requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
        ) as e:
            self.frmwk.print_error(f"could not connect to target: {type(e).__name__}")
            return {}
        # Otherwise, if the resource simply doesn't exist, keep moving.
        except (requests.exceptions.HTTPError, requests.exceptions.ReadTimeout) as e:
            self.frmwk.print_error({type(e).__name__})
            return {}
    
    # Check target for the presence of each static resource.
    def scan_target(self, target: str, request_all: bool = False) -> pd.DataFrame:
        matches = pd.DataFrame()

        for resource in self.static_resources:
            # Search the resource for relevant mtime-related HTTP response headers.
            resp_headers = self.get_mtime_headers(
                target=target,
                resource=resource,
            )

            for header_name, header_value in resp_headers.items():
                # Convert header value to datetime.
                header_parser = getattr(self, self.mtime_headers[header_name])
                mtime = pd.Timestamp(header_parser(header_value), tz="UTC")

                # Get exact matches.
                exact = self.f5_version[self.f5_version["modification_time"] == mtime]
                exact["precision"] = "exact"
                results = exact

                if request_all or exact.empty:
                    # Get approximate matches.
                    delta = datetime.timedelta(hours=27)
                    approx = self.f5_version[
                        (self.f5_version["modification_time"] != mtime)
                        & (self.f5_version["modification_time"] >= mtime - delta)
                        & (self.f5_version["modification_time"] <= mtime + delta)
                    ]
                    approx["precision"] = "approximate"

                    # Combine results.
                    results = (
                        pd.concat([exact, approx]).reset_index().drop("index", axis=1)
                    )

                results["target"] = target
                results["resource"] = resource
                results["header_name"] = header_name
                results["header_value"] = header_value

                # Append and optionally immediately return matches.
                matches = pd.concat([matches, results])
                if not exact.empty and not request_all:
                    matches["modification_time"] = matches[
                        "modification_time"
                    ].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                    return matches.reset_index().drop("index", axis=1)
        
        if "modification_time" in matches:
            matches["modification_time"] = matches[
                "modification_time"
            ].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        return matches.reset_index().drop("index", axis=1)

    # Parse an ETag value into a datetime.
    @staticmethod
    def etag_to_datetime(etag: str) -> datetime.datetime:

        # ETag: "1fe7-5db411548c100"
        if re.match(r"^[0-9a-f]{4}-[0-9a-f]{13}$", etag):
            timestamp = int(str(int(etag.split("-")[1], 16))[:-6])

        # ETag: "6e1862414fe4"
        elif re.match(r"^[0-9a-f]{12}$", etag):
            timestamp = int(etag[-8:], 16)

        # Unknown format.
        else:
            timestamp = 0

        return datetime.datetime.utcfromtimestamp(timestamp)

    # Parse a Last-Modified value into a datetime.
    @staticmethod
    def last_modified_to_datetime(last_modified: str) -> datetime.datetime:

        # Last-Modified: Mon, 28 Mar 2022 06:04:20 GMT
        return datetime.datetime.strptime(last_modified[:-4], "%a, %d %b %Y %X")