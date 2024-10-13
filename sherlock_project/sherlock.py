#! /usr/bin/env python3

"""
Sherlock: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""

import sys

try:
    from sherlock_project.__init__ import import_error_test_var # noqa: F401
except ImportError:
    print("Did you run Sherlock with `python3 sherlock/sherlock.py ...`?")
    print("This is an outdated method. Please see https://sherlockproject.xyz/installation for up-to-date instructions.")
    sys.exit(1)

import csv
import signal
import pandas as pd
import os
import re
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from json import loads as json_loads
from time import monotonic

import requests
from requests_futures.sessions import FuturesSession

from sherlock_project.__init__ import (
    __longname__,
    __shortname__,
    __version__,
    forge_api_latest_release,
)

from sherlock_project.result import QueryStatus
from sherlock_project.result import QueryResult
from sherlock_project.notify import QueryNotify
from sherlock_project.notify import QueryNotifyPrint
from sherlock_project.sites import SitesInformation
from colorama import init
from argparse import ArgumentTypeError


class SherlockFuturesSession(FuturesSession):
    def request(self, method, url, hooks=None, *args, **kwargs):
        """Request URL.

        This extends the FuturesSession request method to calculate a response
        time metric to each request.

        It is taken (almost) directly from the following Stack Overflow answer:
        https://github.com/ross/requests-futures#working-in-the-background
        """
        # Record the start time for the request.
        if hooks is None:
            hooks = {}
        start = monotonic()

        def response_time(resp, *args, **kwargs):
            """Response Time Hook."""
            resp.elapsed = monotonic() - start

        try:
            if isinstance(hooks["response"], list):
                hooks["response"].insert(0, response_time)
            elif isinstance(hooks["response"], tuple):
                hooks["response"] = list(hooks["response"])
                hooks["response"].insert(0, response_time)
            else:
                hooks["response"] = [response_time, hooks["response"]]
        except KeyError:
            hooks["response"] = [response_time]

        return super(SherlockFuturesSession, self).request(
            method, url, hooks=hooks, *args, **kwargs
        )


def get_response(request_future, error_type, social_network):
    # Default for Response object if some failure occurs.
    response = None

    error_context = "General Unknown Error"
    exception_text = None
    try:
        response = request_future.result()
        if response.status_code:
            error_context = None
    except requests.exceptions.HTTPError as errh:
        error_context = "HTTP Error"
        exception_text = str(errh)
    except requests.exceptions.ProxyError as errp:
        error_context = "Proxy Error"
        exception_text = str(errp)
    except requests.exceptions.ConnectionError as errc:
        error_context = "Error Connecting"
        exception_text = str(errc)
    except requests.exceptions.Timeout as errt:
        error_context = "Timeout Error"
        exception_text = str(errt)
    except requests.exceptions.RequestException as err:
        error_context = "Unknown Error"
        exception_text = str(err)

    return response, error_context, exception_text


def interpolate_string(input_object, username):
    if isinstance(input_object, str):
        return input_object.replace("{}", username)
    elif isinstance(input_object, dict):
        return {k: interpolate_string(v, username) for k, v in input_object.items()}
    elif isinstance(input_object, list):
        return [interpolate_string(i, username) for i in input_object]
    return input_object


def check_for_parameter(username):
    """Check if {?} exists in the username"""
    return "{?}" in username


checksymbols = ["_", "-", "."]


def multiple_usernames(username):
    """Replace the parameter with symbols and return a list of usernames"""
    return [username.replace("{?}", i) for i in checksymbols]


def sherlock(
    username,
    site_data,
    query_notify: QueryNotify,
    tor: bool = False,
    unique_tor: bool = False,
    dump_response: bool = False,
    proxy=None,
    timeout=60,
):
    """Run Sherlock Analysis.

    Checks for existence of username on various social media sites.
    """
    # Notify caller that we are starting the query.
    query_notify.start(username)

    # Create session based on request methodology
    if tor or unique_tor:
        try:
            from torrequest import TorRequest
        except ImportError:
            print("Important!")
            print("> --tor and --unique-tor are now DEPRECATED, and may be removed in a future release of Sherlock.")
            print("> Please see the documentation for installation guidance.")
            sys.exit(query_notify.finish())

        # Requests using Tor obfuscation
        try:
            underlying_request = TorRequest()
        except OSError:
            print("Tor not found in system path. Unable to continue.\n")
            sys.exit(query_notify.finish())

        underlying_session = underlying_request.session
    else:
        # Normal requests
        underlying_session = requests.session()

    max_workers = min(len(site_data), 20)
    session = SherlockFuturesSession(max_workers=max_workers, session=underlying_session)

    # Results from analysis of all sites
    results_total = {}

    # First create futures for all requests
    for social_network, net_info in site_data.items():
        # Results from analysis of this specific site
        results_site = {"url_main": net_info.get("urlMain")}

        # A user agent is needed for some sites
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0",
        }

        if "headers" in net_info:
            # Override/append any extra headers required by a given site.
            headers.update(net_info["headers"])

        # URL of user on site (if it exists)
        url = interpolate_string(net_info["url"], username.replace(' ', '%20'))

        # Don't make request if username is invalid for the site
        regex_check = net_info.get("regexCheck")
        if regex_check and re.search(regex_check, username) is None:
            results_site["status"] = QueryResult(
                username, social_network, url, QueryStatus.ILLEGAL
            )
            results_site["url_user"] = ""
            query_notify.update(results_site["status"])
        else:
            # URL of user on site (if it exists)
            results_site["url_user"] = url
            url_probe = net_info.get("urlProbe")
            request_method = net_info.get("request_method")
            request_payload = net_info.get("request_payload")
            request = None

            if request_method == "GET":
                request = session.get
            elif request_method == "HEAD":
                request = session.head
            elif request_method == "POST":
                request = session.post
            elif request_method == "PUT":
                request = session.put

            if request_payload is not None:
                request_payload = interpolate_string(request_payload, username)

            if url_probe is None:
                url_probe = url
            else:
                url_probe = interpolate_string(url_probe, username)

            if net_info["errorType"] == "response_url":
                allow_redirects = False
            else:
                allow_redirects = True

            future = request(
                url=url_probe,
                headers=headers,
                allow_redirects=allow_redirects,
                timeout=timeout,
                json=request_payload,
            )

            # Store future in data for access later
            net_info["request_future"] = future

        # Add this site's results into final dictionary
        results_total[social_network] = results_site

    for social_network, net_info in site_data.items():
        # Retrieve results again
        results_site = results_total.get(social_network)
        url = results_site.get("url_user")
        status = results_site.get("status")
        if status is not None:
            continue

        # Get the expected error type
        error_type = net_info["errorType"]
        future = net_info["request_future"]
        r, error_text, exception_text = get_response(
            request_future=future, error_type=error_type, social_network=social_network
        )

        # Get response time for response of our request.
        try:
            response_time = r.elapsed
        except AttributeError:
            response_time = None

        # Default query status
        query_status = QueryStatus.UNKNOWN

        if error_text is not None:
            query_status = QueryStatus.ERROR
        elif error_type == "status_code":
            error_codes = net_info.get("errorCode")
            query_status = QueryStatus.CLAIMED
            if isinstance(error_codes, int):
                error_codes = [error_codes]

            if error_codes and r.status_code in error_codes:
                query_status = QueryStatus.AVAILABLE
            elif r.status_code >= 300 or r.status_code < 200:
                query_status = QueryStatus.AVAILABLE
        elif error_type == "message":
            error_flag = not any(error in r.text for error in net_info.get("errorMsg", []))
            query_status = QueryStatus.CLAIMED if error_flag else QueryStatus.AVAILABLE
        elif error_type == "response_url":
            if 200 <= r.status_code < 300:
                query_status = QueryStatus.CLAIMED
            else:
                query_status = QueryStatus.AVAILABLE

        result = QueryResult(
            username=username,
            site_name=social_network,
            site_url_user=url,
            status=query_status,
            query_time=response_time,
        )
        query_notify.update(result)

        # Save status of request
        results_site["status"] = result
        results_total[social_network] = results_site

    return results_total


def timeout_check(value):
    """Check Timeout Argument."""
    float_value = float(value)
    if float_value <= 0:
        raise ArgumentTypeError(f"Invalid timeout value: {value}. Timeout must be a positive number.")
    return float_value


def handler(signal_received, frame):
    """Exit gracefully without throwing errors"""
    sys.exit(0)


def main():
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=f"{__longname__} (Version {__version__})",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__shortname__} v{__version__}",
        help="Display version information and dependencies.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        "-d",
        "--debug",
        action="store_true",
        dest="verbose",
        default=False,
        help="Display extra debugging information and metrics.",
    )
    parser.add_argument(
        "--folderoutput",
        "-fo",
        dest="folderoutput",
        help="If using multiple usernames, the output of the results will be saved to this folder.",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="output",
        help="If using single username, the output of the result will be saved to this file.",
    )
    parser.add_argument(
        "--tor",
        "-t",
        action="store_true",
        dest="tor",
        default=False,
        help="Make requests over Tor; increases runtime; requires Tor to be installed and in system path.",
    )
    parser.add_argument(
        "--unique-tor",
        "-u",
        action="store_true",
        dest="unique_tor",
        default=False,
        help="Make requests over Tor with new Tor circuit after each request; increases runtime; requires Tor to be installed and in system path.",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        dest="csv",
        default=False,
        help="Create Comma-Separated Values (CSV) File.",
    )
    parser.add_argument(
        "--xlsx",
        action="store_true",
        dest="xlsx",
        default=False,
        help="Create the standard file for the modern Microsoft Excel spreadsheet (xlsx).",
    )
    parser.add_argument(
        "--site",
        action="append",
        metavar="SITE_NAME",
        dest="site_list",
        default=[],
        help="Limit analysis to just the listed sites. Add multiple options to specify more than one site.",
    )
    parser.add_argument(
        "--proxy",
        "-p",
        metavar="PROXY_URL",
        action="store",
        dest="proxy",
        default=None,
        help="Make requests over a proxy. e.g. socks5://127.0.0.1:1080",
    )
    parser.add_argument(
        "--dump-response",
        action="store_true",
        dest="dump_response",
        default=False,
        help="Dump the HTTP response to stdout for targeted debugging.",
    )
    parser.add_argument(
        "--json",
        "-j",
        metavar="JSON_FILE",
        dest="json_file",
        default=None,
        help="Load data from a JSON file or an online, valid, JSON file.",
    )
    parser.add_argument(
        "--timeout",
        action="store",
        metavar="TIMEOUT",
        dest="timeout",
        type=timeout_check,
        default=60,
        help="Time (in seconds) to wait for response to requests (Default: 60)",
    )
    parser.add_argument(
        "--print-all",
        action="store_true",
        dest="print_all",
        default=False,
        help="Output sites where the username was not found.",
    )
    parser.add_argument(
        "--print-found",
        action="store_true",
        dest="print_found",
        default=True,
        help="Output sites where the username was found.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        default=False,
        help="Don't color terminal output",
    )
    parser.add_argument(
        "username",
        nargs="+",
        metavar="USERNAMES",
        action="store",
        help="One or more usernames to check with social networks. Check similar usernames using {?} (replace to '_', '-', '.').",
    )
    parser.add_argument(
        "--browse",
        "-b",
        action="store_true",
        dest="browse",
        default=False,
        help="Browse to all results on default browser.",
    )

    parser.add_argument(
        "--local",
        "-l",
        action="store_true",
        default=False,
        help="Force the use of the local data.json file.",
    )

    parser.add_argument(
        "--nsfw",
        action="store_true",
        default=False,
        help="Include checking of NSFW sites from the default list.",
    )

    parser.add_argument(
        "--no-txt",
        action="store_true",
        dest="no_txt",
        default=False,
        help="Disable creation of a txt file",
    )

    args = parser.parse_args()

    # If the user presses CTRL-C, exit gracefully without throwing errors
    signal.signal(signal.SIGINT, handler)

    # Check for newer version of Sherlock. If it exists, let the user know
    try:
        latest_release_raw = requests.get(forge_api_latest_release).text
        latest_release_json = json_loads(latest_release_raw)
        latest_remote_tag = latest_release_json["tag_name"]

        if latest_remote_tag[1:] != __version__:
            print(
                f"Update available! {__version__} --> {latest_remote_tag[1:]}"
                f"\n{latest_release_json['html_url']}"
            )
    except Exception as error:
        print(f"A problem occurred while checking for an update: {error}")

    # Check arguments
    if args.tor and (args.proxy is not None):
        raise Exception("Tor and Proxy cannot be set at the same time.")

    if args.proxy is not None:
        print("Using the proxy: " + args.proxy)

    if args.tor or args.unique_tor:
        print("Using Tor to make requests")

    if args.no_color:
        init(strip=True, convert=False)
    else:
        init(autoreset=True)

    # Check if both output methods are entered as input.
    if args.output and args.folderoutput:
        print("You can only use one of the output methods.")
        sys.exit(1)

    # Check validity for single username output.
    if args.output and len(args.username) != 1:
        print("You can only use --output with a single username")
        sys.exit(1)

    # Create object with all information about sites
    try:
        if args.local:
            sites = SitesInformation(
                os.path.join(os.path.dirname(__file__), "resources/data.json")
            )
        else:
            sites = SitesInformation(args.json_file)
    except Exception as error:
        print(f"ERROR:  {error}")
        sys.exit(1)

    if not args.nsfw:
        sites.remove_nsfw_sites(do_not_remove=args.site_list)

    site_data_all = {site.name: site.information for site in sites}
    if args.site_list == []:
        site_data = site_data_all
    else:
        site_data = {}
        site_missing = []
        for site in args.site_list:
            counter = 0
            for existing_site in site_data_all:
                if site.lower() == existing_site.lower():
                    site_data[existing_site] = site_data_all[existing_site]
                    counter += 1
            if counter == 0:
                site_missing.append(f"'{site}'")

        if site_missing:
            print(f"Error: Desired sites not found: {', '.join(site_missing)}.")

        if not site_data:
            sys.exit(1)

    # Create notify object for query results.
    query_notify = QueryNotifyPrint(
        result=None, verbose=args.verbose, print_all=args.print_all, browse=args.browse
    )

    # Run report on all specified users.
    all_usernames = []
    for username in args.username:
        if check_for_parameter(username):
            for name in multiple_usernames(username):
                all_usernames.append(name)
        else:
            all_usernames.append(username)

    for username in all_usernames:
        results = sherlock(
            username,
            site_data,
            query_notify,
            tor=args.tor,
            unique_tor=args.unique_tor,
            dump_response=args.dump_response,
            proxy=args.proxy,
            timeout=args.timeout,
        )

        if args.output:
            result_file = args.output
        elif args.folderoutput:
            os.makedirs(args.folderoutput, exist_ok=True)
            result_file = os.path.join(args.folderoutput, f"{username}.txt")
        else:
            result_file = f"{username}.txt"

        if not args.no_txt:
            with open(result_file, "w", encoding="utf-8") as file:
                exists_counter = 0
                for website_name in results:
                    dictionary = results[website_name]
                    if dictionary.get("status").status == QueryStatus.CLAIMED:
                        exists_counter += 1
                        file.write(dictionary["url_user"] + "\n")
                file.write(f"Total Websites Username Detected On: {exists_counter}\n")

        if args.csv:
            result_file = f"{username}.csv"
            if args.folderoutput:
                os.makedirs(args.folderoutput, exist_ok=True)
                result_file = os.path.join(args.folderoutput, result_file)

            with open(result_file, "w", newline="", encoding="utf-8") as csv_report:
                writer = csv.writer(csv_report)
                writer.writerow(
                    [
                        "username",
                        "name",
                        "url_main",
                        "url_user",
                        "exists",
                        "http_status",
                        "response_time_s",
                    ]
                )
                for site in results:
                    if (
                        args.print_found
                        and not args.print_all
                        and results[site]["status"].status != QueryStatus.CLAIMED
                    ):
                        continue
                    response_time_s = results[site]["status"].query_time or ""
                    writer.writerow(
                        [
                            username,
                            site,
                            results[site]["url_main"],
                            results[site]["url_user"],
                            str(results[site]["status"].status),
                            results[site]["http_status"],
                            response_time_s,
                        ]
                    )

        if args.xlsx:
            usernames = []
            names = []
            url_main = []
            url_user = []
            exists = []
            http_status = []
            response_time_s = []

            for site in results:
                if (
                    args.print_found
                    and not args.print_all
                    and results[site]["status"].status != QueryStatus.CLAIMED
                ):
                    continue

                usernames.append(username)
                names.append(site)
                url_main.append(results[site]["url_main"])
                url_user.append(results[site]["url_user"])
                exists.append(str(results[site]["status"].status))
                http_status.append(results[site]["http_status"])
                response_time_s.append(results[site]["status"].query_time or "")

            df = pd.DataFrame(
                {
                    "username": usernames,
                    "name": names,
                    "url_main": url_main,
                    "url_user": url_user,
                    "exists": exists,
                    "http_status": http_status,
                    "response_time_s": response_time_s,
                }
            )
            df.to_excel(f"{username}.xlsx", sheet_name="sheet1", index=False)

        print()
    query_notify.finish()


if __name__ == "__main__":
    main()
