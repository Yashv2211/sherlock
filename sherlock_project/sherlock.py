#! /usr/bin/env python3

"""
Sherlock: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""
import sys
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
        """
        # Record the start time for the request.
        if hooks is None:
            hooks = {}
        start = monotonic()

        def response_time(resp, *args, **kwargs):
            """Response Time Hook."""
            resp.elapsed = monotonic() - start
            return

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
    """Checks if {?} exists in the username."""
    return "{?}" in username


checksymbols = ["_", "-", "."]


def multiple_usernames(username):
    """Replace the parameter with symbols and return a list of usernames."""
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
    """Run Sherlock Analysis."""
    query_notify.start(username)

    if tor or unique_tor:
        try:
            from torrequest import TorRequest
        except ImportError:
            print("Error: Tor request library not found.")
            sys.exit(query_notify.finish())

        try:
            underlying_request = TorRequest()
        except OSError:
            print("Error: Tor not found in system path.")
            sys.exit(query_notify.finish())

        underlying_session = underlying_request.session
    else:
        underlying_session = requests.session()

    max_workers = min(len(site_data), 20)
    session = SherlockFuturesSession(max_workers=max_workers, session=underlying_session)
    results_total = {}

    for social_network, net_info in site_data.items():
        results_site = {"url_main": net_info.get("urlMain")}
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0",
        }
        if "headers" in net_info:
            headers.update(net_info["headers"])

        url = interpolate_string(net_info["url"], username.replace(' ', '%20'))

        regex_check = net_info.get("regexCheck")
        if regex_check and re.search(regex_check, username) is None:
            results_site["status"] = QueryResult(
                username, social_network, url, QueryStatus.ILLEGAL
            )
            query_notify.update(results_site["status"])
        else:
            results_site["url_user"] = url
            url_probe = net_info.get("urlProbe") or url
            request_method = net_info.get("request_method")
            request_payload = net_info.get("request_payload")
            if request_payload:
                request_payload = interpolate_string(request_payload, username)

            request = getattr(session, request_method.lower(), session.get)

            allow_redirects = net_info["errorType"] != "response_url"
            future = request(
                url=url_probe,
                headers=headers,
                allow_redirects=allow_redirects,
                timeout=timeout,
                json=request_payload,
            )
            net_info["request_future"] = future

            if unique_tor:
                underlying_request.reset_identity()

        results_total[social_network] = results_site

    for social_network, net_info in site_data.items():
        results_site = results_total.get(social_network)

        url = results_site.get("url_user")
        status = results_site.get("status")
        if status:
            continue

        error_type = net_info["errorType"]
        future = net_info["request_future"]
        r, error_text, exception_text = get_response(
            request_future=future, error_type=error_type, social_network=social_network
        )

        try:
            response_time = r.elapsed
        except AttributeError:
            response_time = None

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
            context=error_text,
        )
        query_notify.update(result)
        results_site["status"] = result
        results_site["http_status"] = r.status_code if r else "?"
        results_site["response_text"] = r.text if r else ""

    return results_total


if __name__ == "__main__":
    main()
