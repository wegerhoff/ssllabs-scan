"""
See APi doc: https://github.com/ssllabs/ssllabs-scan/blob/stable/ssllabs-api-docs.md
"""
from __future__ import print_function
from datetime import datetime
import json
import os
import requests
import time


API_URL = "https://api.ssllabs.com/api/v3/analyze"

CHAIN_ISSUES = {
    "0": "none",
    "1": "unused",
    "2": "incomplete chain",
    "3": "chain contains unrelated or duplicate certificates",
    "4": "the certificates form a chain (trusted or not) but incorrect order",
    "16": "contains a self-signed root certificate",
    "32": "the certificates form a chain but cannot be validated",
}

OPEN_SSL_CCS = {
    "1": "test failed",
    "0": "unknown",
    "1": "not vulnerable",
    "2": "possibly vulnerable, but not exploitable",
    "3": "vulnerable and exploitable",
}

# Forward secrecy protects past sessions against future compromises of secret keys or passwords.
FORWARD_SECRECY = {
    "0": "No WEAK",
    "1": "With some browsers WEAK",
    "2": "With modern browsers",
    "4": "Yes (with most browsers) ROBUST",
}

OPEN_SSL_LUCKY_MINUS_20 = {
    "1": "test failed",
    "0": "unknown",
    "1": "not vulnerable",
    "2": "vulnerable and insecure"
}

BLEICHENBACHER = {
    "-1": "test failed",
    "0": "unknown",
    "1": "not vulnerable",
    "2": "vulnerable (weak oracle)",
    "3": "vulnerable (strong oracle)",
    "4": "inconsistent results"
}

TICKETBLEED = {
    "1": "test failed",
    "0": "unknown",
    "1": "not vulnerable",
    "2": "vulnerable and insecure"
}

POODLE_TLS = {
    "3": "timeout",
    "-2": "TLS not supported",
    "-1": "test failed",
    "0": "unknown",
    "1": "not vulnerable",
    "2": "vulnerable"
}

PROTOCOLS = ["TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0 INSECURE", "SSL 2.0 INSECURE"]

VULNERABLES = ["Vuln Beast", "Vuln Drown", "Vuln Heartbleed", "Vuln FREAK",
               "Vuln openSsl Ccs", "Vuln openSSL LuckyMinus20", "Vuln POODLE", "Vuln POODLE TLS", "Bleichenbacher", "Ticketbleed" ]

SUMMARY_COL_NAMES = ["Domain", "Grade", "Grade (Trust ign.)", "IP", "Status", "HasWarnings", "Cert Expiry", "Chain Status", "Forward Secrecy", "Heartbeat ext"] + VULNERABLES + PROTOCOLS + ["Full Report"]


class SSLLabsClient():
    def __init__(self, check_progress_interval_secs=30):
        self.__check_progress_interval_secs = check_progress_interval_secs

    def analyze(self, host, summary_csv_file):
        data = self.start_new_scan(host=host)

        # write the output to file
        json_file = os.path.join(os.path.dirname(summary_csv_file), "{}.json".format(host))
        with open(json_file, "w") as outfile:
            json.dump(data, outfile, indent=2)

        # write the summary to file
        self.append_summary_csv(summary_csv_file, host, data)

    def start_new_scan(self, host, publish="off", startNew="off", all="done", ignoreMismatch="on"):
        path = API_URL
        payload = {
            "host": host,
            "publish": publish,
            "startNew": startNew,
            "all": all,
            "ignoreMismatch": ignoreMismatch
        }
        results = self.request_api(path, payload)
        payload.pop("startNew")

        while results["status"] != "READY" and results["status"] != "ERROR":
            time.sleep(self.__check_progress_interval_secs)
            results = self.request_api(path, payload)
        return results

    @staticmethod
    def request_api(url, payload):
        response = requests.get(url, params=payload)
        return response.json()

    @staticmethod
    def prepare_datetime(epoch_time):
        # SSL Labs returns an 13-digit epoch time that contains milliseconds, Python only expects 10 digits (seconds)
        return datetime.utcfromtimestamp(float(str(epoch_time)[:10])).strftime("%Y-%m-%d")

    def append_summary_csv(self, summary_file, host, data):
        # write the summary to file
        with open(summary_file, "a") as outfile:
            if 'certs' in data:
                validUntil = "-" if not data['certs'] else self.prepare_datetime(data['certs'][0]['notAfter'])
            else:
                validUntil = "-"
            if 'endpoints' in data:
                for ep in data["endpoints"]:
                    if 'certChains' in ep["details"]:
                        chainIssues = "-" if not ep["details"]["certChains"] else CHAIN_ISSUES[str(ep["details"]["certChains"][0]["issues"])]
                    else:
                        chainIssues = "-"
                    # see SUMMARY_COL_NAMES
                    summary = [
                        host,
                        "-" if 'grade' not in ep else ep["grade"],
                        "-" if 'gradeTrustIgnored' not in ep else ep["gradeTrustIgnored"],
                        "-" if 'ipAddress' not in ep else ep["ipAddress"],
                        ep["statusMessage"],
                        "-" if 'hasWarnings' not in ep else ep["hasWarnings"],
                        validUntil,
                        chainIssues,
                        "-" if 'forwardSecrecy' not in ep["details"] else FORWARD_SECRECY[str(ep["details"]["forwardSecrecy"])],
                        "-" if 'heartbeat' not in ep["details"] else ep["details"]["heartbeat"],
                        "-" if 'vulnBeast' not in ep["details"] else ep["details"]["vulnBeast"],
                        "-" if 'drownVulnerable' not in ep["details"] else ep["details"]["drownVulnerable"],
                        "-" if 'heartbleed' not in ep["details"] else ep["details"]["heartbleed"],
                        "-" if 'freak' not in ep["details"] else ep["details"]["freak"],
                        "-" if 'openSslCcs' not in ep["details"] else OPEN_SSL_CCS[str(ep["details"]["openSslCcs"])],
                        "-" if 'openSSLLuckyMinus20' not in ep["details"] else OPEN_SSL_LUCKY_MINUS_20[str(ep["details"]["openSSLLuckyMinus20"])],
                        "-" if 'poodle' not in ep["details"] else ep["details"]["poodle"],
                        "-" if 'poodleTls' not in ep["details"] else POODLE_TLS[str(ep["details"]["poodleTls"])],
                        "-" if 'bleichenbacher' not in ep["details"] else BLEICHENBACHER[str(ep["details"]["bleichenbacher"])],
                        "-" if 'ticketbleed' not in ep["details"] else TICKETBLEED[str(ep["details"]["ticketbleed"])]
                    ]
                    for protocol in PROTOCOLS:
                        found = False
                        for p in ep["details"]["protocols"]:
                            if protocol.startswith("{} {}".format(p["name"], p["version"])):
                                found = True
                                break
                        summary += ["Yes" if found is True else "No"]
            else:
                # Catch "Unable to resolve domain name"
                summary = [
                    host,
                    "-","-","-",
                    data['statusMessage'],
                    "-","-","-","-","-","-","-","-","-","-","-","-","-","-","-","-","-","-","-","-"
                ]

            # append link to the full report
            summary += ["{}.json".format(host)]

            outfile.write(",".join(str(s) for s in summary) + "\n")
