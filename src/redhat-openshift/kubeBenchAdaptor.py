import time
import json
import sys
import requests
import os
import logging
import argparse
import datetime
import string
import random
from kubeBenchResultsParser import fetchFailureList,fetchWarningList
from kubeBenchL1Adaptor import postToSA
from ibm_cloud_sdk_core.authenticators import BearerTokenAuthenticator, IAMAuthenticator
from ibm_security_advisor_findings_api_sdk import FindingsApiV1

logger = logging.getLogger("adaptor")
logger.setLevel(logging.INFO)

def obtain_iam_token(api_key, token_url):
    if not api_key:
        raise Exception("obtain_iam_token: missing api key")
    try:
        authenticator = IAMAuthenticator(api_key, url=os.environ['TOKEN_URL'])
        token = authenticator.token_manager.get_token()
    except requests.exceptions.HTTPError as err:
        logger.exception("an unexpected error was encountered while obtaining IAM token: "+str(err))
        sys.exit(1)
    if token:
        return token


def adaptInsightsToOccurence(finding_type, provider_id,remediation, message, account_id, cluster_name):
    severity = "LOW"
    if (provider_id == "kubeBenchRedhatOpenshiftFailures"):
        severity = "HIGH"    
    initial = ""
    if(finding_type == "kubebenchredhat-openshift-failure"):
        initial = "Failure - "
    else:
        initial = "Warning - "

    pay_json = {
        "note_name": str(account_id) + "/providers/" + str(provider_id) + "/notes/" + str(finding_type),
        "kind": "FINDING",
        "short_description": initial + message[7: len(message) -9 ],
        # "message": message,
        "description": message,
        "remediation": remediation,
        "provider_id": provider_id,
        "context" : {
			"resource_name": cluster_name,
			"resource_type": "cluster",
        },
        "id": id_generator(),
        "finding": {
            "severity": severity,
            "next_steps": [{
			"title": remediation
			}]
        }
    }
    return pay_json


def id_generator(size=6, chars=string.digits):
    return ''.join(random.choice(chars) for x in range(size))


# This method needs to be defined for any partner application that needs to adapt
def fetchInsightsReportedByPartner(account_id, cluster_name):
    fileName = '/vul.txt'
    kubeBenchFailureVulnerabilities = fetchFailureList(fileName)
    kubebenchWarningVulnerabilities= fetchWarningList(fileName)
    vulnerabilityInsights = {"insights": []}
    finding_type = "kubebenchredhat-openshift-failure"
    for failure in kubeBenchFailureVulnerabilities:
        kbenchFailure = adaptInsightsToOccurence(finding_type, "kubeBenchRedhatOpenshiftFailures", failure["remediation"], failure["issue"], account_id, cluster_name)
        vulnerabilityInsights["insights"].append(kbenchFailure)
    finding_type = "kubebenchredhat-openshift-warning"
    for warning in kubebenchWarningVulnerabilities:
        kbenchWarning = adaptInsightsToOccurence(finding_type, "kubeBenchRedhatOpenshiftWarnings", warning["remediation"], warning["issue"], account_id, cluster_name)
        vulnerabilityInsights["insights"].append(kbenchWarning)
    return vulnerabilityInsights


def main(args):
    account_id = args[1]
    apikey = args[2]
    cluster_name =  args[3]
    endpoint =  args[4]
    vulnerabilityInsights = fetchInsightsReportedByPartner(account_id, cluster_name)
    postToSA({"vulnerabilityInsights": vulnerabilityInsights,
            "apikey": apikey,
            "account": account_id,
            "endpoint": endpoint})

if __name__ == "__main__":
    main(sys.argv)
