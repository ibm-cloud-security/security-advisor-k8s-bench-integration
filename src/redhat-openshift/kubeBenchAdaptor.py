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
<<<<<<< HEAD


# Change the context according to your service

def obtain_iam_token(api_key, token_url):
    if not api_key:
        raise Exception("obtain_uaa_token: missing api key")

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }

    body = 'grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&apikey=' + api_key + '&response_type=cloud_iam'
    try:
        response = requests.post(token_url, data=body, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        logger.exception("An unexpected error was encountered while obtaining IAM token" + str(err))
        return None
    if response.status_code == 200 and response.json()['access_token']:
        return response.json()['access_token']
=======
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
>>>>>>> c040036... sdk integration complete


def adaptInsightsToOccurence(finding_type, provider_id,remediation, message, account_id, cluster_name):
    severity = "LOW"
    if (provider_id == "kubeBenchRedhatOpenshiftFailures"):
<<<<<<< HEAD
        severity = "HIGH"
    
=======
        severity = "HIGH"    
>>>>>>> c040036... sdk integration complete
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


<<<<<<< HEAD

=======
>>>>>>> c040036... sdk integration complete
def id_generator(size=6, chars=string.digits):
    return ''.join(random.choice(chars) for x in range(size))


# This method needs to be defined for any partner application that needs to adapt
def fetchInsightsReportedByPartner(account_id, cluster_name):
    fileName = '/vul.txt'
    kubeBenchFailureVulnerabilities = fetchFailureList(fileName)
<<<<<<< HEAD
    print(kubeBenchFailureVulnerabilities)
    kubebenchWarningVulnerabilities= fetchWarningList(fileName)

    vulnerabilityInsights = {"insights": []}
    finding_type = "kubebenchredhat-openshift-failure"
    for failure in kubeBenchFailureVulnerabilities:
        print(failure)
        kbenchFailure = adaptInsightsToOccurence(finding_type,
                                                   "kubeBenchRedhatOpenshiftFailures",
                                                   failure["remediation"],
                                                   failure["issue"],
                                                   account_id, cluster_name)


        vulnerabilityInsights["insights"].append(kbenchFailure)


    finding_type = "kubebenchredhat-openshift-warning"
    for warning in kubebenchWarningVulnerabilities:

        kbenchWarning = adaptInsightsToOccurence(finding_type,
                                                   "kubeBenchRedhatOpenshiftWarnings",
                                                   warning["remediation"],
                                                   warning["issue"],
                                                   account_id, cluster_name)


        vulnerabilityInsights["insights"].append(kbenchWarning)

=======
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
>>>>>>> c040036... sdk integration complete
    return vulnerabilityInsights


def main(args):
<<<<<<< HEAD

=======
>>>>>>> c040036... sdk integration complete
    account_id = args[1]
    apikey = args[2]
    cluster_name =  args[3]
    endpoint =  args[4]
    vulnerabilityInsights = fetchInsightsReportedByPartner(account_id, cluster_name)
    postToSA({"vulnerabilityInsights": vulnerabilityInsights,
            "apikey": apikey,
            "account": account_id,
            "endpoint": endpoint})

<<<<<<< HEAD

=======
>>>>>>> c040036... sdk integration complete
if __name__ == "__main__":
    main(sys.argv)
