import time
import json
import sys
import requests
import logging
import argparse
import datetime
import string
import random
import os

logger = logging.getLogger("iam")

vulnerablity_notes_defenition = {
    "notes": [
        {
            "kind": "FINDING",
            "short_description": "Kube bench redhat-openshift warnings",
            "long_description": "Kube bench redhat-openshift warnings",
            "provider_id": "kubeBenchRedhatOpenshiftWarnings",
            "id": "kubebenchredhat-openshift-warning",
            "reported_by": {
                "id": "kubebenchredhat-openshift-warning",
                "title": "Kubebench redhat openshift control"
            },
            "finding": {
                "severity": "LOW",
                "next_steps": [{
                    "title": "KUBE BENCH REDHAT OPENSHIFT WARNINGS"
                }]
            }
        },
        {
            "kind": "FINDING",
            "short_description": "Kube bench redhat openshift failures",
            "long_description": "Kube Bench RedhatOpenshift failures",
            "provider_id": "kubeBenchRedhatOpenshiftFailures",
            "id": "kubebenchredhat-openshift-failure",
            "reported_by": {
                "id": "kubebenchredhat-openshift-failure",
                "title": "Kubebench redhat openshift control"
            },
            "finding": {
                "severity": "HIGH",
                "next_steps": [{
                    "title": "KUBE BENCH REDHAT OPENSHIFT FAILURE "
                }]
            }
        },

        {
            "kind": "CARD",
            "provider_id": "kubeBenchRedhatOpenshift",
            "id": "kubebenchredhat-openshift-card",
            "short_description": "Kubebench redhat openshift vulnerabilities",
            "long_description": "kubebench redhat openshift reported vulnerabilities",
            "reported_by": {
                "id": "kubebenchredhat-openshift-card",
                "title": "kubebench redhat openshift vulnerabilities"
            },
            "card": {
                "section": "Container Config Benchmark",
                "title": "Kube-Bench",
                "subtitle": "Redhat Openshift",
                "context" : {},
                "finding_note_names": [
                    "providers/kubeBenchRedhatOpenshiftWarnings/notes/kubebenchredhat-openshift-warning",
                    "providers/kubeBenchRedhatOpenshiftFailures/notes/kubebenchredhat-openshift-failure"
                ],
                "elements": [{
                    "kind": "NUMERIC",
                    "text": "Warnings",
                    "default_time_range": "4d",
                    "value_type": {
                        "kind": "FINDING_COUNT",
                        "finding_note_names": [
                            "providers/kubeBenchRedhatOpenshiftWarnings/notes/kubebenchredhat-openshift-warning"
                        ]
                    }
                },
                    {
                        "kind": "NUMERIC",
                        "text": "Failiures",
                        "default_time_range": "4d",
                        "value_type": {
                            "kind": "FINDING_COUNT",
                            "finding_note_names": [
                                "providers/kubeBenchRedhatOpenshiftFailures/notes/kubebenchredhat-openshift-failure"
                            ]
                        }
                    }
                ]
            }
        }
    ]
}


def obtain_iam_token(api_key):
    if not api_key:
        raise Exception("obtain_uaa_token: missing api key")

    token_url = os.environ['TOKEN_URL']
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


def create_note(account_id, token, endpoint):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }

    for note in vulnerablity_notes_defenition["notes"]:
        if note['kind'] == "CARD":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshift/notes"
        elif note['provider_id'] == "kubeBenchRedhatOpenshiftWarnings":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftWarnings/notes"
        elif note['provider_id'] == "kubeBenchRedhatOpenshiftFailures":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftFailures/notes"

        try:
            response = requests.post(url, data=json.dumps(note), headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logger.exception("An unexpected error was encountered while creating note" + str(err))
        if response.status_code == 200:
            logger.info("Note created : %s" % note['id'])


def get_all_kubebenchnotes(account_id, token, endpoint):
    notes = []
    url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshift/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftWarnings/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftFailures/notes"
    notes.extend(get_notes(account_id, token, endpoint, url))
    return notes


def get_notes(account_id, token, endpoint, url):
    occurrences = []
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        logger.exception("An unexpected error was encountered while getting the note" + str(err))
        return False
    if response.status_code == 200:
        body = response.json()
        for note in body['notes']:
            occurrences.append(note['id'])
        return note
    else:
        return []


def delete_notes(account_id, token, endpoint, notes):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    for note in notes:
        if note['kind'] == "CARD":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshift/notes"
        elif note['provider_id'] == "kubeBenchRedhatOpenshiftWarnings":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftWarnings/notes"
        elif note['provider_id'] == "kubeBenchRedhatOpenshiftFailures":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftFailures/notes"
        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
        except:
            logger.exception("An unexpected error was encountered while deleting the note" + str(err))
        time.sleep(1)


def get_all_kubebenchoccurrences(account_id, token, endpoint):
    occurrences = []
    url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshift/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftWarnings/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftFailures/occurrences"
    occurrences.extend(get_occurrences(account_id, token, endpoint, url))
    return occurrences


def get_occurrences(account_id, token, endpoint, url):
    occurrences = []
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        logger.exception("An unexpected error was encountered while getting the occurrences" + str(err))
        return False
    if response.status_code == 200:
        body = response.json()
        for occurrence in body['occurrences']:
            occurrences.append(occurrence)
        return occurrences


def delete_occurrences(account_id, token, endpoint, occurrences):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    for occurrence in occurrences:
        if occurrence['provider_id'] == "kubeBenchRedhatOpenshiftWarnings":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftWarnings/occurrences/" + occurrence['id']
        elif occurrence['provider_id'] == "kubeBenchRedhatOpenshiftFailures":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftFailures/occurrences/" + occurrence['id']

        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logger.exception("An unexpected error was encountered while deleting the occurrence" + str(err))
        time.sleep(1)


def id_generator(size=6, chars=string.digits):
    return ''.join(random.choice(chars) for x in range(size))


# This method needs to be defined for any partner application that needs to adapt
def createOccurences(account_id, token, endpoint, occurrencesJson):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }

    for occurrence in occurrencesJson:
        if occurrence['provider_id'] == "kubeBenchRedhatOpenshiftWarnings":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftWarnings/occurrences"
        elif occurrence['provider_id'] == "kubeBenchRedhatOpenshiftFailures":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftFailures/occurrences"
        try:
            response = requests.post(url, data=json.dumps(occurrence), headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logger.exception("An unexpected error was encountered while creating occurrence" + str(err))
        if response.status_code == 200:
            logging.info("Created occurrence")
		    

def executePointInTimeVulnerabilityOccurenceAdapter(apikey, account_id, endpoint, vulnerabilitiesReportedByPartner):
    token = obtain_iam_token(apikey)
    try:
        create_note(account_id, token, endpoint)
    except:
        print("ignoring metadata duplicateerrors")
    try:
        vulnerabilityOccurrences = get_all_kubebenchoccurrences(account_id, token, endpoint)
        delete_occurrences(account_id, token, endpoint, vulnerabilityOccurrences)
    except:
        print("ignoring metadata duplicateerrors")

    createOccurences(account_id, token, endpoint, vulnerabilitiesReportedByPartner["insights"])
    occurrences = get_all_kubebenchoccurrences(account_id, token, endpoint)
    return occurrences


def postToSA(args):
    logging.info("Patch Management Monitoring started")
    apikey = args["apikey"]
    account_id = args["account"]
    endpoint = args["endpoint"]
    vulnerabilityOccurrences = executePointInTimeVulnerabilityOccurenceAdapter(apikey, account_id, endpoint,
                                                                               args["vulnerabilityInsights"])
    logging.info("Patch Management Monitoring completed")
    return {'insights': vulnerabilityOccurrences}
