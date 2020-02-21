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
<<<<<<< HEAD

logger = logging.getLogger("iam")

vulnerablity_notes_defenition = {
    "notes": [
        {
            "kind": "FINDING",
            "short_description": "Kube bench redhat-openshift warnings",
            "long_description": "Kube bench redhat-openshift warnings",
=======
from ibm_cloud_sdk_core.authenticators import BearerTokenAuthenticator, IAMAuthenticator
from ibm_security_advisor_findings_api_sdk import FindingsApiV1

logger = logging.getLogger("l1_adaptor")
logger.setLevel(logging.INFO)

vulnerablity_notes_definition = {
    "notes": [
        {
            "kind": "FINDING",
            "short_description": "kube-bench RedHat OpenShift Warnings",
            "long_description": "kube-bench RedHat OpenShift Warnings",
>>>>>>> c040036... sdk integration complete
            "provider_id": "kubeBenchRedhatOpenshiftWarnings",
            "id": "kubebenchredhat-openshift-warning",
            "reported_by": {
                "id": "kubebenchredhat-openshift-warning",
<<<<<<< HEAD
                "title": "Kubebench redhat openshift control"
=======
                "title": "kube-bench RedHat OpenShift Control"
>>>>>>> c040036... sdk integration complete
            },
            "finding": {
                "severity": "LOW",
                "next_steps": [{
<<<<<<< HEAD
                    "title": "KUBE BENCH REDHAT OPENSHIFT WARNINGS"
=======
                    "title": "kube-bench RedHat OpenShift Warnings"
>>>>>>> c040036... sdk integration complete
                }]
            }
        },
        {
            "kind": "FINDING",
<<<<<<< HEAD
            "short_description": "Kube bench redhat openshift failures",
            "long_description": "Kube Bench RedhatOpenshift failures",
=======
            "short_description": "kube-bench RedHat OpenShift Failures",
            "long_description": "kube-bench RedHat OpenShift Failures",
>>>>>>> c040036... sdk integration complete
            "provider_id": "kubeBenchRedhatOpenshiftFailures",
            "id": "kubebenchredhat-openshift-failure",
            "reported_by": {
                "id": "kubebenchredhat-openshift-failure",
<<<<<<< HEAD
                "title": "Kubebench redhat openshift control"
=======
                "title": "kube-bench RedHat OpenShift Control"
>>>>>>> c040036... sdk integration complete
            },
            "finding": {
                "severity": "HIGH",
                "next_steps": [{
<<<<<<< HEAD
                    "title": "KUBE BENCH REDHAT OPENSHIFT FAILURE "
                }]
            }
        },

=======
                    "title": "kube-bench RedHat OpenShift Failures"
                }]
            }
        },
>>>>>>> c040036... sdk integration complete
        {
            "kind": "CARD",
            "provider_id": "kubeBenchRedhatOpenshift",
            "id": "kubebenchredhat-openshift-card",
<<<<<<< HEAD
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
=======
            "short_description": "kube-bench RedHat OpenShift Vulnerabilities",
            "long_description": "kube-bench RedHat OpenShift Vulnerabilities",
            "reported_by": {
                "id": "kubebenchredhat-openshift-card",
                "title": "kube-bench RedHat OpenShift Vulnerabilities"
            },
            "card": {
                "section": "Container Config Benchmark",
                "title": "kube-bench",
                "subtitle": "RedHat OpenShift",
>>>>>>> c040036... sdk integration complete
                "context" : {},
                "finding_note_names": [
                    "providers/kubeBenchRedhatOpenshiftWarnings/notes/kubebenchredhat-openshift-warning",
                    "providers/kubeBenchRedhatOpenshiftFailures/notes/kubebenchredhat-openshift-failure"
                ],
<<<<<<< HEAD
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
=======
                "elements": [
                    {
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
                        "text": "Failures",
>>>>>>> c040036... sdk integration complete
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
<<<<<<< HEAD
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
=======
        raise Exception("obtain_iam_token: missing api key")
    try:
        authenticator = IAMAuthenticator(api_key, url=os.environ['TOKEN_URL'])
        token = authenticator.token_manager.get_token()
    except requests.exceptions.HTTPError as err:
        logger.exception("an unexpected error was encountered while obtaining IAM token: "+str(err))
        sys.exit(1)
    if token:
        return token

def create_note(account_id, token, endpoint):
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for note in vulnerablity_notes_definition["notes"]:
            response = findingsAPI.create_note(
                account_id=account_id,
                provider_id=note['provider_id'],
                short_description=note['short_description'],
                long_description=note['long_description'],
                kind=note['kind'],
                id=note['id'],
                reported_by=note['reported_by'],
                finding=note['finding'] if 'finding' in note else None,
                card=note['card'] if 'card' in note else None
            )
            if response.get_status_code() == 200:
                logger.info("created note: %s" % note['id'])
            else:
                logger.error("unable to create note: %s" % note['id'])
    except:
        logger.exception("an unexpected error was encountered while creating note")
>>>>>>> c040036... sdk integration complete


def get_all_kubebenchnotes(account_id, token, endpoint):
    notes = []
<<<<<<< HEAD
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
=======
    providers = ["kubeBenchRedhatOpenshift", "kubeBenchRedhatOpenshiftWarnings", "kubeBenchRedhatOpenshiftFailures"]
    notes.extend(get_notes(account_id, token, endpoint, providers))
    return notes


def get_notes(account_id, token, endpoint, providers):
    notes = []
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for provider in providers:
            response = findingsAPI.list_notes(
                account_id=account_id, 
                provider_id=provider
            )
            if response.get_status_code() == 200:
                logger.info("got notes by provider: %s" % provider)
                for note in response.get_result()['notes']:
                    notes.append(note)
            else:
                logger.error("unable to get notes by provider: %s" % provider)
        return notes
    except requests.exceptions.HTTPError as err:
        logger.exception("an unexpected error was encountered while getting the note: "+str(err))
        return False


def delete_notes(account_id, token, endpoint, notes):
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for note in notes:
            response = findingsAPI.delete_note(
                account_id=account_id, 
                provider_id=note['provider_id'], 
                note_id=note['id']
            )
            if response.get_status_code() == 200:
                logger.info("deleted note: %s" % note['id'])
            else:
                logger.error("unable to delete note: %s" % note['id'])
    except:
        logger.exception("an unexpected error was encountered while deleting the note: "+str(err))
    time.sleep(1)
>>>>>>> c040036... sdk integration complete


def get_all_kubebenchoccurrences(account_id, token, endpoint):
    occurrences = []
<<<<<<< HEAD
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
=======
    providers = ["kubeBenchRedhatOpenshift", "kubeBenchRedhatOpenshiftWarnings", "kubeBenchRedhatOpenshiftFailures"]
    occurrences.extend(get_occurrences(account_id, token, endpoint, providers))
    return occurrences


def get_occurrences(account_id, token, endpoint, providers):
    occurrences = []
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for provider_id in providers:
            response = findingsAPI.list_occurrences(
                account_id=account_id, 
                provider_id=provider_id
            )
            if response.get_status_code() == 200:
                logger.info("got occurrences by provider: %s" % provider_id)
                for occurrence in response.get_result()['occurrences']:
                    occurrences.append(occurrence)
            else:
                logger.error("unable to get occurrences by provider: %s" % provider_id)
        return occurrences
    except requests.exceptions.HTTPError as err:
        logger.exception("an unexpected error was encountered while getting the occurrences: "+str(err))
        return False


def delete_occurrences(account_id, token, endpoint, occurrences):
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for occurrence in occurrences:
            response = findingsAPI.delete_occurrence(
                account_id=account_id, 
                provider_id=occurrence['provider_id'], 
                occurrence_id=occurrence['id']
            )
            if response.get_status_code() == 200:
                logger.info("deleted occurrence: %s" % occurrence['id'])
            else:
                logger.error("unable to delete occurrence: %s" % occurrence['id'])
    except requests.exceptions.HTTPError as err:
        logger.exception("an unexpected error was encountered while deleting the occurrence: "+str(err))
    time.sleep(1)
>>>>>>> c040036... sdk integration complete


def id_generator(size=6, chars=string.digits):
    return ''.join(random.choice(chars) for x in range(size))


# This method needs to be defined for any partner application that needs to adapt
def createOccurences(account_id, token, endpoint, occurrencesJson):
<<<<<<< HEAD
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
=======
    try:
        findingsAPI = FindingsApiV1(
            authenticator=BearerTokenAuthenticator(token)
        )
        findingsAPI.set_service_url(endpoint)
        for occurrence in occurrencesJson:
            response = findingsAPI.create_occurrence(
                account_id=account_id,
                provider_id=occurrence['provider_id'],
                note_name=occurrence['note_name'],
                kind=occurrence['kind'],
                remediation=occurrence['remediation'],
                context=occurrence['context'],
                id=occurrence['id'],
                finding=occurrence['finding'] if 'finding' in occurrence else None,
                kpi=occurrence['kpi'] if 'kpi' in occurrence else None
            )
            if response.status_code == 200:
                logger.info("created occurrence: %s" % occurrence['id'])
            else:
                logger.error("unable to create occurrence: %s" % occurrence['id'])
    except requests.exceptions.HTTPError as err:
            logger.exception("an unexpected error was encountered while creating occurrence: "+str(err))
>>>>>>> c040036... sdk integration complete
		    

def executePointInTimeVulnerabilityOccurenceAdapter(apikey, account_id, endpoint, vulnerabilitiesReportedByPartner):
    token = obtain_iam_token(apikey)
    try:
        create_note(account_id, token, endpoint)
    except:
<<<<<<< HEAD
        print("ignoring metadata duplicateerrors")
=======
        print("ignoring metadata duplicate errors")
>>>>>>> c040036... sdk integration complete
    try:
        vulnerabilityOccurrences = get_all_kubebenchoccurrences(account_id, token, endpoint)
        delete_occurrences(account_id, token, endpoint, vulnerabilityOccurrences)
    except:
<<<<<<< HEAD
        print("ignoring metadata duplicateerrors")
=======
        print("ignoring metadata duplicate errors")
>>>>>>> c040036... sdk integration complete

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
