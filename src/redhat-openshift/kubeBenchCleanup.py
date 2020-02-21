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

logger = logging.getLogger("cleanup")


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
=======
from ibm_cloud_sdk_core.authenticators import BearerTokenAuthenticator, IAMAuthenticator
from ibm_security_advisor_findings_api_sdk import FindingsApiV1

logger = logging.getLogger("cleanup")
logger.setLevel(logging.INFO)

def obtain_iam_token(api_key):
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
    notes = []
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
            notes.append(note)
        return notes
    else:
        return []
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
>>>>>>> c040036... sdk integration complete


def delete_all_kubenotes(account_id, token, endpoint):
	notes = get_all_kubebenchnotes(account_id, token, endpoint)
	delete_notes(account_id, token, endpoint, notes)
	
def delete_notes(account_id, token, endpoint, notes):
<<<<<<< HEAD
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    for note in notes:
        if note['kind'] == "CARD":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshift/notes/"+ note['id']
        elif note['provider_id'] == "kubeBenchRedhatOpenshiftWarnings":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftWarnings/notes/"+ note['id']
        elif note['provider_id'] == "kubeBenchRedhatOpenshiftFailures":
            url = endpoint + "/" + account_id + "/providers/kubeBenchRedhatOpenshiftFailures/notes/"+ note['id']
        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
        except:
            logger.exception("An unexpected error was encountered while deleting the note" + str(err))
        time.sleep(1)
=======
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

def cleanup(apikey, account_id, endpoint):
    token = obtain_iam_token(apikey)
    try:
<<<<<<< HEAD
    	delete_all_kubenotes(account_id, token, endpoint)
        vulnerabilityOccurrences = get_all_kubebenchoccurrences(account_id, token, endpoint)
        delete_occurrences(account_id, token, endpoint, vulnerabilityOccurrences)
    except:
        logger.exception("An unexpected error was encountered while cleanup");
=======
        delete_all_kubenotes(account_id, token, endpoint)
        vulnerabilityOccurrences = get_all_kubebenchoccurrences(account_id, token, endpoint)
        delete_occurrences(account_id, token, endpoint, vulnerabilityOccurrences)
    except:
        logger.exception("An unexpected error was encountered while cleanup")
>>>>>>> c040036... sdk integration complete

def main(args):
    account_id = args[1]
    apikey = args[2]
    endpoint =  args[3]
    cleanup(apikey, account_id, endpoint)


if __name__ == "__main__":
    main(sys.argv)
