import json
import os
import time
import gzip
import pickle

from os import path
from datetime import datetime

TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

CONNECTION_NEW = 'new'
CONNECTION_OLD = 'old'
CONNECTION_UNUSED = 'unused'
CONNECTION_TOTAL = 'total'
CONNECTION_LAST_RUN = 'last_run'
CONNECTION_NAME = 'name'
CONNECTION_ID = 'id'
CONNECTION_CONTEXT = 'context'
CONNECTION_VALUE = 'value'
CONNECTIONS_STRUCTURE = 'connections'

URL_CONNECTIONS = 'connections'
URL_JOB = 'jobs/'
URL_CREATE_USERS_EXPORTS_JOB = 'jobs/users-exports'

JOB_ID = 'job'
JOB_LOCATION = 'location'

STATUS_COMPLETED = 'completed'
STATUS = 'status'


def scrape_data(session, params):
    """
    scrape data from auth0
    :param session: current thread information
    :param params: parameters array as defined in the configuration file
    """
    base_url = params['base_url']
    headers = {'Authorization': 'Bearer ' + params['token']}
    old_threshold = time.time() - int(params['old_threshold'])
    new_threshold = time.time() - int(params['new_threshold'])

    database_file = 'persisted.txt'  # store in local database the requests history so that limits can be put in place
    requests_limit = int(params['requests_limit'])  # the number of requests is limited, cannot trigger them all at once
    requests_ttl = int(params['requests_ttl'])  # limit requests to target only the old ones

    # get all connections for the token
    connections = load_db(database_file, session, base_url, headers)

    # trigger a full user list export for each connection
    jobs = create_export_users_job(session, base_url, headers, connections, requests_limit, requests_ttl)

    # for each successfully submitted retrieve and process its outcome
    process_jobs(connections, session, base_url, headers, jobs, old_threshold, new_threshold)

    # persist in local db the current value of connections structure
    persist_db(database_file, connections)

    # parse connections into the output data
    return parse_connections(connections)


def load_db(database_file, session, base_url, headers):
    """
    Tries to load the database containing connections and their stored values.
    If it fails, it will retrieve connections from auth0 and initialize them
    """
    try:
        if path.exists(database_file):
            with open(database_file, 'rb') as handle:
                data = pickle.load(handle)
                print(data)
            return data
    except Exception as e:
        print(e)
        print('error restoring data from db - discarding all data')
        os.remove(database_file)

    return get_all_connections(session, base_url, headers)


def persist_db(database_file, connections):
    with open(database_file, 'wb') as handle:
        pickle.dump(connections, handle, protocol=pickle.HIGHEST_PROTOCOL)


def get_all_connections(session, base_url, headers):
    """ fetch all available connections for the provided session """
    url = base_url + URL_CONNECTIONS
    all_connections = []
    try:
        response = session.get(url=url, headers=headers)
        if response.text:
            connections = json.loads(response.text)
            for connection in connections:
                all_connections.append({
                    CONNECTION_ID: connection[CONNECTION_ID],
                    CONNECTION_NAME: connection[CONNECTION_NAME],
                    CONNECTION_LAST_RUN: 0,
                    CONNECTION_TOTAL: 0,
                    CONNECTION_OLD: 0,
                    CONNECTION_NEW: 0,
                    CONNECTION_UNUSED: 0
                })
        return all_connections
    except Exception as e:
        print(e)


def create_export_users_job(session, base_url, headers, connections, requests_limit, requests_ttl):
    """
    creates "requests_limit" amount of jobs to auth0 to export users
    each connection in "connections" will require an individual job
    """
    url = base_url + URL_CREATE_USERS_EXPORTS_JOB
    all_jobs = []
    eligible_last_run = time.time() - requests_ttl
    requests = 0

    try:
        for connection in connections:
            # check both requests_limit and ttl for current request
            if requests < requests_limit and connection[CONNECTION_LAST_RUN] < eligible_last_run:
                requests += 1  # increment requests counter to enable requests_limit capability
                data = {
                    "connection_id": connection[CONNECTION_ID],
                    "format": "json",
                    "limit": 500000
                }
                print('Submitting job for connection {}'.format(connection[CONNECTION_ID]))
                response = session.post(url=url, headers=headers, data=data)
                if response.text:
                    job = json.loads(response.text)
                    all_jobs.append({
                        CONNECTION_ID: connection[CONNECTION_ID],
                        'job': job['id']
                    })
                    print('Created job {}'.format(job['id']))
    except Exception as e:
        print(e)

    return all_jobs


def process_jobs(connections, session, base_url, headers, jobs, old_threshold, new_threshold):
    """ processes the data for each submitted job in "jobs" """
    for job in jobs:
        data = fetch_a_job(session, base_url, headers, job)
        if data:  # if data was fetched from the job
            for connection in connections:  # identify which connection it relates to
                if connection[CONNECTION_ID] == job[CONNECTION_ID]:  # this connection has new data - update it
                    total = 0
                    old = 0
                    new = 0
                    unused = 0
                    for element in data['users']:
                        total += 1

                        if 'created_at' in element:
                            created_at = datetime.strptime(element['created_at'], TIMESTAMP_FORMAT).timestamp()
                            if created_at > new_threshold:
                                new += 1

                        if 'last_login' in element:
                            last_login = datetime.strptime(element['last_login'], TIMESTAMP_FORMAT).timestamp()
                            if last_login < old_threshold:
                                old += 1
                        else:
                            unused += 1

                        connection[CONNECTION_TOTAL] = total
                        connection[CONNECTION_OLD] = old
                        connection[CONNECTION_NEW] = new
                        connection[CONNECTION_UNUSED] = unused

                    # set connection last_run to store in db and prevent job exhaustion
                    connection[CONNECTION_LAST_RUN] = time.time()


def fetch_a_job(session, base_url, headers, job):
    """ retrieves an auth0 submitted job, containing zipped json data, and parses it into a "users" array """
    url = base_url + URL_JOB + job[JOB_ID]
    retries = 0
    retries_limit = 10

    try:
        while retries < retries_limit:
            retries += 1
            print('Fetching results for job {}'.format(job[JOB_ID]))
            response = session.get(url=url, headers=headers)
            if response.text:
                job_data = json.loads(response.text)
                if job_data[STATUS] == STATUS_COMPLETED:
                    response_data = session.get(job_data[JOB_LOCATION])
                    raw_data = gzip.decompress(response_data.content).decode()

                    # the generated json is malformed - it's missing the delimiters and all elements are root
                    result = json.loads("{\"users\" : [" + raw_data.replace("\n{", ",\n{") + "]}")
                    return result

            if retries < retries_limit:
                # failed to retrieve data and more retries available - give it a rest and retry
                time.sleep(1)
    except Exception as e:
        print(e)

    return


def parse_connections(connections):
    """
    parses the internal database data, containing each connection values, and splits into separate elements so
    that grafana dashboard can display it in a meaningful way
    """
    return_data = {CONNECTIONS_STRUCTURE: []}
    for connection in connections:
        for context in ['total', 'new', 'old', 'unused']:
            if context == 'total':
                value = connection[CONNECTION_TOTAL]
            elif context == 'new':
                value = connection[CONNECTION_NEW]
            elif context == 'old':
                value = connection[CONNECTION_OLD]
            else:
                value = connection[CONNECTION_UNUSED]

            return_data[CONNECTIONS_STRUCTURE].append({
                CONNECTION_ID: connection[CONNECTION_ID],
                CONNECTION_NAME: connection[CONNECTION_NAME],
                CONNECTION_CONTEXT: context,
                CONNECTION_VALUE: value
            })
    print(return_data)
    return return_data
