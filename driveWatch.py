from __future__ import print_function
import httplib2
import os
import time
import webbrowser
import pytz
import json
import threading
import tempfile
import subprocess
import sys
import logging
import logging.handlers

from datetime import datetime, timedelta
from dateutil.parser import parse
from apiclient import discovery
from oauth2client import client
from oauth2client.file import Storage
from collections import namedtuple

SCOPES = 'https://www.googleapis.com/auth/admin.reports.audit.readonly'
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'Reports API Python Quickstart'

EVENT_NAMES = ['create', 'upload', 'edit', 'view', 'rename',
                'move', 'add_to_folder', 'remove_from_folder',
                'trash', 'delete', 'untrash', 'download', 'preview',
                'print', 'change_acl_editors', 'change_document_access_scope',
                'change_document_visibility', 'change_user_access',
                'team_drive_membership_change']

VIEW_THRESHOLD = 30

MAX_RESULTS = 100

BASELINE_PERCENT = 0.2 # percent to increase baseline by

TOKEN_ALERT=0
USER_ALERT=1
BASELINE_ALERT=2
THRESHOLD_ALERT=3

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class GSuiteTokens(object):
    __metaclass__ = Singleton

    def __init__(self, cfg_file="config.json"):
        self.cfg_file = cfg_file
        self.users_view_map = {}
        self.document_tokens = {}
        self.user_tokens = {}
        self.event_loop_thread = None
        self.logging = False
        self.syslog_logger = None
        self.user_baseline_map = {}

        dir_name = tempfile.mkdtemp()
        self.logfile_doc_tokens = os.path.join(dir_name, 'doc_tokens.log')
        self.logfile_user_tokens = os.path.join(dir_name, 'user_tokens.log')
        self.logfile_all_activity = os.path.join(dir_name, 'all_activity.log')
        self.logfile_user_activity = os.path.join(dir_name, 'user_activity.log')

        open(self.logfile_user_tokens, 'a').close()
        open(self.logfile_all_activity, 'a').close()
        open(self.logfile_user_activity, 'a').close()
        open(self.logfile_doc_tokens, 'a').close()

        # subprocess.call(['sh', 't.sh', self.logfile_doc_tokens,
        #     self.logfile_user_tokens, self.logfile_all_activity,
        #     self.logfile_user_activity])

        self.load_cfg()

        credentials = self.get_credentials()
        http = credentials.authorize(httplib2.Http())
        self.service = discovery.build('admin', 'reports_v1', http=http)

    def load_cfg(self):
        with open(self.cfg_file) as f:
            cfg = json.load(f)

        if 'document_tokens' not in cfg and 'user_tokens' not in cfg:
            raise Exception('No token configuration found')

        if 'document_tokens' in cfg:
            for document_token in cfg['document_tokens']:
                self.document_tokens[document_token['document_id']] = document_token['events']

        if 'user_tokens' in cfg:
            for user_token in cfg['user_tokens']:
                self.user_tokens[user_token['user_email']] = user_token['events']

        if 'logging' in cfg:
            if 'enabled' in cfg['logging']:
                try:
                    self.logging = bool(int(cfg['logging']['enabled']))
                except:
                    pass
        
        if 'syslog' in cfg:
            if 'enabled' in cfg['syslog']:
                try:
                    if bool(int(cfg['syslog']['enabled'])):
                        self.syslog_logger = logging.getLogger('rsyslog')
                        rsyslog_h = rsyslog_handler()
                        self.syslog_logger.addHandler(rsyslog_handler())
                        self.syslog_logger.setLevel(logging.INFO)
                except:
                    pass

    def get_credentials(self):
        """Gets valid user credentials from storage.

        If nothing has been stored, or if the stored credentials are invalid,
        the OAuth2 flow is completed to obtain the new credentials.

        Returns:
            Credentials, the obtained credential.
        """
        home_dir = os.path.expanduser('~')
        credential_dir = os.path.join(home_dir, '.credentials')
        if not os.path.exists(credential_dir):
            os.makedirs(credential_dir)
        credential_path = os.path.join(credential_dir,
                                       'admin-reports_v1-python-quickstart.json')
        store = Storage(credential_path)
        credentials = store.get()
        if not credentials or credentials.invalid:
            flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES,redirect_uri='urn:ietf:wg:oauth:2.0:oob')
            flow.user_agent = APPLICATION_NAME
            auth_uri = flow.step1_get_authorize_url()
            webbrowser.open(auth_uri)
            auth_code = raw_input('Enter the authentication code: ')
            credentials = flow.step2_exchange(auth_code)
            store.put(credentials)

        return credentials

    def start_event_loop(self):
        if not self.event_loop_thread:
            self.event_loop_thread = threading.Thread(target=self._event_loop)
            self.event_loop_thread.start()

    def stop_event_loop(self):
        if self.event_loop_thread:
            self.event_loop_thread.stop()

    def _event_loop(self):
        print("[*] Starting event loop...")
        start_time = datetime.utcnow()
        d = datetime.utcnow()
        d_with_timezone = d.replace(tzinfo=pytz.UTC)
        d = d_with_timezone.isoformat()

        self.build_user_basline()
        
        print("[*] Drivewatch Ready!")

        while True:
            results = self.service.activities().list(
                startTime=d, userKey='all', applicationName='drive').execute()
            activities = results.get('items', [])

            if activities:
                d = datetime.utcnow()
                d_with_timezone = d.replace(tzinfo=pytz.UTC)
                d = d_with_timezone.isoformat()

            for activity in activities:
                for event in activity['events']:
                    self.token_document(activity['actor']['email'], event)
                    self.token_user(activity['actor']['email'], event)
                    self.log_drive_events(activity)
                    self.user_view_counts(event, activity['actor']['email'], self.service)

            if (datetime.utcnow() - start_time) > timedelta(hours=24):
                self.build_user_basline()

            time.sleep(5)

    def build_user_basline(self):
        print("[*] Building user baseline...")
        tmp_user_view_map = {}
        def parse_activities(activities):
            for activity in activities:
                # get actor info
                is_view = False
                doc_id = None
                for event in activity['events']:
                    if (event['name'] == 'view'):
                        is_view = True
                    
                    for param in event['parameters']:
                        if param['name'] == 'doc_id':
                            doc_id = param['value']
                            break
                    
                    if doc_id and is_view:
                        break
                try:
                    actor = activity['actor']['email']
                    if is_view and actor:
                        dt = parse(activity['id']['time'])
                        key = "{actor},{date}".format(actor=actor, date=dt.strftime('%Y-%d-%m'))

                        if not tmp_user_view_map.get(key):
                            tmp_user_view_map[key] = []
                        
                        if not doc_id in  tmp_user_view_map[key]:
                            tmp_user_view_map[key].append(doc_id)
                except:
                    pass
                
        results = self.service.activities().list(
            userKey='all', applicationName='drive', maxResults=MAX_RESULTS).execute()
        activities = results.get('items', [])
        parse_activities(activities)

        next_page_token = results.get('nextPageToken', None)
        while next_page_token:
            results = self.service.activities().list(
                userKey='all', applicationName='drive', maxResults=MAX_RESULTS, pageToken=next_page_token).execute()
            activities = results.get('items', [])
            parse_activities(activities)

            next_page_token = results.get('nextPageToken', None)
        
        tmp_map = {}
        for key, value in tmp_user_view_map.iteritems():
            actor = key.split(',')[0]
            if not tmp_map.get(actor):
                tmp_map[actor] = []
            tmp_map[actor].append(len(value))
        
        for key, value in tmp_map.iteritems():
            tmp_map[key] = round(1.0 * sum(value)/len(value))
        
        self.user_baseline_map = tmp_map.copy()
        
    def token_document(self, actor, event):
        if self.document_tokens:
            owner_email = None
            for param in event['parameters']:
                if param['name'] == 'owner' and param['value'] in self.user_tokens:
                    owner_email = param['value']
                    break
            for param in event['parameters']:
                if param['name'] == 'doc_id' and \
                    (param['value'] in self.document_tokens and
                        event['name'] in self.document_tokens[param['value']]):
                    self.alert(TOKEN_ALERT, owner=owner_email, doc_id=param['value'], event_type=event['name'], actor=actor)

    def token_user(self, actor, event):
        if self.user_tokens:
            owner_email = None
            for param in event['parameters']:
                if param['name'] == 'owner' and param['value'] in self.user_tokens:
                    owner_email = param['value']
                    break
            for param in event['parameters']:
                if param['name'] == 'doc_id' and owner_email and \
                    event['name'] in self.user_tokens[owner_email]:
                    self.alert(USER_ALERT, actor=actor, owner=owner_email, doc_id=param['value'], event_type=event['name'])


    def log_drive_events(self, activity):
        if self.logging:
            print(activity)

    def user_view_counts(self, event, actor, service):
        if (event['name'] == 'view'):
            if actor in self.users_view_map:
                views_and_docs = self.users_view_map[actor]
                if (datetime.now() - views_and_docs[0]) > timedelta(hours=24):
                    self.users_view_map[actor] = (datetime.now(), [])
                    return

                old_time = views_and_docs[0]
                docs = views_and_docs[1]

                for param in event['parameters']:
                    if param['name'] == 'doc_id':
                        doc_id = param['value']
                        if not doc_id in docs:
                            docs.append(param['value'])

                self.users_view_map[actor] = (old_time, docs)

                num_docs_viewed = len(docs)
                if num_docs_viewed > VIEW_THRESHOLD:
                    start_time = datetime.utcnow() - timedelta(hours=24)
                    start_time_tz = start_time.replace(tzinfo=pytz.UTC)
                    start_time = start_time_tz.isoformat()
                    
                    results = service.activities().list(
                        startTime=start_time, userKey='all', applicationName='drive').execute()
                    activities = results.get('items', [])

                    self.alert(THRESHOLD_ALERT, actor=actor, num_docs_viewed=num_docs_viewed)
                    self.users_view_map[actor] = (datetime.now(), [])
                else:
                    actor_baseline = self.user_baseline_map.get(actor)
                    if actor_baseline and docs:
                        baseline = round(actor_baseline*BASELINE_PERCENT) + actor_baseline
                        if num_docs_viewed > baseline:
                            self.alert(BASELINE_ALERT, actor=actor, num_docs_viewed=num_docs_viewed, baseline=baseline)
            else:
                self.users_view_map[actor] = (datetime.now(), [])

    def alert(self, alert_type, owner=None, actor=None, num_docs_viewed=None, baseline=None, doc_id=None, event_type=None):
        alert_msg = None

        if alert_type == TOKEN_ALERT:
            alert_msg = "Token fired! {owner}'s document: {doc_id} had the event occur: {event_type} which was made by user: {actor}".format(
                owner=owner,
                actor=actor,
                doc_id=doc_id,
                event_type=event_type
            )
            # TODO write to log file?
        elif alert_type == USER_ALERT:
            # don't alert when user is doing stuff in his own drive
            if owner == actor:
                return

            alert_msg = "User token fired! {owner}'s document: {doc_id} had the event occur: {event_type} which was made by user: {actor}".format(
                owner=owner,
                actor=actor,
                doc_id=doc_id,
                event_type=event_type
            )
            # TODO write to log file?
        elif alert_type == BASELINE_ALERT:
            alert_msg = "Actor Baseline Exceeded! {actor}'s view activity was {num_docs_viewed} where baseline was {baseline}.".format(
                actor=actor,
                num_docs_viewed=num_docs_viewed,
                baseline=baseline
            )
            # TODO write to log file?
        elif alert_type == THRESHOLD_ALERT:
            alert_msg = "View Threshold Exceeded! {actor}'s view activity was {num_docs_viewed} where the threshold is {threshold}.".format(
                actor=actor,
                num_docs_viewed=num_docs_viewed,
                threshold=VIEW_THRESHOLD
            )
            # TODO write to log file?
        print(alert_msg)
        if self.syslog_logger:
            self.syslog_logger.critical(alert_msg)


class MySysLogHandler(logging.handlers.SysLogHandler):
    def __init__(self, *kwargs):
        from sys import platform
        address = '/dev/log'
        if platform == "darwin":
            address = '/var/run/syslog'

        super(MySysLogHandler, self).__init__(address=address, facility=logging.handlers.SysLogHandler.LOG_LOCAL0)

    def emit(self, record):
        priority = self.encodePriority(self.facility, self.mapPriority(record.levelname))
        record.ident = "drivewatch:"
        super(MySysLogHandler, self).emit(record)

def rsyslog_handler():
    handler = MySysLogHandler()
    handler.formatter = logging.Formatter(fmt="%(ident)s %(levelname)s: %(message)s")
    return handler

if __name__ == '__main__':
    print("[*] Starting Drivewatch...")
    if len(sys.argv) >= 2:
        g = GSuiteTokens(sys.argv[1])
    else:
        g = GSuiteTokens()
    g.start_event_loop()
