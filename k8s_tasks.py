#!/usr/bin/env python3

import argparse
import configparser
import errno
import fileinput
import logging
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.request
import yaml
from subprocess import SubprocessError
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('k8s-task')

slack_url = 'https://hooks.slack.com/services/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'
slack_user = 'k8s_bot'
SLACK_API_TOKEN = 'xoxb-2153099799-876628273173-ZCJ5YjmuvIuqlVloZLHyyLPT'

k8s_prod_cluster = 'arn:aws:eks:us-east-1:212771862516:cluster/general'
k8s_dev_cluster = 'arn:aws:eks:us-east-1:332620600903:cluster/general'

def _get_uid_from_ldap(email: str) -> str:
    """Returns user ID for specific email."""

    from ldap3 import Server, Connection
    server = Server('ldap://ldap0.tubular')
    conn = Connection(server, auto_bind=True)
    found = conn.search(
        'dc=tubularlabs,dc=net',
        '(mail={})'.format(email),
        attributes=['uid']
    )
    if not found:
        logger.debug('Email %s does not exist in LDAP, did you enter it correctly?', email)
        return None
    else:
        try:
            entry = conn.entries[0]
            username = entry.uid.values[0]
        except IndexError:
            logger.exception('Something went wrong getting username from LDAP')
            username = None
    return username


def _get_email_from_gitconfig() -> str:
    """Returns user email from gitconfig file."""

    conf = configparser.ConfigParser()
    conf.read(os.path.expanduser('~/.gitconfig'))
    email = conf['user'].get('email', '')
    logger.debug('Found user email in gitconfig: %s', email)
    return email


class User:

    def __init__(self, uid, email):
        self.uid = uid
        self.email = email

        self.slack_username, self.slack_id = self._get_slack_user()

        if self.slack_username and self.slack_id:
            self._save_slack_info()

    def __str__(self):
        return self.uid

    @property
    def slack_encoded(self):
        if self.slack_id:
            return '<@{}>'.format(self.slack_id)
        else:
            return self.uid  # old (existing) behaviour

    def _save_slack_info(self):
        path = pathlib.Path('~/.k8sconfig')
        path = path.expanduser()
        conf = configparser.ConfigParser()

        if path.is_file():
            conf.read(str(path.absolute()))

            if 'slack_id' in conf['user'] and 'slack_username' in conf['user']:
                logger.debug('Slack id and username already in k8sconfig, noop')
                return

        if 'user' not in conf:
            conf['user'] = {}

        conf['user']['slack_username'] = self.slack_username
        conf['user']['slack_id'] = self.slack_id
        with path.open('w') as fd:
            conf.write(fd)
            logger.debug('Saved slack id and username for future use')

    def _get_slack_user(self):
        path = pathlib.Path('~/.k8sconfig')
        path = path.expanduser()
        conf = configparser.ConfigParser()

        if path.is_file():
            conf.read(str(path.absolute()))

            if 'slack_id' in conf['user'] and 'slack_username' in conf['user']:
                return conf['user']['slack_username'], conf['user']['slack_id']

        from slacker import Slacker
        slack = Slacker(SLACK_API_TOKEN)
        response = slack.users.list()
        users = response.body['members']
        slack_email = ''
        for user in users:
            try:
                slack_email = user['profile']['email']
            except KeyError:
                pass
            if self.email == slack_email:
                return user['name'], user['id']
        return None, None


def get_user() -> str:
    """Returns username."""

    username = None
    email = _get_email_from_gitconfig()
    if email:
        username = _get_uid_from_ldap(email)

    # some users use @gmail.com address which we don't know about,
    # try getting from user input
    if not username:
        email = input('Enter your tubularlabs email: ')
        username = _get_uid_from_ldap(email)

    username = username or os.getlogin()  # final fallback is shell login
    user = User(uid=username, email=email)
    logger.info('You are identified as: %s', user)
    return user


def slack_post(message: str):
    """Posts messages to slack."""

    data = urllib.parse.urlencode({'payload': {'username': slack_user, 'text': message}}).encode("utf-8")
    resp = urllib.request.urlopen(urllib.request.Request(slack_url, data))


def git_add(path):
    try:
        subprocess.check_call(['git', 'add', path])
    except SubprocessError:
        logger.error('git add failed')
        raise


def git_commit(message):
    try:
        subprocess.check_call(['git', 'commit', '--no-verify', '-m', message])
    except SubprocessError:
        logger.error('git commit failed')
        raise


def git_pull(rebase=False):
    try:
        if rebase:
            subprocess.check_call(['git', 'pull', '--rebase'])
        else:
            subprocess.check_call(['git', 'pull'])
    except SubprocessError:
        logger.error('git pull failed')
        raise


def git_push(origin):
    try:
        subprocess.check_call(['git', 'push', 'origin', origin])
    except SubprocessError:
        logger.error('git push failed')
        raise


def git_process(path: str, message: str):
    """Executes git commands on the current branch."""

    branch = subprocess.check_output(
        ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
        stderr=subprocess.STDOUT,
        universal_newlines=True
    ).strip()
    git_add(path)
    git_commit(message)
    git_push(branch)


def _get_task_full_name(task: str) -> str:
    """Returns task name as it is in k8s."""

    with open(task, 'r') as task_config:
        for line in task_config:
            re_env = re.match(r'(^  env: )(prod|stage|dev)', line.rstrip())
            if re_env:
                env = re_env.group(2)
            re_app = re.match(r'(^  app_name: )(.*)', line.rstrip())
            if re_app:
                app = re_app.group(2)
            re_group = re.match(r'(^      group: )(.*)', line.rstrip())
            if re_group:
                group = re_group.group(2)
            re_task = re.match(r'(^    - name: )(.*)', line.rstrip())
            if re_task:
                task = re_task.group(2)
    task_full_name = env + '-' + app + '-' + group + '-' + task
    return task_full_name


def _get_tasks(path: str, kind: str, state: str) -> list:
    """
    Returns list of task according to provided state and kind.

    Parameters:
        kind (str): type of task (['service'|'cronjob'|'any']).
        state (str): state of task (['enabled'|'disabled'|'any']).

    Returns:
        list: list of tasks.
    """

    tasks_filtered_by_state = []
    tasks = []
    tree = os.walk(path)
    for wd, dirs, files in tree:
        for f in files:
            if state == 'enabled':
                if re.search(r'\.values\.yaml$', f) is not None:
                    task = wd + '/' + f
                    tasks_filtered_by_state.append(task)
            elif state == 'disabled':
                if re.search(r'\.values\.yaml_disabled$', f) is not None:
                    task = wd + '/' + f
                    tasks_filtered_by_state.append(task)
            elif state == 'any':
                if re.search(r'\.values\.yaml', f) is not None:
                    task = wd + '/' + f
                    tasks_filtered_by_state.append(task)

    # Yujin: there is no a good way to determine a kind of a task,
    # so we check if there is a schedule specified
    for task in tasks_filtered_by_state:
        if kind == 'cronjob':
            with open(task) as task_config:
                if re.search(
                        r'      schedule: [\'\"]?[\d\*\s/]{9,}[\'\"]?', task_config.read()
                ) is not None:
                    tasks.append(task)
        elif kind == 'service':
            with open(task) as task_config:
                if re.search(
                        r'      schedule: \'?[\d\*\s/]{9,}\'?', task_config.read()
                ) is not None:
                    tasks.append(task)
        elif kind == 'any':
            tasks.append(task)

    return tasks


def _check_kubectl(cluster: str):
    """Different checks to make sure kubectl commands can be run."""

    if cluster == 'prod':
        context = k8s_prod_cluster
    elif cluster == 'dev':
        context = k8s_dev_cluster

    try:
        subprocess.check_call(
            ['kubectl', 'config', 'use-context', context],
            stderr=subprocess.STDOUT
        )
    except OSError as e:
        if e.errno == errno.ENOENT:
            logger.error('please, install kubectl binary first.\n')
            sys.exit(1)
        else:
            raise
    except subprocess.CalledProcessError as e:
        if 'error: no context exists with the name' in e.output:
            logger.error(
                'please, configure kubectl first.\n'
                'more info at https://tubularlabs.atlassian.net/wiki/spaces/EN/pages/'
                '797704229/Kubernetes#Kubernetes-SetuptostartworkingwithKubernetes.'
            )
            sys.exit(1)
        else:
            raise

    try:
        k_version_out = subprocess.check_output(
            ['kubectl', 'version', '--output', 'yaml'],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        ).strip()
    except subprocess.CalledProcessError as e:
        if 'error: Unable to connect to the server' in e.output:
            logger.error('please, check that you are conncted to VPN.')
        elif 'error: You must be logged in to the server' in e.output:
            logger.error(
                'please login to AWS first.\n'
                'more info at https://tubularlabs.atlassian.net/wiki/spaces/EN/pages/'
                '571998243/TB+CLI#TBCLI-Okta-basedtemporaryAWScredentials.'
            )
            sys.exit(1)
        else:
            raise

    k_version_yaml = yaml.load(k_version_out, Loader=yaml.BaseLoader)
    k_client_version = k_version_yaml['clientVersion']['major'] + '.'\
                       + k_version_yaml['clientVersion']['minor']
    k_server_version = k_version_yaml['serverVersion']['major'] + '.'\
                       + k_version_yaml['serverVersion']['minor']

    if k_client_version != k_server_version:
        logger.error(
           'client and server version mismatch.\n'
           'server version is: {}.\n'.format(k_server_version),
           'client version is: {}.'.format(k_client_version))
        sys.exit(1)


def disable_task():
    """Disables task by renaming helm values file with suffix '_disabled'."""

    git_pull(rebase=True)
    path = args.path.strip('/.')
    tasks = _get_tasks(path, kind='any', state='enabled')
    if tasks:
        for task in tasks:
            task_disabled = task+ '_disabled'
            os.rename(task, task_disabled)
            git_add(task)
            git_add(task_disabled)
            user = get_user()
            print(user)
            message = '{} disabled task(s) {}'.format(user.slack_encoded, task)
            if args.message:
                message = '{} - {}'.format(message, args.message)
            slack_post(message)

        logging.info('committing task(s) changes to repo.')
        git_process(path, 'Removed task(s) {}'.format(path))
    else:
        logger.info('there are not tasks to be disabled.')


def enable_task():
    """Enables task by removing suffix '_disabled' for helm values file."""

    git_pull(rebase=True)
    path = args.path.strip('/.')
    tasks = _get_tasks(path, kind='any', state='disabled')
    if tasks:
        for task in tasks:
            task_enabled = re.sub(r'_disabled$', '', task)
            os.rename(task, task_enabled)
            git_add(task)
            git_add(task_enabled)
            user = get_user()
            message = '{} enabled task(s) {}'.format(user.slack_encoded, task)
            if args.message:
                message = '{} - {}'.format(message, args.message)
            slack_post(message)

        logging.iinfo('committing task(s) changes to repo.')
        git_process(path, 'Deployed task(s) {}'.format(path))
    else:
        logger.info('there are no tasks for enableing.')


def update_image_tag():
    """Updates image tag."""

    git_pull(rebase=True)
    path = args.path.strip('/.')
    tag= args.tag
    tasks = _get_tasks(path, kind='any', state='any')
    if tasks:
        for task in tasks:
            task_config = fileinput.FileInput(task, inplace=True)
            for line in task_config:
                line = re.sub(
                    r'(^    tag: )[0-9.]+$', r'\g<1>{}'.format(tag), line.rstrip()
                )
                print(line)
            git_add(task)
            user = get_user()
            message = '{} updated tag for task(s) {}'.format(user.slack_encoded, task)
            if args.message:
                message = '{} - {}'.format(message, args.message)
            slack_post(message)

        logging.info('committing task(s) changes to repo.')
        git_process(path, 'Updated tag for task(s) tasks {}'.format(path))
    else:
        logger.info('there are no tasks for tag updatingi.')


def kill_task():
    """Kill running task."""

    cluster = args.cluster
    _check_kubectl(cluster)
    path = args.path.strip('/.')
    tasks = _get_tasks(path, kind='cronjob', state='enabled')
    for task in tasks:
        task_full_name = _get_task_full_name(task)
        try:
            ps = subprocess.Popen(
                #['kubectl', 'get', 'jobs', '-n', 'tubular-services', '--no-headers', '|', 'awk', '\'/{}/{{print'.format(task_full_name), '$1}\'', '|', 'xargs', 'kubectl', '-n', 'tubular-services', 'delete', 'job']
                    ('kubectl', 'get', 'jobs', '-n', 'tubular-services', '--no-headers'),
                    stdout=subprocess.PIPE
                 )
            ps = subprocess.Popen(
                    ('awk', '/{}/{{print $1}}'.format(task_full_name)),
                    stdin=ps.stdout, stdout=subprocess.PIPE
                )
            subprocess.check_call(
                ['xargs', 'kubectl', '-n', 'tubular-services', 'delete', 'job'],
                stdin=ps.stdout
            )
        except subprocess.CalledProcessError as e:
            logger.error('Killing of job(s) %s failed %s', task, e)
        else:
            user = get_user()
            message = '{} killed task(s) {}'.format(user.slack_encoded, task)
            if args.message:
                message = '{} - {}'.format(message, args.message)
            slack_post(message)


def run_task():
    """Force task run. """

    cluster = args.cluster
    _check_kubectl(cluster)
    path = args.path.strip('/.')
    tasks = _get_tasks(path, kind='cronjob', state='enabled')
    for task in tasks:
        task_full_name = _get_task_full_name(task)
        try:
            subprocess.check_call(
                ['kubectl', 'create', 'job', '--from=cronjob/{}'.format(task_full_name),
                 '{}-{}'.format(task_full_name, int(time.time()))]
            )
        except subprocess.CalledProcessError as e:
            logger.error('Run of job(s) %s failed', task)
        else:
            user = get_user()
            message = '{} killed task(s) {}'.format(user.slack_encoded, task)
            if args.message:
                message = '{} - {}'.format(message, args.message)
            slack_post(message)


parser = argparse.ArgumentParser(description='Run ./%(prog)s help to start')
parser.add_argument('--log-level', help='Logging level', default='info')

subparsers = parser.add_subparsers(help='list of commands',
                                   metavar='{enable, disable, update_image_tag, kill, run}')

# enable parser
enable_parser = subparsers.add_parser('enable', help='enable new task')
enable_parser.add_argument('path', action='store', help='path to task')
enable_parser.add_argument('-m', '--message', action='store', help='optional commit message')
enable_parser.set_defaults(function=enable_task)

# disable task
disable_parser = subparsers.add_parser('disable', help='disable existing task')
disable_parser.add_argument('path', action='store', help='path to task')
disable_parser.add_argument('-m', '--message', action='store', help='optional commit message')
disable_parser.set_defaults(function=disable_task)

# update docker tag
update_image_tag_parser = subparsers.add_parser('update_image_tag', help='update docker tag for task')
update_image_tag_parser.add_argument('tag', action='store', default='',
                                      help='sets docker image tag to specified version')
update_image_tag_parser.add_argument('path', action='store', help='path to task')
update_image_tag_parser.add_argument('-m', '--message', action='store', help='optional action message')
update_image_tag_parser.set_defaults(function=update_image_tag)

# kill task
kill_parser = subparsers.add_parser('kill', help='kill existing task (cronjob only)')
kill_parser.add_argument('cluster', action='store', help='cluster to work with')
kill_parser.add_argument('path', action='store', help='path to task')
kill_parser.add_argument('-m', '--message', action='store', help='optional commit message')
kill_parser.set_defaults(function=kill_task)

# run task
run_parser = subparsers.add_parser('run', help='run existing task (cronjob only)')
run_parser.add_argument('cluster', action='store', help='cluster to work with')
run_parser.add_argument('path', action='store', help='path to task')
run_parser.add_argument('-m', '--message', action='store', help='optional commit message')
run_parser.set_defaults(function=run_task)

# parser initialization
try:
    args = parser.parse_args()

    # setup logging
    root_logger = logging.getLogger()
    root_logger.setLevel(args.log_level.upper())

    # call subparser function
    args.function()

except AttributeError:
    parser.print_help()
    sys.exit(1)
