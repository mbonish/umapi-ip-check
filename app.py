import logging
import subprocess
import time
from datetime import datetime
from os.path import exists

import dns.resolver
import umapi_client
import yaml
from python_hosts import Hosts, HostsEntry

logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger()
hosts = Hosts(path='C:\Windows\System32\drivers\etc\hosts')
umapi = 'connector-umapi-stage.yml'
check_umapi = exists(umapi)


class Endpoint():
    def __init__(self, address, created=None, last_ping=None, host=None, alive=None, **kwargs):
        self.address = address
        self.created = date_parse(created) if created else datetime.now()
        self.last_ping = date_parse(last_ping) if last_ping else self.created
        self.host = host
        self.alive = alive or True

    def to_string(self):
        data = vars(self).copy()
        data['created'] = date_fmt(self.created)
        data['last_ping'] = date_fmt(self.last_ping)
        data['age'] = str(self.last_ping - self.created)
        return data


def date_fmt(date):
    return date.strftime('%Y/%m/%d %H:%M:%S')


def date_parse(date):
    return datetime.strptime(date, '%Y/%m/%d %H:%M:%S')


def get_connection(auth_dict, ims_host, host, ssl_verify=True, **kwargs):
    try:
        return umapi_client.Connection(
            org_id=auth_dict['org_id'],
            auth_dict=auth_dict,
            ims_host=ims_host,
            user_management_endpoint="https://{}/v2/usermanagement".format(host),
            user_agent="endpoint-tester",
            logger=logger,
            timeout_seconds=5,
            retry_max_attempts=1,
            ssl_verify=ssl_verify
        )
    except Exception as e:
        raise AssertionError("Connection failed: " + str(e))


def check_address(ip, connection, host, check_user):
    new_entry = HostsEntry(entry_type='ipv4', address=ip, names=[host])
    hosts.add([new_entry], force=True)
    hosts.write()
    subprocess.check_output('ipconfig /flushdns')
    time.sleep(2)
    try:
        return umapi_client.UserQuery(connection, check_user).result().get('email') == check_user
    except umapi_client.UnavailableError as e:
        if "Too many requests" in e.result.text:
            return True
        return False


def main():
    conn = None
    if check_umapi:
        with open(umapi) as f:
            um_opts = yaml.safe_load(f)
            auth_dict = um_opts['enterprise']
            server = um_opts['server']
            host = server['host']
            check_user = server['check_user_email']
        conn = get_connection(auth_dict, **server)

    else:
        logger.info("No umapi configuration for {}... skipping umapi checks".format(umapi))
        host = 'usermanagement.adobe.io'

    addresses = {}
    filename = 'ip-{}.yml'.format(host)
    logger.info("Using host: {}".format(host))
    logger.info("Using file: {}".format(filename))

    if exists(filename):
        with open(filename) as f:
            for a, e in yaml.safe_load(f).items():
                addresses[a] = Endpoint(**e)

    while True:
        for ip in [e.to_text() for e in dns.resolver.query(host, 'A')]:
            if ip in addresses:
                addresses[ip].last_ping = datetime.now()
                addresses[ip].alive = True
            else:
                addresses[ip] = Endpoint(ip, host=host)

        logger.info('Total collected: ' + str(len(addresses)))
        logger.info('Total alive: ' + str(len([e for a, e in addresses.items() if e.alive is True])))
        logger.info('Total dead: ' + str(len([e for a, e in addresses.items() if e.alive is False])))

        if conn:
            for a, e in addresses.items():
                e.alive = check_address(a, conn, host, check_user)
                status = "alive!" if e.alive else 'dead :('
                logger.info("Checked {0}: {1} -> {2}".format(a, host, status))

        with open(filename, 'w') as f:
            yaml.dump({a: e.to_string() for a, e in addresses.items()}, f)

        time.sleep(120)


if __name__ == '__main__':
    main()
