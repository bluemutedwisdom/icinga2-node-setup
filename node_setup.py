#!/usr/bin/env python
import os
import pwd
import grp
import errno
import argparse
import json
import sys
import logging
from subprocess import call
import requests

requests.packages.urllib3.disable_warnings()

CERT_DIR = '/var/lib/icinga2/certs'
OWNER = 'icinga'
GROUP = 'icinga'
ZONE_FILE = '/etc/icinga2/zones.conf'
HEADERS = {'Accept': 'application/json'}
LOG_FILE = '/var/log/icinga2_api_config.log'


def args_check(args=None):
    parser = \
        argparse.ArgumentParser(description='Register Host to the Icinga2')

    parser.add_argument('--master',
                        help='Resolvable fqdn of the master',
                        required=False, action='store_true')
    parser.add_argument('--client',
                        help='Resolvable fqdn of the client',
                        required=False, action='store_true')
    parser.add_argument('--master-host',
                        help='Icinga2 master host to establish connection with',
                        required=False, default='')
    parser.add_argument('--port',
                        help='The port the master is connectable on',
                        required=False, default='')
    parser.add_argument('--client-host',
                        help='Configured client host name',
                        required=False, default='')
    parser.add_argument('--api-user',
                        help='API Request user',
                        required=False, default='')
    parser.add_argument('--api-password',
                        help='API Request user key',
                        required=False, default='')
    parser.add_argument('--enable-global',
                        help='Enables global templates configuration',
                        required=False, action='store_true')
    parser.add_argument('--disable-checker',
                        help='Disables checker Icinga2 feature',
                        required=False, action='store_true')
    parser.add_argument('--disable-confd',
                        help='Disables conf.d directory',
                        required=False, action='store_true')
    results = parser.parse_args(args)
    return (results.master,
            results.client,
            results.satelite,
            results.master_host,
            results.port,
            results.client_host,
            results.api_user,
            results.api_key,
            results.enable_global,
            results.disable_checker,
            results.disable_confd)


def create_dir(path):
    """
        Check if folder exist, if not create it
    """
    if not os.path.exists(path):
        try:
            os.makedirs(path)
        except OSError as err:
            if err.errno != errno.EEXIST:
                logging.critical("Failed to create directory. Error:\n{0}".format(err))
                raise


def chown(path, owner, group):
    """
        Change file/directory ownership
    """
    uid = pwd.getpwnam(owner).pw_uid
    gid = grp.getgrnam(group).gr_gid
    os.chown(path, uid, gid)


def restart_icinga():
    """
        Restarts Icinga2 daemon
    """
    command = ["service", "icinga2", "restart"]
    try:
        call(command, shell=False)
        logging.info("Icinga2 daemon restarted")
    except Exception as err:
        logging.critical("Failed to restart Icinga2 daemon. Error: \n{0}".format(err))


def enable_global_templates(path):
    """
        Configure global templates usage
    """
    conf = '\nobject Zone "global-templates" {\n\tglobal = true\n}'
    with open(path, "a") as zonefile:
        zonefile.write(conf)


def disable_checker_feature():
    """
        Disable Icinga2 checker feature.
        If this client node is configured as remote command endpoint
        execution you can safely disable the checker feature.
    """
    command = ["/usr/bin/icinga2", "feature", "disable", "checker"]
    try:
        call(command, shell=False)
        logging.info("checker feature disabled")
    except Exception as err:
        logging.critical("Failed to disable cherker feature. Error: \n{0}".format(err))


def disable_confd():
    """
      Disable “conf.d” inclusion if this is a top down configured client.
    """
    command = [
        "sed", "-i",
        "'s/include_recursive \"conf.d\"/\/\/include_recursive \"conf.d\"/g'",
        "/etc/icinga2/icinga2.conf"]
    try:
        call(command, shell=False)
        logging.info("Disabled conf.d")
    except Exception as err:
        logging.critical("Failed to disable conf.d. Error: \n{0}".format(err))


def get_ticket(master, port, user, key, fqdn):
    """
        Get ticket hash generated on Icinga2 master for current host
    """
    gen_ticket_url = "https://{0}:{1}/v1/actions/generate-ticket".format(master,
                                                                         port)
    payload = {"cn": fqdn}
    data = json.dumps(payload)
    response = requests.post(
        gen_ticket_url,
        headers=HEADERS,
        data=data,
        auth=(user, key),
        verify=False
    )
    data = response.json()
    results = data['results']
    ticket = ''
    for result in results:
        try:
            logging.info("Getting ticket from Icinga2 master: {0}".format(master))
            ticket = result['ticket']
        except KeyError:
            logging.critical("Failed to get ticket. Response from Icinga2 \
                             master: {}".format(results))
            # Exit script
            raise
    return ticket


def configure_master():
    """
    Configure host in 'master' mode
    """
    # Configureation command
    node_setup_command = ["/usr/bin/icinga2", "node", "setup", "--master"]
    try:
        call(node_setup_command, shell=False)
        logging.info("Host successfully promoted to master")
    except Exception as err:
        logging.critical("Failed to promote. Error: \n{0}".format(err))


def configure_client(master_host, master_ip, port, client_host, ticket):
    """
        Register Host as an Icinga2 client
    """
    client_key_location = "{0}/{1}.key".format(CERT_DIR, client_host)
    client_crt_location = "{0}/{1}.crt".format(CERT_DIR, client_host)
    trusted_crt_location = "{0}/trusted-master.crt".format(CERT_DIR)
    ca_location = "{0}/ca.key".format(CERT_DIR)

    # Logging
    logging.info("In case of failure check following directories/files")

    logging.info("Client key: {1}".format(client_key_location))

    logging.info("Client certificate: {1}".format(client_crt_location))

    logging.info("Trusted certificate: {1}".format(trusted_crt_location))

    logging.info("FQDN CA certificate: {1}".format(ca_location))
    # Configuration commands
    new_cert_command = [
        '/usr/sbin/icinga2',
        'pki', 'new-cert', '--cn', client_host, '--key',
        client_key_location, '--cert', client_crt_location
    ]
    save_cert_command = [
        '/usr/sbin/icinga2',
        'pki', 'save-cert', '--key', client_key_location,
        '--cert', client_crt_location, '--trustedcert',
        trusted_crt_location, '--host', master_host
    ]
    request_command = [
        '/usr/sbin/icinga2',
        'pki', 'request', '--host', master_host, '--port',
        port, '--ticket', ticket, '--key', client_key_location,
        '--cert', client_crt_location, '--trustedcert',
        trusted_crt_location, '--ca', ca_location
    ]
    endpoint = "{0},{1},{2}".format(master_host, master_ip, port)
    node_setup_command = [
        '/usr/sbin/icinga2',
        'node', 'setup', '--ticket', ticket, '--endpoint',
        master_host, '--zone', client_host, '--master_host', master_host,
        '--trustedcert', trusted_crt_location, '--accept-commands',
        '--accept-config', '--endpoint', endpoint
    ]
    try:
        call(new_cert_command, shell=False)
        call(request_command, shell=False)
        call(save_cert_command, shell=False)
        call(node_setup_command, shell=False)
    except Exception as e:
        logging.critical("Failed to promote. Error: \n{0}".format(e))


if __name__ == '__main__':
    (MASTER,
     CLIENT,
     MASTER_HOST,
     PORT,
     CLIENT_HOST,
     API_USER,
     API_PASSWORD,
     ENABLE_GLOBAL,
     DISABLE_CHECKER,
     DISABLE_CONFD) = args_check(sys.argv[1:])
    # Enable logging
    logging.basicConfig(format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filename=LOG_FILE, filemode="w", level=logging.DEBUG)

    if MASTER:
        configure_master()

    elif CLIENT:
        # Ensure certificate directory exists
        create_dir(CERT_DIR)
        # Ensure correct ownership
        chown(CERT_DIR, OWNER, GROUP)
        # Get ticket generated for curret host on Icinga2 Master
        ticket = get_ticket(MASTER_HOST,
                            PORT,
                            API_USER,
                            API_PASSWORD,
                            CLIENT_HOST)
        # Register client
        configure_client(MASTER_HOST,
                         PORT,
                         CLIENT_HOST,
                         ticket)
        if ENABLE_GLOBAL:
            enable_global_templates(ZONE_FILE)
        if DISABLE_CHECKER:
            disable_checker_feature()
        if DISABLE_CONFD:
            disable_confd()
