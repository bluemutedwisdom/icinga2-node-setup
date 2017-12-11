#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Small utility to auto-configure Icinga2 node (master/satelite/client) and
establish API connection
"""
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
PORT = '5665'
ZONE_FILE = '/etc/icinga2/zones.conf'
API_USER_FILE = '/etc/icinga2/conf.d/api-debug-user.conf'
HEADERS = {'Accept': 'application/json'}
LOG_FILE = '/var/log/icinga2_api_config.log'


def args_check(args=None):
    """
        Parse input arguments
    """
    description = """ Small utility to auto-configure Icinga2 node
     (master/satelite/client) and establish API connection
    """
    parser = \
        argparse.ArgumentParser(description=description)

    subparsers = parser.add_subparsers(help='sub-command help')

    master_parser = subparsers.add_parser('setup_master', help='b help')
    master_parser.set_defaults(mode='master')
    api_listener_help = """ Bind the ApiListener object to a specific
     host/port. Format: <address>,<port>
    """
    master_parser.add_argument('--api-listener', help=api_listener_help)

    client_parser = subparsers.add_parser('setup_client', help='client help')
    client_parser.set_defaults(mode='client')
    master_host_help = " Icinga2 master host to establish connection with "
    client_parser.add_argument('--master-host',
                               help=master_host_help,
                               required=True, default='')
    client_parser.add_argument('--port',
                               help='The port the master is connectable on',
                               required=False, default='')
    common_name_help = """Configured client common name. By convention this
     should be the host’s FQDN"""
    client_parser.add_argument('--common-name',
                               help=common_name_help,
                               required=True, default='')
    client_parser.add_argument('--api-user',
                               help='API Request user',
                               required=True, default='')
    client_parser.add_argument('--api-password',
                               help='API Request user key',
                               required=True, default='')
    endpoint_help = """If client should connect to the master node, use
     following format: <master-host>,<master-address>,<port>"""
    client_parser.add_argument('--endpoint',
                               help=endpoint_help,
                               required=True, default='')
    client_parser.add_argument('--enable-global',
                               help='Enables global templates configuration',
                               required=False, action='store_true')
    client_parser.add_argument('--disable-checker',
                               help='Disables checker Icinga2 feature',
                               required=False, action='store_true')
    client_parser.add_argument('--disable-confd',
                               help='Disables conf.d directory',
                               required=False, action='store_true')
    client_parser.add_argument('--add-debug-api',
                               help='Add api debug user for the client',
                               required=False, action='store_true')
    client_parser.add_argument('--debug-user-pass',
                               help='Debug user password',
                               required=False, default='')

    results = parser.parse_args(args)
    return results


def create_dir(path):
    """
        Check if folder exist, if not create it
    """
    if not os.path.exists(path):
        try:
            os.makedirs(path)
        except OSError as err:
            if err.errno != errno.EEXIST:
                msg = "Failed to create directory. Error:\n{0}".format(err)
                logging.critical(msg)
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
        msg = "Failed to restart Icinga2 daemon. Error: \n{0}".format(err)
        logging.critical(msg)
        raise


def enable_global_templates(path):
    """
        Configure global templates usage
    """
    conf = """
    object Zone "global-templates" {
        global = true
    }"""
    with open(path, "a") as zonefile:
        zonefile.write(conf)
        zonefile.close()


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
        msg = "Failed to disable cherker feature. Error: \n{0}".format(err)
        logging.critical(msg)
        raise


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
        raise


def configure_api_debug_user(path, password):
    """
        Configures api user for remote debugging
    """
    conf = """
    object ApiUser "root" {
        password = "{0}"
        permissions = ["*"]
    }
    """.format(password)
    with open(path, "a+") as api_user_file:
        api_user_file.write(conf)
        api_user_file.close()


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
            msg = "Getting ticket from Icinga2 master: {0}".format(master)
            logging.info(msg)
            ticket = result['ticket']
        except KeyError:
            msg = "Failed to get ticket. Response from Icinga2 \
                             master: {0}".format(results)
            logging.critical(msg)
            # Exit script
            raise
    return ticket


def configure_master(api_listener):
    """
    Configure host in 'master' mode
    """
    # Configureation command
    node_setup_command = ["/usr/bin/icinga2", "node", "setup", "--master"]
    if api_listener:
        node_setup_command.extend(["--listener", api_listener])
    try:
        call(node_setup_command, shell=False)
        logging.info("Host successfully promoted to master")
    except Exception as err:
        msg = "Failed to promote to master. Error: \n{0}".format(err)
        logging.critical(msg)
        raise


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
    except Exception as err:
        logging.critical("Failed to promote. Error: \n{0}".format(err))
        raise


if __name__ == '__main__':
    # Setup logging
    logging.basicConfig(format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filename=LOG_FILE, filemode="w", level=logging.DEBUG)
    args = args_check(sys.argv[1:])
    if args.mode == 'master':
        configure_master(args.api_listener)
    elif args.mode == 'client':
        create_dir(CERT_DIR)
        chown(CERT_DIR, OWNER, GROUP)
        port = PORT
        if args.port:
            port = args.port
        # Request registry ticket
        ticket = get_ticket(args.master_host,
                            port,
                            args.api_user,
                            args.api_password,
                            args.common_name)
        # Register client
        configure_client(args.master_host,
                         args.port,
                         args.common_name,
                         ticket)

        if args.enable_global:
            enable_global_templates(ZONE_FILE)
        if args.disable_checker:
            disable_checker_feature()
        if args.disable_confd:
            disable_confd()
        if args.add_debug_api:
            configure_api_debug_user(args.debug_user_pass)
