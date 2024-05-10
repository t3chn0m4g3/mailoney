__author__ = '@awhitehatter'
__version__ = '0.2'
__author__ = "@referefref"
'''
SMTP Honeypot implemented in Python with extensible modules, HPFeeds and file logging.
'''

import argparse
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
import subprocess

import modules.postfix_creds
import modules.open_relay
import modules.schizo_open_relay

logger = logging.getLogger('Mailoney')
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(filename='./logs/mailoney.log', maxBytes=10240, backupCount=3)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def parse_args():
    parser = argparse.ArgumentParser(description="Configure the SMTP Honeypot settings")
    parser.add_argument('-i', '--ip', default='0.0.0.0', help='IP address to listen on')
    parser.add_argument('-p', '--port', type=int, default=25, help='Port to listen on')
    parser.add_argument('-s', '--servername', required=True, help='The name that will show up as the mail server name.')
    parser.add_argument('-t', '--type', choices=['open_relay', 'postfix_creds', 'schizo_open_relay'], required=True, help='Type of honeypot to deploy')
    parser.add_argument('-logpath',action='store', metavar='<logpath>',  default=os.environ.get('LOGPATH'), help='path for file logging')
    parser.add_argument('-hpfserver', action='store', metavar='<hpfeeds-server>', default=os.environ.get('HPFEEDS_SERVER', None), help='HPFeeds Server')
    parser.add_argument('-hpfport', action='store', metavar='<hpfeeds-port>', default=os.environ.get('HPFEEDS_PORT', None), help='HPFeeds Port')
    parser.add_argument('-hpfident', action='store', metavar='<hpfeeds-ident>', default=os.environ.get('HPFEEDS_IDENT', None), help='HPFeeds Username')
    parser.add_argument('-hpfsecret', action='store', metavar='<hpfeeds-secret>', default=os.environ.get('HPFEEDS_SECRET', None), help='HPFeeds Secret')
    parser.add_argument('-hpfchannelprefix', action='store', metavar='<hpfeeds-channel-prefix>', default=os.environ.get('HPFEEDS_CHANNELPREFIX', None), help='HPFeeds Channel Prefix')
    
    excopt = parser.add_argument_group('- Run time options')
    runopt = excopt.add_mutually_exclusive_group(required=True)
    runopt.add_argument('-D', '--debug', help='Run in the foreground', action='store_true')
    runopt.add_argument('-B', '--daemon', help='Daemonize the process', action='store_true')
    
    return parser.parse_args()

def connect_hpfeeds(server, port, ident, secret):
    try:
        import hpfeeds
        hpc = hpfeeds.new(server, port, ident, secret)
        logger.info('Connected to HPFeeds server successfully.')
        return hpc
    except Exception as e:
        logger.error('Failed to connect to HPFeeds server: %s', str(e))
        return None

def main():
    args = parse_args()

    if not os.path.isdir(args.logpath):
        os.makedirs(args.logpath)

    logger.info('Mailoney SMTP Honeypot started. Listening on IP: %s, Port: %d', args.ip, args.port)

    # Setup HPFeeds if credentials are provided and all required are non-null
    hpc = None
    if all([args.hpfserver, args.hpfport, args.hpfident, args.hpfsecret]):
        hpc = connect_hpfeeds(args.hpfserver, args.hpfport, args.hpfident, args.hpfsecret)

    if args.debug or args.daemon:
        module_func = None
        if args.type == 'postfix_creds':
            module_func = modules.postfix_creds.pfserver
        elif args.type == 'open_relay':
            module_func = modules.open_relay.or_module
        elif args.type == 'schizo_open_relay':
            module_func = modules.schizo_open_relay.module

        if module_func:
            if args.debug:
                module_func(args.ip, args.port, logger, hpc)
            elif args.daemon:
                pid = os.fork()
                if pid == 0:
                    os.setsid()
                    module_func(args.ip, args.port, logger, hpc)
                    sys.exit(0)
                else:
                    logger.info('Daemon started with PID %d', pid)
                    sys.exit(0)

if __name__ == "__main__":
    main()
