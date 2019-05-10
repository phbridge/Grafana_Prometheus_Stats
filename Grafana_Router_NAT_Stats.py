# Title
# Grfana Router Nat Stats
#
# Language
# Python 3.5
#
# Description
# This script will pull the NAT stats from a router (not avalable via SNMP) and display them on a page so that
# Prometheus can then pull the page and get the latest stats. The same script can also be easily modified to pull
# other stats from a router via CLI
#
# Contacts
# Phil Bridges - phbridge@cisco.com
#
# EULA
# This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges
# with a variety of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and
# arrangements. Until provision of alcohol or baked goodies your on your own but there is no rocket science
# involved so dont panic too much. To accept this EULA you must include the correct flag when running the script.
# If this script goes crazy wrong and breaks everything then your also on your own and Phil will not accept any
# liability of any type or kind. As this script belongs to Phil and NOT Cisco then Cisco cannot be held
# responsible for its use or if it goes bad, nor can Cisco make any profit from this script. Phil can profit
# from this script but will not assume any liability. Other than the boring stuff please enjoy and plagiarise
# as you like (as I have no ways to stop you) but common courtesy says to credit me in some way.
# [see above comments on Beer, Wine, Steak and Greggs.].
#
# Version Control               Comments
# Version 0.01 Date 06/05/19    Initial draft
#
# Version 6.9 Date xx/xx/xx     Took over world and actually got paid for value added work....If your reading this
#                               approach me on Linked-In for details of weekend "daily" rate
# Version 7.0 Date xx/xx/xx     Note to the Gaffer - if your reading this then the above line is a joke only :-)
#
# ToDo *******************TO DO*********************
# 1.0 DONE Import credentials
# 2.0 DONE Run and collect raw data per command
# 3.0 DONE Filter the data for the stats
# 4.0 DONE Display stats for that device on the page
# 5.0 DONE Add argparse for debug and EULA
# 6.0 Implement multiprocessing
# 7.0 implement connection reuse
#

from flask import Flask             # Flask to serve pages
from flask import Response          # Flask to serve pages
import NAT_Stats_Credentials        # Imported credentials
import logging.handlers             # Needed for loggin
import time                         # Only for time.sleep
import wsgiserver                   # from gevent.wsgi
import argparse                     # Only used for debugging and EULA
import paramiko                     # used for the SSH session
import socket                       # only used to raise socket exceptions
from multiprocessing import pool    # trying to run in parallel rather than in sequence

server_IP = "127.0.0.1"
server_port = 8082

logFile = "grafana_router_nat_stats_%s_%s.log" % (server_IP, server_port)
logCount = 4
logBytes = 1048576

web_app = Flask('router_nat_stats')


def run_command(session, command):
    output = ""
    session.send(command + "\n")
    time.sleep(1)       # TODO implement something better than sleep here?
    output = session.recv(65535).decode("utf-8")
    return output


def login_to_host(seed_hostname, seed_username, seed_password):
    crawler_connection_pre = paramiko.SSHClient()
    crawler_connection_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    results = ""
    try:
        logger.debug(seed_hostname + " Starting connection")
        crawler_connection_pre.connect(hostname=seed_hostname,
                                   port=22,
                                   username=seed_username,
                                   password=seed_password,
                                   look_for_keys=False,
                                   allow_agent=False,
                                   timeout=10,
                                   auth_timeout=15)
        logger.debug(seed_hostname + " Invoking Shell")
        crawler_connected = crawler_connection_pre.get_transport().open_session()
        crawler_connected.invoke_shell()
        active_nat_stats_raw = run_command(crawler_connected, "sho ip nat statistics | i Total active translations")
        logger.debug(seed_hostname + "raw nat output " + active_nat_stats_raw)
        active_nat_stats = active_nat_stats_raw.splitlines()[-2].split(" ")[3]
        logger.info(seed_hostname + "filtered output " + active_nat_stats)
        results += 'Active_NAT{host="%s"} %s\n' % (seed_hostname, str(active_nat_stats))
        crawler_connected.close()
        return results

    except paramiko.AuthenticationException:
        logger.warning(seed_hostname + " ########## Auth Error ##########")
        results += 'Active_NAT{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## Auth Error ##########")
        return results
    except paramiko.SSHException:
        logger.warning(seed_hostname + " ########## SSH Error ##########")
        results += 'Active_NAT{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## SSH Error ##########")
        return results
    except socket.error:
        logger.warning(seed_hostname + " ########## Socket Error ##########")
        results += 'Active_NAT{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## Socket Error ##########")
        return results
    except Exception as e:
        logger.warning(seed_hostname + " ########## Unknown Error " + str(e) + "##########")
        results += 'Active_NAT{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## Unknown Error " + str(e) + "##########r")
        return results


def parse_all_arguments():
    parser = argparse.ArgumentParser(description='process input')
    parser.add_argument("-d", "--debug", action='store_true', default=False, help="increase output verbosity", )
    parser.add_argument("-ACCEPTEULA", "--acceptedeula", action='store_true', default=False,
                        help="Marking this flag accepts EULA embedded withing the script")
    args = parser.parse_args()
    if not args.acceptedeula:
        print("""you need to accept the EULA agreement which is as follows:-
    # EULA
    # This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges 
    # with a varity of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and 
    # arrangements. Until provison of alcohol or baked goodies your on your own but there is no rocket sciecne 
    # involved so dont panic too much. To accept this EULA you must include the correct flag when running the script. 
    # If this script goes crazy wrong and breaks everything then your also on your own and Phil will not accept any 
    # liability of any type or kind. As this script belongs to Phil and NOT Cisco then Cisco cannot be held 
    # responsable for its use or if it goes bad, nor can Cisco make any profit from this script. Phil can profit 
    # from this script but will not assume any liability. Other than the boaring stuff please enjoy and plagerise 
    # as you like (as I have no ways to stop you) but common curtacy says to credit me in some way. 
    # [see above comments on Beer, Wine, Steak and Greggs.].

    # To accept the EULA please run with the -ACCEPTEULA flag
        """)
        quit()
    return args


@web_app.route('/nat_stats')
# gets called via the http://your_server_ip:port/nat_stats
def get_stats():
    results = ''
    for host in NAT_Stats_Credentials.hosts:
        logger.info("----------- Processing Host: %s -----------" % host['host'])
        # login to box
        results += login_to_host(host['host'], host['username'], host['password'])
        logger.info("----------- Finished -----------")
        # return text to service
    return Response(results, mimetype='text/plain')


if __name__ == '__main__':
    args = parse_all_arguments()
    print("grafana_router_nat_stats Service Started")
    # Enable logging
    logger = logging.getLogger("grafana_router_nat_stats")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(logFile, maxBytes=logBytes, backupCount=logCount)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info("---------------------- STARTING ----------------------")
    logger.info("grafana_router_nat_stats script started")
    http_server = wsgiserver.WSGIServer(host=server_IP, port=server_port, wsgi_app=web_app)
    http_server.start()


