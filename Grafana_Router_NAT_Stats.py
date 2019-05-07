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
# 2.0 Run and collect raw data per command
# 3.0 Filter the data for the stats
# 4.0 Display stats for that device on the page
# 5.0 Add argparse for debug and EULA
#
#

from flask import Flask
from flask import Response
import NAT_Stats_Credentials
from datetime import datetime, timedelta
import logging
import logging.handlers
import time
import wsgiserver       #from gevent.wsgi
import argparse
import paramiko


server_IP = "127.0.0.1"
server_port = 8082

logFile = "grafana_router_nat_stats_%s_%s.log" % (server_IP, server_port)
logCount = 4
logBytes = 1048576

web_app = Flask('router_nat_stats')


def login_to_host(seed_hostname, seed_username, seed_password):
    crawler_connection = paramiko.SSHClient()
    crawler_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        #output_log.write(str(datetime.now()) + "     " + "attempt 1 logging onto host for prompt " + str(seed) + "\n")
        crawler_connection.connect(hostname=seed_hostname,
                                   port=22,
                                   username=seed_username,
                                   password=seed_password,
                                   look_for_keys=False,
                                   allow_agent=False,
                                   timeout=10,
                                   auth_timeout=15)
        crawler_connected = crawler_connection.invoke_shell()
        time.sleep(5)
        output = crawler_connected.recv(1000).decode("utf-8")
        print(output)
        prompt = output.splitlines()[-1].strip()
        print(prompt)
        # if prompt ends in # then handle if prompt ends in > then handle
        # this is to catch logging in with limited privilage
        if prompt.endswith(">"):
            priv_prompt = str(prompt[:-1] + "#")
        else:
            priv_prompt = prompt

        #output_log.write(str(datetime.now()) + "     " + "prompt for host " + str(seed_hostname) + " is " + str(prompt) + "\n")

        crawler_talk = SSHClientInteraction(crawler_connection, timeout=15, display=False)

        crawler_talk.expect(prompt)

        if prompt.endswith(">"):
            crawler_talk.expect("password: ")
            crawler_talk.send(args.secret_password)
        else:
            crawler_talk.expect(priv_prompt)

        crawler_talk.send("terminal exec prompt timestamp")
        crawler_talk.expect(priv_prompt)
        crawler_talk.send("terminal length 0")
        crawler_talk.expect(priv_prompt)

        crawler_talk.send("sho version | i Cisco IOS Software")
        crawler_talk.expect(priv_prompt)
        results = ""
        if "XE Software" in str(crawler_talk.current_output):
            active_nat_stats = get_active_nat_stats(crawler_talk, "XE")

        elif "IOS Software" in str(crawler_talk.current_output):
            active_nat_stats = get_active_nat_stats(crawler_talk, "IOS")

        results += 'Active_NAT{host="%s"} %s\n' % (host['host'], str(active_nat_stats))
        
        crawler_connected.close()
        return results
        

    except paramiko.AuthenticationException:
        print(str(datetime.now()) + "     " + str(seed_hostname) + " ======== Bad credentials ")
        #output_log.write(str(datetime.now()) + "     " + str(seed_hostname) + " ======== Bad credentials ")
        #output_results.write(str(datetime.now()) + "," + seed_hostname + "," + "Bad credentials" + "," + "Bad credentials" + "\n")
        results += 'Active_NAT{host="%s"} %s\n' % (host['host'], "0")
        return results
    except paramiko.SSHException:
        print(str(datetime.now()) + "     " + str(seed_hostname) + " ======== Issues with ssh service ")
        #output_log.write(str(datetime.now()) + "     " + str(seed_hostname) + " ======== Issues with ssh service ")
        #output_results.write(str(datetime.now()) + "," + seed_hostname + "," + "Issues with ssh service" + "," + "Issues with ssh service" + "\n")
        results += 'Active_NAT{host="%s"} %s\n' % (host['host'], "0")
        return results
    except socket.error:
        print(str(datetime.now()) + "     " + str(seed_hostname) + " ======== socket error ")
        #output_log.write(str(datetime.now()) + "     " + str(seed_hostname) + " ======== socket error ")
        #output_results.write(str(datetime.now()) + "," + seed_hostname + "," + "socket error" + "," + "socket error" + "\n")
        results += 'Active_NAT{host="%s"} %s\n' % (host['host'], "0")
        return results
    except Exception:
        print(str(datetime.now()) + "     " + str(seed_hostname) + " ======== unknown error ")
        #output_log.write(str(datetime.now()) + "     " + str(seed_hostname) + " ======== unknown error ")
        #output_results.write(str(datetime.now()) + "," + seed_hostname + "," + "unknown error" + "," + "unknown error" + "\n")
        results += 'Active_NAT{host="%s"} %s\n' % (host['host'], "0")
        return results
    print(host)
    print(username)
    print(password)
    session = host
    return session


def get_active_nat_stats(session, software_type):
    print("stats")
    print(session)
    active_nat_stats = "564322"
    return active_nat_stats


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

# gets called via the http://your_server_ip:port/nat_stats


@web_app.route('/nat_stats')
def get_stats():
    results = ''
    for host in NAT_Stats_Credentials.hosts:
        logger.info("----------- Processing Host: %s -----------" % host['host'])
        # login to router
        results += login_to_host(host['host'], host['username'], host['password'])
        # return the results to the caller
        logger.info("----------- Finished -----------")
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
    logger.info("-" * 25)
    logger.info("grafana_router_nat_stats script started")

    http_server = wsgiserver.WSGIServer(host=server_IP, port=server_port, wsgi_app=web_app) #, log=logger)
    #http_server.serve_forever()
    http_server.start()


