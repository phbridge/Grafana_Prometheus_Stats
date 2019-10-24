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
# Version 0.1  Date 17/05/19    Improved Error handling
# Version 0.2  Date 18/05/19    Restructured some code to work better of various OS's
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
# 6.0 DONE Implement multiprocessing
# 7.0 Implement connection reuse - Ideally keep SSH connection open full time
# 8.0 Something better than time.sleep() waiting for response.
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
from multiprocessing import Pool    # trying to run in parallel rather than in sequence

server_IP = "127.0.0.1"
server_port = 8085
# Note absolute logfile path must exist when its run as a service else service will not start properly.
logfile = "/home/phbridge/Grafana_Prometheus_Stats/grafana_router_nat_stats_%s_%s.log" % (server_IP, server_port)
# Note absolute logfile path must exist when its run as a service else service will not start properly.
logCount = 4
logBytes = 1048576
web_app = Flask('router_nat_stats')


def run_command(session, command, wait):
    output = ""
    session.send(command + "\n")
    time.sleep(wait)       # TODO implement something better than sleep here?
    output = session.recv(65535).decode("utf-8")
    return output


def get_total_nat_translations(session, os_type, seed_hostname):
    if os_type == "IOS-XE":
        active_nat_stats_raw = run_command(session, "sho ip nat statistics | i Total active translations", 1)
    elif os_type == "IOS":
        active_nat_stats_raw = run_command(session, "sho ip nat statistics | i Total active translations", 1)
    else:
        #TODO return this as Error
        #results = 'Active_NAT_Total{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## OS Not Supported for Active_NAT_Total ##########")
        return results
    logger.debug(seed_hostname + "raw nat output " + active_nat_stats_raw)
    active_nat_stats = active_nat_stats_raw.splitlines()[-2].split(" ")[3]
    logger.info(seed_hostname + " active_nat_stats " + active_nat_stats)
    results = 'Active_NAT_Total{host="%s"} %s\n' % (seed_hostname, str(active_nat_stats))
    return results


def get_total_tcp_nat_translations(session, os_type, seed_hostname):
    if os_type == "IOS-XE":
        active_nat_stats_raw = run_command(session, "sho ip nat translations tcp total", 1)
        active_nat_stats = active_nat_stats_raw.splitlines()[-3].split(" ")[4]
    elif os_type == "IOS":
        active_nat_stats_raw = run_command(session, "sho ip nat translations tcp | count tcp", 1)
        active_nat_stats = active_nat_stats_raw.splitlines()[-2].split(" ")[7]
    else:
        #TODO return this as Error
        #results = 'Active_NAT_TCP{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## OS Not Supported for Active_NAT_TCP ##########")
        return results
    logger.debug(seed_hostname + "raw nat output " + active_nat_stats_raw)
    logger.info(seed_hostname + " active_nat_tcp_stats " + active_nat_stats)
    results = 'Active_NAT_TCP{host="%s"} %s\n' % (seed_hostname, str(active_nat_stats))
    return results


def get_total_udp_nat_translations(session, os_type, seed_hostname):
    if os_type == "IOS-XE":
        active_nat_stats_raw = run_command(session, "sho ip nat translations udp total", 1)
        active_nat_stats = active_nat_stats_raw.splitlines()[-3].split(" ")[4]
    elif os_type == "IOS":
        active_nat_stats_raw = run_command(session, "sho ip nat translations udp | count udp", 1)
        active_nat_stats = active_nat_stats_raw.splitlines()[-2].split(" ")[7]
    else:
        #TODO return this as Error
        #results = 'Active_NAT_UDP{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## OS Not Supported for Active_NAT_UDP ##########")
        return results
    logger.debug(seed_hostname + "raw nat output " + active_nat_stats_raw)
    logger.info(seed_hostname + " active_nat_tcp_stats " + active_nat_stats)
    results = 'Active_NAT_UDP{host="%s"} %s\n' % (seed_hostname, str(active_nat_stats))
    return results


def get_total_icmp_nat_translations(session, os_type, seed_hostname):
    if os_type == "IOS-XE":
        active_nat_stats_raw = run_command(session, "sho ip nat translations icmp total", 1)
        active_nat_stats = active_nat_stats_raw.splitlines()[-3].split(" ")[4]
    elif os_type == "IOS":
        active_nat_stats_raw = run_command(session, "sho ip nat translations icmp | count icmp", 1)
        active_nat_stats = active_nat_stats_raw.splitlines()[-2].split(" ")[7]
    else:
        #TODO return this as Error
        #results = 'Active_NAT_ICMP{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## OS Not Supported for Active_NAT_ICMP ##########")
        return results
    logger.debug(seed_hostname + "raw nat output " + active_nat_stats_raw)
    logger.info(seed_hostname + " active_nat_tcp_stats " + active_nat_stats)
    results = 'Active_NAT_ICMP{host="%s"} %s\n' % (seed_hostname, str(active_nat_stats))
    return results


def login_to_host(seed_hostname, seed_username, seed_password, device_OS):
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
                                       timeout=10)
        logger.debug(seed_hostname + " Invoking Shell")
        crawler_connected = crawler_connection_pre.get_transport().open_session()
        crawler_connected.invoke_shell()

        run_command(crawler_connected, "terminal length 0", 1)

        results += get_total_nat_translations(crawler_connected, device_OS, seed_hostname)
        results += get_total_tcp_nat_translations(crawler_connected, device_OS, seed_hostname)
        results += get_total_udp_nat_translations(crawler_connected, device_OS, seed_hostname)
        results += get_total_icmp_nat_translations(crawler_connected, device_OS, seed_hostname)

        qos_output_raw = run_command(crawler_connected, "sho policy-map interface output | i pkts|no-buffer", 1)
        QoS_PLAT_Pkts = qos_output_raw.splitlines()[-12].split(" ")[-1].split("/")[0]
        results += 'QoS_PLAT_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Pkts))
        results += 'QoS_PLAT_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Pkts))
        QoS_PLAT_Bytes = qos_output_raw.splitlines()[-12].split(" ")[-1].split("/")[1]
        results += 'QoS_PLAT_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Bytes))
        results += 'QoS_PLAT_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Bytes))
        QoS_PLAT_Drops = qos_output_raw.splitlines()[-13].split("/")[-2]
        results += 'QoS_PLAT_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Drops))
        results += 'QoS_PLAT_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Drops))

        QoS_GOLD_Pkts = qos_output_raw.splitlines()[-10].split(" ")[-1].split("/")[0]
        results += 'QoS_GOLD_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Pkts))
        results += 'QoS_GOLD_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Pkts))
        QoS_GOLD_Bytes = qos_output_raw.splitlines()[-10].split(" ")[-1].split("/")[1]
        results += 'QoS_GOLD_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Bytes))
        results += 'QoS_GOLD_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Bytes))
        QoS_GOLD_Drops = qos_output_raw.splitlines()[-11].split("/")[-3]
        results += 'QoS_GOLD_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Drops))
        results += 'QoS_GOLD_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Drops))

        QoS_SILVER_Pkts = qos_output_raw.splitlines()[-8].split(" ")[-1].split("/")[0]
        results += 'QoS_SILVER_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Pkts))
        results += 'QoS_SILVER_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Pkts))
        QoS_SILVER_Bytes = qos_output_raw.splitlines()[-8].split(" ")[-1].split("/")[1]
        results += 'QoS_SILVER_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Bytes))
        results += 'QoS_SILVER_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Bytes))
        QoS_SILVER_Drops = qos_output_raw.splitlines()[-9].split("/")[-3]
        results += 'QoS_SILVER_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Drops))
        results += 'QoS_SILVER_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Drops))

        QoS_BRONZE_Pkts = qos_output_raw.splitlines()[-6].split(" ")[-1].split("/")[0]
        results += 'QoS_BRONZE_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Pkts))
        results += 'QoS_BRONZE_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Pkts))
        QoS_BRONZE_Bytes = qos_output_raw.splitlines()[-6].split(" ")[-1].split("/")[1]
        results += 'QoS_BRONZE_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Bytes))
        results += 'QoS_BRONZE_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Bytes))
        QoS_BRONZE_Drops = qos_output_raw.splitlines()[-7].split("/")[-3]
        results += 'QoS_BRONZE_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Drops))
        results += 'QoS_BRONZE_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Drops))

        QoS_TIN_Pkts = qos_output_raw.splitlines()[-4].split(" ")[-1].split("/")[0]
        results += 'QoS_TIN_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Pkts))
        results += 'QoS_TIN_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Pkts))
        QoS_TIN_Bytes = qos_output_raw.splitlines()[-4].split(" ")[-1].split("/")[1]
        results += 'QoS_TIN_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Bytes))
        results += 'QoS_TIN_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Bytes))
        QoS_TIN_Drops = qos_output_raw.splitlines()[-5].split("/")[-3]
        results += 'QoS_TIN_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Drops))
        results += 'QoS_TIN_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Drops))

        QoS_DEFAULT_Pkts = qos_output_raw.splitlines()[-2].split(" ")[-1].split("/")[0]
        results += 'QoS_DEFAULT_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Pkts))
        results += 'QoS_DEFAULT_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Pkts))
        QoS_DEFAULT_Bytes = qos_output_raw.splitlines()[-2].split(" ")[-1].split("/")[1]
        results += 'QoS_DEFAULT_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Bytes))
        results += 'QoS_DEFAULT_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Bytes))
        QoS_DEFAULT_Drops = qos_output_raw.splitlines()[-3].split("/")[-3]
        results += 'QoS_DEFAULT_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Drops))
        results += 'QoS_DEFAULT_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Drops))

        qos_output_raw_raw = run_command(crawler_connected, "sho policy-map interface input | i packets", 1)
        #Neeed to have this goofing as IOS and IOS-XE output is different
        qos_output_raw = "null"
        for line in qos_output_raw_raw:
            if "        " not in line:
                qos_output_raw += str(line + "\n")

        QoS_PLAT_Pkts = qos_output_raw.splitlines()[-7].split(" ")[-4]
        results += 'QoS_PLAT_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Pkts))
        QoS_PLAT_Bytes = qos_output_raw.splitlines()[-7].split(" ")[-2]
        results += 'QoS_PLAT_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Bytes))
        #QoS_PLAT_Drops = qos_output_raw.splitlines()[-13].split("/")[-2]
        #results += 'QoS_PLAT_IN_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Drops))

        QoS_GOLD_Pkts = qos_output_raw.splitlines()[-6].split(" ")[-4]
        results += 'QoS_GOLD_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Pkts))
        QoS_GOLD_Bytes = qos_output_raw.splitlines()[-6].split(" ")[-2]
        results += 'QoS_GOLD_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Bytes))
        #QoS_GOLD_Drops = qos_output_raw.splitlines()[-11].split("/")[-3]
        #results += 'QoS_GOLD_IN_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Drops))

        QoS_SILVER_Pkts = qos_output_raw.splitlines()[-5].split(" ")[-4]
        results += 'QoS_SILVER_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Pkts))
        QoS_SILVER_Bytes = qos_output_raw.splitlines()[-5].split(" ")[-2]
        results += 'QoS_SILVER_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Bytes))
        #QoS_SILVER_Drops = qos_output_raw.splitlines()[-9].split("/")[-3]
        #results += 'QoS_SILVER_IN_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Drops))

        QoS_BRONZE_Pkts = qos_output_raw.splitlines()[-4].split(" ")[-4]
        results += 'QoS_BRONZE_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Pkts))
        QoS_BRONZE_Bytes = qos_output_raw.splitlines()[-4].split(" ")[-2]
        results += 'QoS_BRONZE_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Bytes))
        #QoS_BRONZE_Drops = qos_output_raw.splitlines()[-7].split("/")[-3]
        #results += 'QoS_BRONZE_IN_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Drops))

        QoS_TIN_Pkts = qos_output_raw.splitlines()[-3].split(" ")[-4]
        results += 'QoS_TIN_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Pkts))
        QoS_TIN_Bytes = qos_output_raw.splitlines()[-3].split(" ")[-2]
        results += 'QoS_TIN_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Bytes))
        #QoS_TIN_Drops = qos_output_raw.splitlines()[-5].split("/")[-3]
        #results += 'QoS_TIN_IN_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Drops))

        QoS_DEFAULT_Pkts = qos_output_raw.splitlines()[-2].split(" ")[-4]
        results += 'QoS_DEFAULT_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Pkts))
        QoS_DEFAULT_Bytes = qos_output_raw.splitlines()[-2].split(" ")[-2]
        results += 'QoS_DEFAULT_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Bytes))
        #QoS_DEFAULT_Drops = qos_output_raw.splitlines()[-3].split("/")[-3]
        #results += 'QoS_DEFAULT_IN_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Drops))

        # qos_output_raw = run_command(crawler_connected, "sho policy-map interface | i Class|pkts|drops", 1)
        # QoS_PLAT_Pkts = qos_output_raw.splitlines()[-19].split(" ")[-1].split("/")[0]
        # results += 'QoS_PLAT_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Pkts))
        # QoS_PLAT_Bytes = qos_output_raw.splitlines()[-19].split(" ")[-1].split("/")[1]
        # results += 'QoS_PLAT_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Bytes))
        # QoS_PLAT_Drops = qos_output_raw.splitlines()[-20].split("/")[-2]
        # results += 'QoS_PLAT_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_PLAT_Drops))
        #
        # QoS_GOLD_Pkts = qos_output_raw.splitlines()[-14].split(" ")[-1].split("/")[0]
        # results += 'QoS_GOLD_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Pkts))
        # QoS_GOLD_Bytes = qos_output_raw.splitlines()[-14].split(" ")[-1].split("/")[1]
        # results += 'QoS_GOLD_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Bytes))
        # QoS_GOLD_Drops = qos_output_raw.splitlines()[-15].split("/")[-2]
        # results += 'QoS_GOLD_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_GOLD_Drops))
        #
        # QoS_SILVER_Pkts = qos_output_raw.splitlines()[-11].split(" ")[-1].split("/")[0]
        # results += 'QoS_SILVER_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Pkts))
        # QoS_SILVER_Bytes = qos_output_raw.splitlines()[-11].split(" ")[-1].split("/")[1]
        # results += 'QoS_SILVER_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Bytes))
        # QoS_SILVER_Drops = qos_output_raw.splitlines()[-12].split("/")[-2]
        # results += 'QoS_SILVER_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_SILVER_Drops))
        #
        # QoS_BRONZE_Pkts = qos_output_raw.splitlines()[-8].split(" ")[-1].split("/")[0]
        # results += 'QoS_BRONZE_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Pkts))
        # QoS_BRONZE_Bytes = qos_output_raw.splitlines()[-8].split(" ")[-1].split("/")[1]
        # results += 'QoS_BRONZE_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Bytes))
        # QoS_BRONZE_Drops = qos_output_raw.splitlines()[-9].split("/")[-2]
        # results += 'QoS_BRONZE_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_BRONZE_Drops))
        #
        # QoS_TIN_Pkts = qos_output_raw.splitlines()[-5].split(" ")[-1].split("/")[0]
        # results += 'QoS_TIN_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Pkts))
        # QoS_TIN_Bytes = qos_output_raw.splitlines()[-5].split(" ")[-1].split("/")[1]
        # results += 'QoS_TIN_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Bytes))
        # QoS_TIN_Drops = qos_output_raw.splitlines()[-6].split("/")[-2]
        # results += 'QoS_TIN_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_TIN_Drops))
        #
        # QoS_DEFAULT_Pkts = qos_output_raw.splitlines()[-2].split(" ")[-1].split("/")[0]
        # results += 'QoS_DEFAULT_Pkts{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Pkts))
        # QoS_DEFAULT_Bytes = qos_output_raw.splitlines()[-2].split(" ")[-1].split("/")[1]
        # results += 'QoS_DEFAULT_Bytes{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Bytes))
        # QoS_DEFAULT_Drops = qos_output_raw.splitlines()[-3].split("/")[-2]
        # results += 'QoS_DEFAULT_Drops{host="%s"} %s\n' % (seed_hostname, str(QoS_DEFAULT_Drops))

        crawler_connected.close()
        crawler_connection_pre.close()
        return results

    except paramiko.AuthenticationException:
        logger.warning(seed_hostname + " ########## Auth Error ##########")
        #results += 'Active_NAT{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## Auth Error ##########")
        return results
    except paramiko.SSHException:
        logger.warning(seed_hostname + " ########## SSH Error ##########")
        #results += 'Active_NAT{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## SSH Error ##########")
        return results
    except socket.error:
        logger.warning(seed_hostname + " ########## Socket Error ##########")
        #results += 'Active_NAT{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## Socket Error ##########")
        return results
    except Exception as e:
        logger.warning(seed_hostname + " ########## Unknown Error " + str(e) + "##########")
        #results += 'Active_NAT{host="%s"} %s (%s) \n' % (seed_hostname, "0", "########## Unknown Error " + str(e) + "##########r")
        return results


def processing_test(hostname, username, password):
    longstring = str(hostname + username + password + "\n")
    print("process")
    print("begin wait")
    time.sleep(10)
    print("end wait")
    print(str(hostname + username + password + "\n"))
    return longstring


def process_hosts_in_parallel():
    logger.info("----------- Processing Parallel -----------")
    results = ""
    hosts = []
    for each in NAT_Stats_Credentials.hosts:
        host_details = []
        host_details.append(each['host'])
        host_details.append(each['username'])
        host_details.append(each['password'])
        host_details.append(each['OS'])
        hosts.append(host_details)
    with Pool(processes=args.max_threads) as process_worker:
        results = process_worker.starmap(login_to_host, hosts)
    return results


def process_hosts_in_serial():
    logger.info("----------- Processing Serial -----------")
    results = ""
    for host in NAT_Stats_Credentials.hosts:
        logger.info("----------- Processing Host: %s -----------" % host['host'])
        # login to box
        results += login_to_host(host['host'], host['username'], host['password'], host['OS'])
        logger.info("----------- Finished -----------")
        # return text to service
    return results


def parse_all_arguments():
    parser = argparse.ArgumentParser(description='process input')
    parser.add_argument("-d", "--debug", action='store_true', default=False, help="increase output verbosity", )
    parser.add_argument("-s", "--single_thread", action='store_true', default=False, help="run in single threaded mode")
    parser.add_argument("-t", "--max_threads", default=10, help="max number of threads to run in parrellel")
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
# gets called via the http://127.0.0.1:8082/nat_stats
def get_stats():
    if args.single_thread:
        results = process_hosts_in_serial()
    else:
        results = process_hosts_in_parallel()
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
    handler = logging.handlers.RotatingFileHandler(logfile, maxBytes=logBytes, backupCount=logCount)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info("---------------------- STARTING ----------------------")
    logger.info("grafana_router_nat_stats script started")
    http_server = wsgiserver.WSGIServer(host=server_IP, port=server_port, wsgi_app=web_app)
    http_server.start()
