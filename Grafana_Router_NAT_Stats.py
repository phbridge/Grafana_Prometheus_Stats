# Copyright (c) 2021 Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at
#
#                https://developer.cisco.com/docs/licenses
#
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.

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
# Recently added the option/ability to run as both pull model (prometheus) and push model (Direct to influx)
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
# 7.0 NOT FOR THIS PRIJECT Implement connection reuse - Ideally keep SSH connection open full time
# 8.0 Something better than time.sleep() waiting for response.
#

from flask import Flask             # Flask to serve pages
from flask import Response          # Flask to serve pages
import credentials                  # Imported credentials
import logging.handlers             # Needed for loggin
import time                         # Only for time.sleep
import wsgiserver                   # from gevent.wsgi
# import argparse                     # Only used for debugging and EULA
import re
import paramiko                     # used for the SSH session
import socket                       # only used to raise socket exceptions
from multiprocessing import Pool    # trying to run in parallel rather than in sequence
import threading                    # for periodic cron type jobs
from datetime import timedelta      # calculate x time ago
from datetime import datetime       # timestamps mostly
import inspect                      # logging
import signal
import requests
import sys
import traceback

FLASK_HOST = credentials.FLASK_HOST
FLASK_PORT = credentials.FLASK_PORT
# Note absolute logfile path must exist when its run as a service else service will not start properly.
LOGFILE = credentials.LOGFILE
INFLUX_MODE = credentials.INFLUX_MODE
FLASK_MODE = credentials.FLASK_MODE
MAX_THREADS = credentials.MAX_THREADS
HOSTS = credentials.HOSTS
INFLUX_DB_PATH = credentials.INFLUX_DB_PATH

THREAD_TO_BREAK = threading.Event()

flask_app = Flask('router_nat_stats')


def run_command(session, command, wait=2):
    output = ""
    session.send(command + "\n")
    time.sleep(wait)       # TODO implement something better than sleep here?
    output = session.recv(65535).decode("utf-8")
    return output


def get_total_nat_translations(session, os_type, seed_hostname):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    try:
        if os_type == "IOS-XE":
            active_nat_stats_raw = run_command(session, "sho ip nat statistics | i Total active translations")
        elif os_type == "IOS":
            active_nat_stats_raw = run_command(session, "sho ip nat statistics | i Total active translations")
        else:
            function_logger.warning(seed_hostname + " ########## OS Not Supported for Active_NAT_Total ##########")
            return None
        function_logger.debug(seed_hostname + "raw nat output " + active_nat_stats_raw)
        active_nat_stats = active_nat_stats_raw.splitlines()[-2].split(" ")[3]
        function_logger.debug(seed_hostname + " active_nat_stats " + active_nat_stats)
        return str(active_nat_stats)
    except IndexError:
        function_logger.warning("Index Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("raw_output was %s" % str(active_nat_stats_raw))
        return None
    except ValueError:
        function_logger.warning("Value Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("raw_output was %s" % str(active_nat_stats_raw))
        return None
    except Exception as e:
        function_logger.error("something went collecting data from host")
        function_logger.error("Unknown Error %s HOST=%s ##########" % (str(e), seed_hostname))
        function_logger.error("Unexpected error:%s" % str(sys.exc_info()[0]))
        function_logger.error("Unexpected error:%s" % str(e))
        function_logger.error("TRACEBACK=%s" % str(traceback.format_exc()))
        return None


def get_total_tcp_nat_translations(session, os_type, seed_hostname):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    try:
        if os_type == "IOS-XE":
            active_nat_stats_raw = run_command(session, "sho ip nat translations tcp total")
            active_nat_stats = active_nat_stats_raw.splitlines()[-3].split(" ")[4]
        elif os_type == "IOS":
            active_nat_stats_raw = run_command(session, "sho ip nat translations tcp | count tcp")
            active_nat_stats = active_nat_stats_raw.splitlines()[-2].split(" ")[7]
        else:
            function_logger.warning(seed_hostname + " ########## OS Not Supported for Active_NAT_TCP ##########")
            return None
        function_logger.debug(seed_hostname + "raw nat output " + active_nat_stats_raw)
        function_logger.debug(seed_hostname + " active_nat_tcp_stats " + active_nat_stats)
        return str(active_nat_stats)
    except IndexError:
        function_logger.warning("Index Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("raw_output was %s" % str(active_nat_stats_raw))
        return None
    except ValueError:
        function_logger.warning("Value Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("raw_output was %s" % str(active_nat_stats_raw))
        return None
    except Exception as e:
        function_logger.error("something went collecting data from host")
        function_logger.error("Unknown Error %s HOST=%s ##########" % (str(e), seed_hostname))
        function_logger.error("Unexpected error:%s" % str(sys.exc_info()[0]))
        function_logger.error("Unexpected error:%s" % str(e))
        function_logger.error("TRACEBACK=%s" % str(traceback.format_exc()))
        return None


def get_total_v4_v6_split(session, os_type, seed_hostname, interface, influx=True):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    results = ""
    ip_output = ""
    ipv6_output = ""
    rcvd_linev4 = ""
    sent_linev4 = ""
    rcvd_linev6 = ""
    sent_linev6 = ""

    def _process_v4_response(rcvd_line, sent_line):
        results_inside = ""
        function_logger.info("rcvdv4_line=%s, sent_linev4=%s" % (rcvd_line, sent_line))
        try:
            ip_pkts_sent = int(sent_line.split()[1])
            ip_bytes_sent = int(sent_line.split()[3])
            ip_pkts_rcvd = int(rcvd_line.split()[1])
            ip_bytes_rcvd = int(rcvd_line.split()[3])
            function_logger.info("hostname=%s ip_pkts_sent=%s ip_bytes_sent=%s ip_pkts_rcvd=%s ip_bytes_rcvd=%s "
                                 % (seed_hostname, ip_pkts_sent, ip_bytes_sent, ip_pkts_rcvd, ip_bytes_rcvd))
            if influx:
                results_inside += 'IP_Stats,host=%s,interface=%s ip_pkts_sent=%s,ip_bytes_sent=%s,ip_pkts_rcvd=%s,ip_bytes_rcvd=%s \n' % \
                                  (seed_hostname, interface, str(ip_pkts_sent), str(ip_bytes_sent), str(ip_pkts_rcvd), str(ip_bytes_rcvd))
            else:
                results_inside += 'ip_pkts_sent{host="%s"} %s\n' % (seed_hostname, str(ip_pkts_sent))
                results_inside += 'ip_bytes_sent{host="%s"} %s\n' % (seed_hostname, str(ip_bytes_sent))
                results_inside += 'ip_pkts_rcvd{host="%s"} %s\n' % (seed_hostname, str(ip_pkts_rcvd))
                results_inside += 'ip_bytes_rcvd{host="%s"} %s\n' % (seed_hostname, str(ip_bytes_rcvd))
            return results_inside
        except IndexError:
            function_logger.warning("Index Error _process_v4_response")
            function_logger.info("rcvd_linev4=%s, sent_linev4=%s" % (rcvd_line, sent_line))
            raise IndexError
        except ValueError:
            function_logger.warning("Value Error _process_v4_response")
            function_logger.info("rcvd_linev4=%s, sent_linev4=%s" % (rcvd_line, sent_line))
            raise ValueError
        except Exception as e:
            function_logger.error("something went wrong processing _process_v4_response v4")
            function_logger.error("Unexpected error:%s" % str(sys.exc_info()[0]))
            function_logger.error("Unexpected error:%s" % str(e))
            function_logger.error("TRACEBACK=%s" % str(traceback.format_exc()))
            return ""

    def _process_v6_response(rcvd_line, sent_line):
        results_inside = ""
        function_logger.info("rcvd_linev6=%s, sent_linev6=%s" % (rcvd_line, sent_line))
        try:
            ipv6_pkts_sent = int(sent_line.split()[1])
            ipv6_bytes_sent = int(sent_line.split()[3])
            ipv6_pkts_rcvd = int(rcvd_line.split()[1])
            ipv6_bytes_rcvd = int(rcvd_line.split()[3])
            function_logger.info("hostname=%s ipv6_pkts_sent=%s ipv6_bytes_sent=%s ipv6_pkts_rcvd=%s ipv6_bytes_rcvd=%s "
                                 % (seed_hostname, ipv6_pkts_sent, ipv6_bytes_sent, ipv6_pkts_rcvd, ipv6_bytes_rcvd))
            if influx:
                results_inside += 'IP_Stats,host=%s,interface=%s ipv6_pkts_sent=%s,ipv6_bytes_sent=%s,ipv6_pkts_rcvd=%s,ipv6_bytes_rcvd=%s \n' % \
                                  (seed_hostname, interface, str(ipv6_pkts_sent), str(ipv6_bytes_sent), str(ipv6_pkts_rcvd), str(ipv6_bytes_rcvd))
            else:
                results_inside += 'ipv6_pkts_sent{host="%s"} %s\n' % (seed_hostname, str(ipv6_pkts_sent))
                results_inside += 'ipv6_bytes_sent{host="%s"} %s\n' % (seed_hostname, str(ipv6_bytes_sent))
                results_inside += 'ipv6_pkts_rcvd{host="%s"} %s\n' % (seed_hostname, str(ipv6_pkts_rcvd))
                results_inside += 'ipv6_bytes_rcvd{host="%s"} %s\n' % (seed_hostname, str(ipv6_bytes_rcvd))
            return results_inside
        except IndexError:
            function_logger.warning("Index Error _process_v6_response")
            function_logger.info("rcvd_linev6=%s, sent_linev6=%s" % (rcvd_line, sent_line))
            raise IndexError
        except ValueError:
            function_logger.warning("Value Error _process_v6_response")
            function_logger.info("rcvd_linev6=%s, sent_linev6=%s" % (rcvd_line, sent_line))
            raise ValueError
        except Exception as e:
            function_logger.error("something went wrong processing _process_v4_response v4")
            function_logger.error("Unexpected error:%s" % str(sys.exc_info()[0]))
            function_logger.error("Unexpected error:%s" % str(e))
            function_logger.error("TRACEBACK=%s" % str(traceback.format_exc()))
            return ""

    try:
        ip_output = run_command(session, "sho ip traffic interface %s" % interface)
        ipv6_output = run_command(session, "sho ipv6 traffic  interface %s" % interface)
        if os_type == "IOS-XE":
            for line in ip_output.splitlines():
                if re.search("Rcvd", line):
                    rcvd_linev4 = line
                elif re.search("Sent", line):
                    sent_linev4 = line
            function_logger.info(str(rcvd_linev4))
            function_logger.info(str(sent_linev4))
            if not (rcvd_linev4 is "" and sent_linev4 is ""):
                results += _process_v4_response(rcvd_linev4, sent_linev4)
            for line in ipv6_output.splitlines():
                if re.search("Rcvd", line):
                    rcvd_linev6 = line
                elif re.search("Sent", line):
                    sent_linev6 = line
            function_logger.info(str(rcvd_linev6))
            function_logger.info(str(sent_linev6))
            if not (rcvd_linev6 is "" and sent_linev6 is ""):
                results += _process_v6_response(rcvd_linev6, sent_linev6)
        elif os_type == "IOS":
            for line in ip_output.splitlines():
                if re.search("Rcvd", line):
                    rcvd_linev4 = line
                elif re.search("Sent", line):
                    sent_linev4 = line
            function_logger.info(str(rcvd_linev4))
            function_logger.info(str(sent_linev4))
            if not (rcvd_linev4 is "" and sent_linev4 is ""):
                results += _process_v4_response(rcvd_linev4, sent_linev4)
            for line in ipv6_output.splitlines():
                if re.search("Rcvd", line):
                    rcvd_linev6 = line
                elif re.search("Sent", line):
                    sent_linev6 = line
            function_logger.info(str(rcvd_linev6))
            function_logger.info(str(sent_linev6))
            if not (rcvd_linev6 is "" and sent_linev6 is ""):
                results += _process_v6_response(rcvd_linev6, sent_linev6)
        else:
            function_logger.warning(seed_hostname + " ########## OS Not Supported for Active_NAT_TCP ##########")
            return ""
        function_logger.debug("%s %s ip_output %s" % (seed_hostname, interface, ip_output))
        function_logger.debug("%s %s ipv6_output %s" % (seed_hostname, interface, ipv6_output))
        return str(results)
    except IndexError:
        function_logger.warning("Index Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("%s %s ip_output %s" % (seed_hostname, interface, ip_output))
        function_logger.warning("%s %s ipv6_output %s" % (seed_hostname, interface, ipv6_output))
        return ""
    except ValueError:
        function_logger.warning("Value Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("%s %s ip_output %s" % (seed_hostname, interface, ip_output))
        function_logger.warning("%s %s ipv6_output %s" % (seed_hostname, interface, ipv6_output))
        return ""
    except Exception as e:
        function_logger.error("something went collecting data from host")
        function_logger.error("Unknown Error %s HOST=%s ##########" % (str(e), seed_hostname))
        function_logger.error("Unexpected error:%s" % str(sys.exc_info()[0]))
        function_logger.error("Unexpected error:%s" % str(e))
        function_logger.error("TRACEBACK=%s" % str(traceback.format_exc()))
        return ""
    return ""


def get_total_udp_nat_translations(session, os_type, seed_hostname):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    try:
        if os_type == "IOS-XE":
            active_nat_stats_raw = run_command(session, "sho ip nat translations udp total")
            active_nat_stats = active_nat_stats_raw.splitlines()[-3].split(" ")[4]
        elif os_type == "IOS":
            active_nat_stats_raw = run_command(session, "sho ip nat translations udp | count udp")
            active_nat_stats = active_nat_stats_raw.splitlines()[-2].split(" ")[7]
        else:
            function_logger.warning(seed_hostname + " ########## OS Not Supported for Active_NAT_UDP ##########")
            return None
        function_logger.debug(seed_hostname + "raw nat output " + active_nat_stats_raw)
        function_logger.debug(seed_hostname + " active_nat_tcp_stats " + active_nat_stats)
        return str(active_nat_stats)
    except IndexError:
        function_logger.warning("Index Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("raw_output was %s" % str(active_nat_stats_raw))
        return None
    except ValueError:
        function_logger.warning("Value Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("raw_output was %s" % str(active_nat_stats_raw))
        return None
    except Exception as e:
        function_logger.error("something went collecting data from host")
        function_logger.error("Unknown Error %s HOST=%s ##########" % (str(e), seed_hostname))
        function_logger.error("Unexpected error:%s" % str(sys.exc_info()[0]))
        function_logger.error("Unexpected error:%s" % str(e))
        function_logger.error("TRACEBACK=%s" % str(traceback.format_exc()))
        return None


def get_total_icmp_nat_translations(session, os_type, seed_hostname):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    try:
        if os_type == "IOS-XE":
            active_nat_stats_raw = run_command(session, "sho ip nat translations icmp total")
            active_nat_stats = active_nat_stats_raw.splitlines()[-3].split(" ")[4]
        elif os_type == "IOS":
            active_nat_stats_raw = run_command(session, "sho ip nat translations icmp | count icmp")
            active_nat_stats = active_nat_stats_raw.splitlines()[-2].split(" ")[7]
        else:
            function_logger.warning(seed_hostname + " ########## OS Not Supported for Active_NAT_ICMP ##########")
            return None
        function_logger.debug(seed_hostname + "raw nat output " + active_nat_stats_raw)
        function_logger.debug(seed_hostname + " active_nat_tcp_stats " + active_nat_stats)
        return str(active_nat_stats)
    except IndexError:
        function_logger.warning("Index Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("raw_output was %s" % str(active_nat_stats_raw))
        return None
    except ValueError:
        function_logger.warning("Value Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("raw_output was %s" % str(active_nat_stats_raw))
        return None
    except Exception as e:
        function_logger.error("something went collecting data from host")
        function_logger.error("Unknown Error %s HOST=%s ##########" % (str(e), seed_hostname))
        function_logger.error("Unexpected error:%s" % str(sys.exc_info()[0]))
        function_logger.error("Unexpected error:%s" % str(e))
        function_logger.error("TRACEBACK=%s" % str(traceback.format_exc()))
        return None


def login_to_host_nat(seed_hostname, seed_username, seed_password, device_OS, influx=False):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    crawler_connection_pre = paramiko.SSHClient()
    crawler_connection_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    results = ""
    try:
        function_logger.debug(seed_hostname + " Starting connection")
        crawler_connection_pre.connect(hostname=seed_hostname, port=22, username=seed_username, password=seed_password,
                                       look_for_keys=False, allow_agent=False, timeout=10)
        function_logger.debug(seed_hostname + " Invoking Shell")
        crawler_connected = crawler_connection_pre.get_transport().open_session()
        crawler_connected.invoke_shell()
        run_command(crawler_connected, "terminal length 0", 1)
        nat_trans_total = get_total_nat_translations(crawler_connected, device_OS, seed_hostname)
        nat_trans_icmp = get_total_icmp_nat_translations(crawler_connected, device_OS, seed_hostname)
        nat_trans_tcp = get_total_tcp_nat_translations(crawler_connected, device_OS, seed_hostname)
        nat_trans_udp = get_total_udp_nat_translations(crawler_connected, device_OS, seed_hostname)
        crawler_connected.close()
        crawler_connection_pre.close()
        if influx:
            append_this = " "
            if nat_trans_total is not None:
                append_this += 'total=%s,' % str(nat_trans_total)
            if nat_trans_icmp is not None:
                append_this += 'icmp=%s,' % str(nat_trans_icmp)
            if nat_trans_tcp is not None:
                append_this += 'tcp=%s,' % str(nat_trans_tcp)
            if nat_trans_udp is not None:
                append_this += 'udp=%s,' % str(nat_trans_udp)
            results += 'NAT_Translations,host=%s%s \n' % \
                       (seed_hostname, append_this[:-1])
        else:
            if nat_trans_total is not None:
                results += 'NAT_Active_NAT_Total{host="%s"} %s\n' % (seed_hostname, str(nat_trans_total))
            if nat_trans_icmp is not None:
                results += 'NAT_Active_NAT_ICMP{host="%s"} %s\n' % (seed_hostname, str(nat_trans_icmp))
            if nat_trans_tcp is not None:
                results += 'NAT_Active_NAT_TCP{host="%s"} %s\n' % (seed_hostname, str(nat_trans_tcp))
            if nat_trans_udp is not None:
                results += 'NAT_Active_NAT_UDP{host="%s"} %s\n' % (seed_hostname, str(nat_trans_udp))
        return results
    except paramiko.AuthenticationException:
        function_logger.warning("Auth Error HOST=%s" % seed_hostname)
        return results
    except paramiko.SSHException:
        function_logger.warning("SSH Error HOST=%s" % seed_hostname)
        return results
    except socket.error:
        function_logger.warning("Socket Error HOST=%s" % seed_hostname)
        return results
    except Exception as e:
        function_logger.warning("Unknown Error %s HOST=%s ##########" % (str(e), seed_hostname))
        return results


def login_to_host_qos(seed_hostname, seed_username, seed_password, device_OS, qos_interfaces, influx=False):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    crawler_connection_pre = paramiko.SSHClient()
    crawler_connection_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    results = ""
    try:
        function_logger.debug(seed_hostname + " Starting connection")
        crawler_connection_pre.connect(hostname=seed_hostname, port=22, username=seed_username, password=seed_password,
                                       look_for_keys=False, allow_agent=False, timeout=10)
        function_logger.debug(seed_hostname + " Invoking Shell")
        crawler_connected = crawler_connection_pre.get_transport().open_session()
        crawler_connected.invoke_shell()
        run_command(crawler_connected, "terminal length 0", 1)

        for each_interface in qos_interfaces:
            qos_output_raw = run_command(crawler_connected, "sho policy-map interface %s output | i pkts|no-buffer" % each_interface, 2)
            function_logger.info("raw_output for host %s interface %s is %s" % (seed_hostname, each_interface, qos_output_raw))
            qos_pla_pkts = int(qos_output_raw.splitlines()[-12].split(" ")[-1].split("/")[0])
            qos_pla_byte = int(qos_output_raw.splitlines()[-12].split(" ")[-1].split("/")[1])
            qos_pla_drop = int(qos_output_raw.splitlines()[-13].split("/")[-2])
            qos_gol_pkts = int(qos_output_raw.splitlines()[-10].split(" ")[-1].split("/")[0])
            qos_gol_byte = int(qos_output_raw.splitlines()[-10].split(" ")[-1].split("/")[1])
            qos_gol_drop = int(qos_output_raw.splitlines()[-11].split("/")[-3])
            qos_sil_pkts = int(qos_output_raw.splitlines()[-8].split(" ")[-1].split("/")[0])
            qos_sil_byte = int(qos_output_raw.splitlines()[-8].split(" ")[-1].split("/")[1])
            qos_sil_drop = int(qos_output_raw.splitlines()[-9].split("/")[-3])
            qos_bro_pkts = int(qos_output_raw.splitlines()[-6].split(" ")[-1].split("/")[0])
            qos_bro_byte = int(qos_output_raw.splitlines()[-6].split(" ")[-1].split("/")[1])
            qos_bro_drop = int(qos_output_raw.splitlines()[-7].split("/")[-3])
            qos_tin_pkts = int(qos_output_raw.splitlines()[-4].split(" ")[-1].split("/")[0])
            qos_tin_byte = int(qos_output_raw.splitlines()[-4].split(" ")[-1].split("/")[1])
            qos_tin_drop = int(qos_output_raw.splitlines()[-5].split("/")[-3])
            qos_dft_pkts = int(qos_output_raw.splitlines()[-2].split(" ")[-1].split("/")[0])
            qos_dft_byte = int(qos_output_raw.splitlines()[-2].split(" ")[-1].split("/")[1])
            qos_dft_drop = int(qos_output_raw.splitlines()[-3].split("/")[-3])
            if influx:
                results += 'QoS_Stats_Egress,host=%s,interface=%s ' \
                           'pla_pks=%s,pla_bytes=%s,pla_drops=%s,' \
                           'gol_pks=%s,gol_bytes=%s,gol_drops=%s,' \
                           'sil_pks=%s,sil_bytes=%s,sil_drops=%s,' \
                           'bro_pks=%s,bro_bytes=%s,bro_drops=%s,' \
                           'tin_pks=%s,tin_bytes=%s,tin_drops=%s,' \
                           'dft_pks=%s,dft_bytes=%s,dft_drops=%s \n' % \
                           (seed_hostname, each_interface,
                            str(qos_pla_pkts), str(qos_pla_byte), str(qos_pla_drop),
                            str(qos_gol_pkts), str(qos_gol_byte), str(qos_gol_drop),
                            str(qos_sil_pkts), str(qos_sil_byte), str(qos_sil_drop),
                            str(qos_bro_pkts), str(qos_bro_byte), str(qos_bro_drop),
                            str(qos_tin_pkts), str(qos_tin_byte), str(qos_tin_drop),
                            str(qos_dft_pkts), str(qos_dft_byte), str(qos_dft_drop))
            else:
                results += 'QoS_PLAT_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_pla_pkts))
                results += 'QoS_PLAT_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_pla_byte))
                results += 'QoS_PLAT_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_pla_drop))
                results += 'QoS_GOLD_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_gol_pkts))
                results += 'QoS_GOLD_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_gol_byte))
                results += 'QoS_GOLD_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_gol_drop))
                results += 'QoS_SILVER_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_sil_pkts))
                results += 'QoS_SILVER_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_sil_byte))
                results += 'QoS_SILVER_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_sil_drop))
                results += 'QoS_BRONZE_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_bro_pkts))
                results += 'QoS_BRONZE_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_bro_byte))
                results += 'QoS_BRONZE_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_bro_drop))
                results += 'QoS_TIN_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_tin_pkts))
                results += 'QoS_TIN_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_tin_byte))
                results += 'QoS_TIN_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_tin_drop))
                results += 'QoS_DEFAULT_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_dft_pkts))
                results += 'QoS_DEFAULT_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_dft_byte))
                results += 'QoS_DEFAULT_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_dft_drop))
            qos_output_raw_raw = run_command(crawler_connected, "sho policy-map interface %s input | i packets" % each_interface, 2)
            function_logger.info("raw_output for host %s interface %s is %s" % (seed_hostname, each_interface, qos_output_raw_raw))
            for line in qos_output_raw_raw.splitlines():
                if "        " not in str(line):
                    qos_output_raw += str(line + "\n")
            qos_pla_pkts = int(qos_output_raw.splitlines()[-7].split(" ")[-4])
            qos_pla_byte = int(qos_output_raw.splitlines()[-7].split(" ")[-2])
            qos_gol_pkts = int(qos_output_raw.splitlines()[-6].split(" ")[-4])
            qos_gol_byte = int(qos_output_raw.splitlines()[-6].split(" ")[-2])
            qos_sil_pkts = int(qos_output_raw.splitlines()[-5].split(" ")[-4])
            qos_sil_byte = int(qos_output_raw.splitlines()[-5].split(" ")[-2])
            qos_bro_pkts = int(qos_output_raw.splitlines()[-4].split(" ")[-4])
            qos_bro_byte = int(qos_output_raw.splitlines()[-4].split(" ")[-2])
            qos_tin_pkts = int(qos_output_raw.splitlines()[-3].split(" ")[-4])
            qos_tin_byte = int(qos_output_raw.splitlines()[-3].split(" ")[-2])
            qos_dft_pkts = int(qos_output_raw.splitlines()[-2].split(" ")[-4])
            qos_dft_byte = int(qos_output_raw.splitlines()[-2].split(" ")[-2])
            if influx is None:
                results += 'QoS_PLAT_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_pla_pkts))
                results += 'QoS_PLAT_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_pla_byte))
                results += 'QoS_GOLD_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_gol_pkts))
                results += 'QoS_GOLD_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_gol_byte))
                results += 'QoS_SILVER_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_sil_pkts))
                results += 'QoS_SILVER_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_sil_byte))
                results += 'QoS_BRONZE_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_bro_pkts))
                results += 'QoS_BRONZE_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_bro_byte))
                results += 'QoS_TIN_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_tin_pkts))
                results += 'QoS_TIN_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_tin_byte))
                results += 'QoS_DEFAULT_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_dft_pkts))
                results += 'QoS_DEFAULT_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_dft_byte))
            else:
                results += 'QoS_Stats_Ingress,host=%s,interface=%s ' \
                           'pla_pks=%s,pla_bytes=%s,' \
                           'gol_pks=%s,gol_bytes=%s,' \
                           'sil_pks=%s,sil_bytes=%s,' \
                           'bro_pks=%s,bro_bytes=%s,' \
                           'tin_pks=%s,tin_bytes=%s,' \
                           'dft_pks=%s,dft_bytes=%s \n' % \
                           (seed_hostname, each_interface,
                            str(qos_pla_pkts), str(qos_pla_byte),
                            str(qos_gol_pkts), str(qos_gol_byte),
                            str(qos_sil_pkts), str(qos_sil_byte),
                            str(qos_bro_pkts), str(qos_bro_byte),
                            str(qos_tin_pkts), str(qos_tin_byte),
                            str(qos_dft_pkts), str(qos_dft_byte))
        crawler_connected.close()
        crawler_connection_pre.close()
        return results
    except paramiko.AuthenticationException:
        function_logger.warning("Auth Error HOST=%s" % seed_hostname)
        return results
    except paramiko.SSHException:
        function_logger.warning("SSH Error HOST=%s" % seed_hostname)
        return results
    except socket.error:
        function_logger.warning("Socket Error HOST=%s" % seed_hostname)
        return results
    except Exception as e:
        function_logger.warning("Unknown Error %s HOST=%s ##########" % (str(e), seed_hostname))
        return results


def login_to_host_combined(seed_hostname, seed_username, seed_password, device_OS, qos_interfaces, ip_ipv6_interfaces, influx=False, router=True, switch=False):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    function_logger.info("starting on host=%s" % seed_hostname)
    crawler_connection_pre = paramiko.SSHClient()
    crawler_connection_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    class SSHTimeout(Exception):
        signal.alarm(0)
        pass

    def signal_handler(sig, frame):
        function_logger.warning("SIGALRM on host=%s" % seed_hostname)
        raise TimeoutError
        # raise SSHTimeout

    def exit_handler(sig, frame):
        function_logger.info("SIGTERM")
        raise Exception("Caught SIGTERM")

    signal.signal(signal.SIGALRM, signal_handler)
    signal.signal(signal.SIGTERM, exit_handler)
    signal.alarm(25)
    results = ""
    try:
        function_logger.debug(seed_hostname + " Starting connection")
        crawler_connection_pre.connect(hostname=seed_hostname, port=22, username=seed_username, password=seed_password,
                                       look_for_keys=False, allow_agent=False, timeout=10)
        function_logger.debug(seed_hostname + " Invoking Shell")
        crawler_connected = crawler_connection_pre.get_transport().open_session()
        crawler_connected.invoke_shell()
        run_command(crawler_connected, "terminal length 0")
        if router:
            nat_trans_total = get_total_nat_translations(crawler_connected, device_OS, seed_hostname)
            nat_trans_icmp = get_total_icmp_nat_translations(crawler_connected, device_OS, seed_hostname)
            nat_trans_tcp = get_total_tcp_nat_translations(crawler_connected, device_OS, seed_hostname)
            nat_trans_udp = get_total_udp_nat_translations(crawler_connected, device_OS, seed_hostname)
            if influx:
                append_this = " "
                if nat_trans_total is not None:
                    append_this += 'total=%s,' % str(nat_trans_total)
                if nat_trans_icmp is not None:
                    append_this += 'icmp=%s,' % str(nat_trans_icmp)
                if nat_trans_tcp is not None:
                    append_this += 'tcp=%s,' % str(nat_trans_tcp)
                if nat_trans_udp is not None:
                    append_this += 'udp=%s,' % str(nat_trans_udp)
                results += 'NAT_Translations,host=%s%s \n' % (seed_hostname, append_this[:-1])
            else:
                if nat_trans_total is not None:
                    results += 'NAT_Active_NAT_Total{host="%s"} %s\n' % (seed_hostname, str(nat_trans_total))
                if nat_trans_icmp is not None:
                    results += 'NAT_Active_NAT_ICMP{host="%s"} %s\n' % (seed_hostname, str(nat_trans_icmp))
                if nat_trans_tcp is not None:
                    results += 'NAT_Active_NAT_TCP{host="%s"} %s\n' % (seed_hostname, str(nat_trans_tcp))
                if nat_trans_udp is not None:
                    results += 'NAT_Active_NAT_UDP{host="%s"} %s\n' % (seed_hostname, str(nat_trans_udp))
            for each_interface in qos_interfaces:
                qos_output_raw = run_command(crawler_connected, "sho policy-map interface %s output | i pkts|no-buffer" % each_interface)
                qos_pla_pkts = int(qos_output_raw.splitlines()[-12].split(" ")[-1].split("/")[0])
                qos_pla_byte = int(qos_output_raw.splitlines()[-12].split(" ")[-1].split("/")[1])
                qos_pla_drop = int(qos_output_raw.splitlines()[-13].split("/")[-2])
                qos_gol_pkts = int(qos_output_raw.splitlines()[-10].split(" ")[-1].split("/")[0])
                qos_gol_byte = int(qos_output_raw.splitlines()[-10].split(" ")[-1].split("/")[1])
                qos_gol_drop = int(qos_output_raw.splitlines()[-11].split("/")[-3])
                qos_sil_pkts = int(qos_output_raw.splitlines()[-8].split(" ")[-1].split("/")[0])
                qos_sil_byte = int(qos_output_raw.splitlines()[-8].split(" ")[-1].split("/")[1])
                qos_sil_drop = int(qos_output_raw.splitlines()[-9].split("/")[-3])
                qos_bro_pkts = int(qos_output_raw.splitlines()[-6].split(" ")[-1].split("/")[0])
                qos_bro_byte = int(qos_output_raw.splitlines()[-6].split(" ")[-1].split("/")[1])
                qos_bro_drop = int(qos_output_raw.splitlines()[-7].split("/")[-3])
                qos_tin_pkts = int(qos_output_raw.splitlines()[-4].split(" ")[-1].split("/")[0])
                qos_tin_byte = int(qos_output_raw.splitlines()[-4].split(" ")[-1].split("/")[1])
                qos_tin_drop = int(qos_output_raw.splitlines()[-5].split("/")[-3])
                qos_dft_pkts = int(qos_output_raw.splitlines()[-2].split(" ")[-1].split("/")[0])
                qos_dft_byte = int(qos_output_raw.splitlines()[-2].split(" ")[-1].split("/")[1])
                qos_dft_drop = int(qos_output_raw.splitlines()[-3].split("/")[-3])
                if influx:
                    results += 'QoS_Stats_Egress,host=%s,interface=%s ' \
                               'pla_pks=%s,pla_bytes=%s,pla_drops=%s,' \
                               'gol_pks=%s,gol_bytes=%s,gol_drops=%s,' \
                               'sil_pks=%s,sil_bytes=%s,sil_drops=%s,' \
                               'bro_pks=%s,bro_bytes=%s,bro_drops=%s,' \
                               'tin_pks=%s,tin_bytes=%s,tin_drops=%s,' \
                               'dft_pks=%s,dft_bytes=%s,dft_drops=%s \n' % \
                               (seed_hostname, each_interface,
                                str(qos_pla_pkts), str(qos_pla_byte), str(qos_pla_drop),
                                str(qos_gol_pkts), str(qos_gol_byte), str(qos_gol_drop),
                                str(qos_sil_pkts), str(qos_sil_byte), str(qos_sil_drop),
                                str(qos_bro_pkts), str(qos_bro_byte), str(qos_bro_drop),
                                str(qos_tin_pkts), str(qos_tin_byte), str(qos_tin_drop),
                                str(qos_dft_pkts), str(qos_dft_byte), str(qos_dft_drop))
                else:
                    results += 'QoS_PLAT_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_pla_pkts))
                    results += 'QoS_PLAT_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_pla_byte))
                    results += 'QoS_PLAT_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_pla_drop))
                    results += 'QoS_GOLD_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_gol_pkts))
                    results += 'QoS_GOLD_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_gol_byte))
                    results += 'QoS_GOLD_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_gol_drop))
                    results += 'QoS_SILVER_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_sil_pkts))
                    results += 'QoS_SILVER_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_sil_byte))
                    results += 'QoS_SILVER_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_sil_drop))
                    results += 'QoS_BRONZE_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_bro_pkts))
                    results += 'QoS_BRONZE_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_bro_byte))
                    results += 'QoS_BRONZE_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_bro_drop))
                    results += 'QoS_TIN_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_tin_pkts))
                    results += 'QoS_TIN_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_tin_byte))
                    results += 'QoS_TIN_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_tin_drop))
                    results += 'QoS_DEFAULT_OUT_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_dft_pkts))
                    results += 'QoS_DEFAULT_OUT_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_dft_byte))
                    results += 'QoS_DEFAULT_OUT_Drops{host="%s"} %s\n' % (seed_hostname, str(qos_dft_drop))
                qos_output_raw_raw = run_command(crawler_connected, "sho policy-map interface %s input | i packets" % each_interface)
                for line in qos_output_raw_raw.splitlines():
                    if "        " not in str(line):
                        qos_output_raw += str(line + "\n")
                qos_pla_pkts = int(qos_output_raw.splitlines()[-7].split(" ")[-4])
                qos_pla_byte = int(qos_output_raw.splitlines()[-7].split(" ")[-2])
                qos_gol_pkts = int(qos_output_raw.splitlines()[-6].split(" ")[-4])
                qos_gol_byte = int(qos_output_raw.splitlines()[-6].split(" ")[-2])
                qos_sil_pkts = int(qos_output_raw.splitlines()[-5].split(" ")[-4])
                qos_sil_byte = int(qos_output_raw.splitlines()[-5].split(" ")[-2])
                qos_bro_pkts = int(qos_output_raw.splitlines()[-4].split(" ")[-4])
                qos_bro_byte = int(qos_output_raw.splitlines()[-4].split(" ")[-2])
                qos_tin_pkts = int(qos_output_raw.splitlines()[-3].split(" ")[-4])
                qos_tin_byte = int(qos_output_raw.splitlines()[-3].split(" ")[-2])
                qos_dft_pkts = int(qos_output_raw.splitlines()[-2].split(" ")[-4])
                qos_dft_byte = int(qos_output_raw.splitlines()[-2].split(" ")[-2])
                if influx is None:
                    results += 'QoS_PLAT_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_pla_pkts))
                    results += 'QoS_PLAT_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_pla_byte))
                    results += 'QoS_GOLD_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_gol_pkts))
                    results += 'QoS_GOLD_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_gol_byte))
                    results += 'QoS_SILVER_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_sil_pkts))
                    results += 'QoS_SILVER_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_sil_byte))
                    results += 'QoS_BRONZE_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_bro_pkts))
                    results += 'QoS_BRONZE_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_bro_byte))
                    results += 'QoS_TIN_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_tin_pkts))
                    results += 'QoS_TIN_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_tin_byte))
                    results += 'QoS_DEFAULT_IN_Pkts{host="%s"} %s\n' % (seed_hostname, str(qos_dft_pkts))
                    results += 'QoS_DEFAULT_IN_Bytes{host="%s"} %s\n' % (seed_hostname, str(qos_dft_byte))
                else:
                    results += 'QoS_Stats_Ingress,host=%s,interface=%s ' \
                               'pla_pks=%s,pla_bytes=%s,' \
                               'gol_pks=%s,gol_bytes=%s,' \
                               'sil_pks=%s,sil_bytes=%s,' \
                               'bro_pks=%s,bro_bytes=%s,' \
                               'tin_pks=%s,tin_bytes=%s,' \
                               'dft_pks=%s,dft_bytes=%s \n' % \
                               (seed_hostname, each_interface,
                                str(qos_pla_pkts), str(qos_pla_byte),
                                str(qos_gol_pkts), str(qos_gol_byte),
                                str(qos_sil_pkts), str(qos_sil_byte),
                                str(qos_bro_pkts), str(qos_bro_byte),
                                str(qos_tin_pkts), str(qos_tin_byte),
                                str(qos_dft_pkts), str(qos_dft_byte))
            for each_interface in ip_ipv6_interfaces:
                results += get_total_v4_v6_split(crawler_connected, device_OS, seed_hostname, each_interface, influx)
        elif switch:
            print("switch")
        signal.alarm(0)
        crawler_connected.close()
        crawler_connection_pre.close()
    except IndexError:
        function_logger.warning("Index Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("raw_output was %s" % str(qos_output_raw))
        signal.alarm(0)
    except ValueError:
        function_logger.warning("Value Error HOST=%s ##########" % seed_hostname)
        function_logger.warning("raw_output was %s" % str(qos_output_raw))
        signal.alarm(0)
    except paramiko.AuthenticationException:
        function_logger.warning("Auth Error HOST=%s" % seed_hostname)
        signal.alarm(0)
    except paramiko.SSHException:
        function_logger.warning("SSH Error HOST=%s" % seed_hostname)
        signal.alarm(0)
    except socket.error:
        function_logger.warning("Socket Error HOST=%s" % seed_hostname)
        signal.alarm(0)
    except TimeoutError:
        function_logger.warning("Timeout error HOST=%s" % seed_hostname)
        signal.alarm(0)
    except Exception as e:
        function_logger.error("something went bad collecting from host")
        function_logger.error("Unknown Error %s HOST=%s ##########" % (str(e), seed_hostname))
        function_logger.error("Unexpected error:%s" % str(sys.exc_info()[0]))
        function_logger.error("Unexpected error:%s" % str(e))
        function_logger.error("TRACEBACK=%s" % str(traceback.format_exc()))
        signal.alarm(0)
    signal.alarm(0)
    function_logger.info("finishing on host=%s" % seed_hostname)
    return results


def process_hosts_in_parallel_combined(influx=False):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    function_logger.info("----------- Processing Parallel -----------")
    results = ""
    hosts = []
    for each in HOSTS:
        host_details = []
        host_details.append(each['host'])
        host_details.append(each['username'])
        host_details.append(each['password'])
        host_details.append(each['OS'])
        host_details.append(each['qos_interfaces'])
        host_details.append(each['ip_ipv6_interfaces'])
        if influx:
            host_details.append(True)
        hosts.append(host_details)
    with Pool(processes=MAX_THREADS) as process_worker:
        try:
            results = process_worker.starmap(login_to_host_combined, hosts)
        except Exception as e:
            function_logger.error("Unexpected error:%s" % str(sys.exc_info()[0]))
            function_logger.error("Unexpected error:%s" % str(e))
            function_logger.error("TRACEBACK=%s" % str(traceback.format_exc()))
    function_logger.info("----------- Done Processing Parallel -----------")
    return results


def process_hosts_in_parallel_nat(influx=False):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    function_logger.info("----------- Processing Parallel -----------")
    results = ""
    hosts = []
    for each in HOSTS:
        host_details = []
        host_details.append(each['host'])
        host_details.append(each['username'])
        host_details.append(each['password'])
        host_details.append(each['OS'])
        if influx:
            host_details.append(True)
        hosts.append(host_details)
    with Pool(processes=MAX_THREADS) as process_worker:
        results = process_worker.starmap(login_to_host_nat, hosts)
    return results


def process_hosts_in_parallel_qos(influx=False):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    function_logger.info("----------- Processing Parallel -----------")
    results = ""
    hosts = []
    for each in HOSTS:
        host_details = []
        host_details.append(each['host'])
        host_details.append(each['username'])
        host_details.append(each['password'])
        host_details.append(each['OS'])
        host_details.append(each['qos_interfaces'])
        host_details.append(each['ip_ipv6_interfaces'])
        hosts.append(host_details)
        if influx:
            host_details.append(True)
    with Pool(processes=MAX_THREADS) as process_worker:
        results = process_worker.starmap(login_to_host_qos, hosts)
    return results


# def parse_all_arguments():
#     function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
#     parser = argparse.ArgumentParser(description='process input')
#     parser.add_argument("-d", "--debug", action='store_true', default=False, help="increase output verbosity", )
#     parser.add_argument("-s", "--single_thread", action='store_true', default=False, help="run in single threaded mode")
#     parser.add_argument("-t", "--max_threads", default=10, help="max number of threads to run in parrellel")
#     parser.add_argument("-ACCEPTEULA", "--acceptedeula", action='store_true', default=False,
#                         help="Marking this flag accepts EULA embedded withing the script")
#     args = parser.parse_args()
#     if not args.acceptedeula:
#         print("""you need to accept the EULA agreement which is as follows:-
#     # EULA
#     # This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges
#     # with a varity of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and
#     # arrangements. Until provison of alcohol or baked goodies your on your own but there is no rocket sciecne
#     # involved so dont panic too much. To accept this EULA you must include the correct flag when running the script.
#     # If this script goes crazy wrong and breaks everything then your also on your own and Phil will not accept any
#     # liability of any type or kind. As this script belongs to Phil and NOT Cisco then Cisco cannot be held
#     # responsable for its use or if it goes bad, nor can Cisco make any profit from this script. Phil can profit
#     # from this script but will not assume any liability. Other than the boaring stuff please enjoy and plagerise
#     # as you like (as I have no ways to stop you) but common curtacy says to credit me in some way.
#     # [see above comments on Beer, Wine, Steak and Greggs.].
#
#     # To accept the EULA please run with the -ACCEPTEULA flag
#         """)
#         quit()
#     return args


@flask_app.route('/nat_stats')
# gets called via the http://127.0.0.1:8082/nat_stats
def get_stats_nat():
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    results = process_hosts_in_parallel_nat()
    return Response(results, mimetype='text/plain')


@flask_app.route('/qos_stats')
# gets called via the http://127.0.0.1:8082/qos_stats
def get_stats_qos():
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    results = process_hosts_in_parallel_qos()
    return Response(results, mimetype='text/plain')


def graceful_killer(signal_number, frame):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    function_logger.info("Got Kill signal")
    function_logger.info('Received:' + str(signal_number))
    try:
        THREAD_TO_BREAK.set()
        function_logger.info("set thread to break")
        if INFLUX_MODE:
            router_stats_thread.join()
        function_logger.info("joined all threads")
        if FLASK_MODE:
            http_server.stop()
            function_logger.info("stopped HTTP server")
    except Exception as e:
        function_logger.error("Unexpected error:" + str(sys.exc_info()[0]))
        function_logger.error("Unexpected error:" + str(e))
        function_logger.debug("TRACEBACK=" + str(traceback.format_exc()))
    quit()

def router_stats_combined():
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    function_logger.info("router stats_combined_thread")
    historical_upload = ""
    while not THREAD_TO_BREAK.is_set():
        now = datetime.now()
        timestamp_string = str(int(now.timestamp()) * 1000000000)
        future = now + timedelta(seconds=30)
        influx_upload = process_hosts_in_parallel_combined(influx=True)
        to_send = ""
        for host_response in influx_upload:
            for each in host_response.splitlines():
                to_send += each + " " + timestamp_string + "\n"
        if not historical_upload == "":
            function_logger.debug("adding history to upload")
            to_send += historical_upload
        if update_influx(to_send):
            historical_upload = ""
        else:
            max_lines = 100
            line_number = 0
            historical_upload = ""
            for line in to_send.splitlines():
                if line_number < max_lines:
                    historical_upload += line + "\n"
                    line_number += 1
        time_to_sleep = (future - datetime.now()).seconds
        if 30 > time_to_sleep > 0:
            THREAD_TO_BREAK.wait(time_to_sleep)


def update_influx(raw_string, timestamp=None):
    function_logger = logger.getChild("%s.%s.%s" % (inspect.stack()[2][3], inspect.stack()[1][3], inspect.stack()[0][3]))
    function_logger.debug("update_influx")
    try:
        string_to_upload = ""
        if timestamp is not None:
            timestamp_string = str(int(timestamp.timestamp()) * 1000000000)
            for each in raw_string.splitlines():
                string_to_upload += each + " " + timestamp_string + "\n"
        else:
            string_to_upload = raw_string
        success_array = []
        upload_to_influx_sessions = requests.session()
        for influx_url in INFLUX_DB_PATH:
            success = False
            attempts = 0
            attempt_error_array = []
            while attempts < 5 and not success:
                try:
                    upload_to_influx_sessions_response = upload_to_influx_sessions.post(url=influx_url, data=string_to_upload, timeout=(20, 10))
                    if upload_to_influx_sessions_response.status_code == 204:
                        function_logger.debug("content=%s" % upload_to_influx_sessions_response.content)
                        success = True
                    else:
                        attempts += 1
                        function_logger.warning("status_code=%s" % upload_to_influx_sessions_response.status_code)
                        function_logger.warning("content=%s" % upload_to_influx_sessions_response.content)
                except requests.exceptions.ConnectTimeout as e:
                    attempts += 1
                    function_logger.debug("attempted " + str(attempts) + " Failed Connection Timeout")
                    function_logger.debug("Unexpected error:" + str(sys.exc_info()[0]))
                    function_logger.debug("Unexpected error:" + str(e))
                    function_logger.debug("String was:" + str(string_to_upload).splitlines()[0])
                    function_logger.debug("TRACEBACK=" + str(traceback.format_exc()))
                    attempt_error_array.append(str(sys.exc_info()[0]))
                except requests.exceptions.ConnectionError as e:
                    attempts += 1
                    function_logger.debug("attempted " + str(attempts) + " Failed Connection Error")
                    function_logger.debug("Unexpected error:" + str(sys.exc_info()[0]))
                    function_logger.debug("Unexpected error:" + str(e))
                    function_logger.debug("String was:" + str(string_to_upload).splitlines()[0])
                    function_logger.debug("TRACEBACK=" + str(traceback.format_exc()))
                    attempt_error_array.append(str(sys.exc_info()[0]))
                except Exception as e:
                    function_logger.error("attempted " + str(attempts) + " Failed")
                    function_logger.error("Unexpected error:" + str(sys.exc_info()[0]))
                    function_logger.error("Unexpected error:" + str(e))
                    function_logger.error("String was:" + str(string_to_upload).splitlines()[0])
                    function_logger.debug("TRACEBACK=" + str(traceback.format_exc()))
                    attempt_error_array.append(str(sys.exc_info()[0]))
                    break
            success_array.append(success)
        upload_to_influx_sessions.close()
        super_success = False
        for each in success_array:
            if not each:
                super_success = False
                break
            else:
                super_success = True
        if not super_success:
            function_logger.error("update_influx - FAILED after 5 attempts. Failed up update " + str(string_to_upload.splitlines()[0]))
            function_logger.error("update_influx - FAILED after 5 attempts. attempt_error_array: " + str(attempt_error_array))
            return False
        else:
            function_logger.debug("string for influx is %s" % str(string_to_upload))
            function_logger.debug("influx status code is %s" % str(upload_to_influx_sessions_response.status_code))
            function_logger.debug("influx response is code is %s" % str(upload_to_influx_sessions_response.text[0:1000]))
            return True
    except Exception as e:
        function_logger.error("something went bad sending to InfluxDB")
        function_logger.error("Unexpected error:%s" % str(sys.exc_info()[0]))
        function_logger.error("Unexpected error:%s" % str(e))
        function_logger.error("TRACEBACK=%s" % str(traceback.format_exc()))
    return False


if __name__ == '__main__':
    # Create Logger
    logger = logging.getLogger("Python_Monitor")
    logger_handler = logging.handlers.TimedRotatingFileHandler(LOGFILE, backupCount=30, when='D')
    logger_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(process)d:%(thread)d:%(name)s - %(message)s')
    logger_handler.setFormatter(logger_formatter)
    logger.addHandler(logger_handler)
    logger.setLevel(logging.INFO)
    logger.info("---------------------- STARTING ----------------------")
    logger.info("__main__ - " + "Python Monitor Logger")

    # Catch SIGTERM etc
    signal.signal(signal.SIGHUP, graceful_killer)
    signal.signal(signal.SIGTERM, graceful_killer)

    # Start the cron type jobs
    logger.info("start the cron update thread")
    if INFLUX_MODE:
        router_stats_thread = threading.Thread(target=lambda: router_stats_combined())
        router_stats_thread.start()

    # build flask instance.
    if FLASK_MODE:
        logger.info("__main__ - " + "starting flask")
        http_server = wsgiserver.WSGIServer(host=FLASK_HOST, port=FLASK_PORT, wsgi_app=flask_app)
        http_server.start()
