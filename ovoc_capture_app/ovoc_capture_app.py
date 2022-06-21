"""OVOC APP: Syncrhonize network captures between OVOC server and CPE device."""

"""
-------------------------------------------------------------------------------
Script: ovoc_capture_app.py

Description:

This script starts a UDP listener server on an OVOC server and waits for
requests from a 'cpe_capture_app.py' script. The requests received tell this
script to trigger a 'tcpdump' application filtering on a specific CPE device.

There are a mimimum of two scripts that will be required to be run.

    cpe_capture_app.py  (Script should be run on a separate host server that
                         will have ability to have additional Python modules
                         installed like 'requests', 'paramiko', etc. This
                         script DOES NOT have to be run with 'root' 
                         privileges.)

    ovoc_capture_app.py (Script should be run on each OVOC server that is
                         associated with a CPE device being targeted for
                         network traffic captures. This script MUST BE run
                         with 'root' privileges since it will issue system
                         calls to start the linux 'tcpdump' application.)

This script can be run simultaneously on several OVOC servers if needed,
depending on the list of CPE devices entered in the 'cpe_capture_app.py'
target devices list.

Running the 'cpe_capture_app.py' script on a separate server other than an
OVOC server is required since the goal is to understand why an OVOC server
may be losing connectivity to the CPE devices. The intent is that the
separate server will not lose connectivity to the CPE device and be able to
remain in communications with the CPE to issue REST API commands to control
and retrieve debug captures without failure.

The goal is the attempt catch an event where SNMP traffic is not being seen
on the CPE device and it loses management connectivity with the OVOC server.

The traffic captures on the OVOC servers running this script are started
and stopped using UDP signalled requests from the 'cpe_capture_app.py'
script. Requests are sent to this script to the 'listen_port' defined for in
this scripts 'config.py' file.

On the OVOC servers, the network captures are performed by issuing system
calls to the 'tcpdump' app. To start a capture on an OVOC server, this script
receives a 'CAPTURE' request sent from the CPE controller app to inform this
OVOC server of which CPE traffic should be filtered and captured using
'tcpdump'. This OVOC capture app script responds with a '100 Trying' when 
setting up the tcpdump, and a '200 OK' when the tcpdump process is running.
The response will be '503 Service Unavailable' if the capture fails to be
started. The captures are stopped on this OVOC server after the CPE 
controller app script 'cpe_capture_app.py' receives the 'Connection Lost'
SNMP alarm. That CPE app script will send a 'STOP' request to the appropriate
OVOC server app that will trigger this script to kill the tcpdump process for
that CPE device.

The following messages are exchanged:


  CPE script                                 This script
       |                                           |
       |-------- CAPTURE <device address> -------->|
       |                                           |
       |<------ 100 TRYING <device address> -------|
       |                                           |
       |<-------- 200 OK <device address> ---------|
       |                                           |
       |---- STOP <device address> <filename> ---->|
       |                                           |
       |<------ 100 TRYING <device address> -------|
       |                                           |
       |<-------- 200 OK <device address> ---------|
       |                                           |

If this script receives a request and the device address is not found in the
devices information dictionary, then a '404 Not Found' is returned.

If the capture fails to be started or fails to stop, then the response will
be a '503 Service Unavailable'.

This script tracks capture states, all tasks, and other information for each
targeted CPE device. The 'devices_info' dictionary is created to track each
devices information. The following is an example of what is tracked:

 {
     "devices": [
         {
             "device": "<device ip address>",
             "status": "Success|Failure",
             "ovocCapture": "active|not active",
             "description": "<some description>",
             "cpeFilename": "<CPE capture filename>",
             "lastCapture": "<last stopped capture filename>",
             "lastRequest": "<some request>",
             "lastResponse": "<some response>",
             "severity": "NORMAL|MINOR|MAJOR|CRITICAL",
             "tasks": [
                 {
                     "task": "<task name>",
                     "timestamp": "%Y-%m-%dT%H:%M:%S:%f%z",
                     "status": "Success|Failure",
                     "description": "<status information>",
                 },
                 ...
                 <Next Task>
             ]
         },
         ...
         <Next Device>
     ]
 }
 
 For a 'Stop capture' task, the following item is added to the task items:
                     "filename": "<capture filename>",

-------------------------------------------------------------------------------
"""

import io
import os
import sys
import re
import csv
import json
import logging
import json
import time
import socket
import gzip
import shutil
#import pathlib
import glob

from datetime import datetime
from getpass import getpass

# Import config.py
import config

# ------------------------------ #
# Check for root user privileges #
# ------------------------------ #
if os.geteuid() != 0:
    event = 'Must be root user to run this script!'
    print('ERROR: {}'.format(event))
    exit(1)

# ---------------------------- #
# Log File Format and Settings #
# ---------------------------- #
#pathlib.Path(config.storage_dir).mkdir(parents=True, exist_ok=True)
try:
    if not os.path.isdir(config.storage_dir):
        os.makedirs(config.storage_dir)
        print('Log directory [{}] created successfully.'.format(config.storage_dir))
except OSError as error:
    print('ERROR: Log directory [{}] can not be created!'.format(config.storage_dir))
    exit(1)
app_log_level = config.app_log_level
app_log_file = config.storage_dir + '/' + config.app_log_file
app_log_handler = logging.FileHandler(app_log_file)
app_log_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s", datefmt='%d-%b-%Y %H:%M:%S'))
logger = logging.getLogger('trafficCapture')
logger.setLevel(app_log_level)
logger.addHandler(app_log_handler)

# -------------------------- #
# Set log ID for this script #
# -------------------------- #
log_id = '[SID=' + str(os.getpid()) + ']'

# --------------------------------------------------------------------------- #
# FUNCTION: rotate_logs                                                       #
#                                                                             #
# Check to see if the logs files need to be rotated due to the 'current' log  #
# log size being >= '???_max_log_file_size' parameter. The total number of    #
# archived log files is set by the parameter '???_archived_files'. These      #
# parameters are defined in the 'config.py' file and passed to the function   #
# as argument parameters.                                                     #
#                                                                             #
# The 'current' log file path and basename are also defined in the            #
# 'config.py' configuration file. The log file is passed into this function   #
# as a parameter as well.                                                     #
#                                                                             #
# Parameters:                                                                 #
#     logger         - File handler for storing logged actions                #
#     log_id         - Unique identifier for this devices log entries         #
#     log_file       - User's log file path and name                          #
#     max_size       - Maximum size for current log file                      #
#     archived_files - Maxiumn number of archived files to store              #
#                                                                             #
# Return values:                                                              #
#     status - 'True' if log files rotated, else 'False'                      #
# --------------------------------------------------------------------------- #
def rotate_logs(logger, log_id, log_file, max_size, archived_files):
    """Rotate log files if current log file is >= to defined max file size."""

    status = False

    # ------------------------------------------- #
    # Append storage directory to 'log_file' name #
    # ------------------------------------------- #
    log_file = config.storage_dir + '/' + log_file

    # --------------------------- #
    # Check current log file size #
    # --------------------------- #
    if os.path.exists(log_file):
        if os.path.getsize(log_file) >= max_size * 1048576:

            event = 'Rotating [{}] log files...'.format(log_file)
            logger.info('{} - {}'.format(log_id, event))

            # -------------------------------------------------- #
            # Shift existing archived files down one position in #
            # the archived files stored.  If max files exist,    #
            # then oldest file is removed from system.           #
            # -------------------------------------------------- #
            for index in range(archived_files, 0, -1):

                if os.path.exists(log_file + '.' + str(index) + '.gz'):

                    if index == archived_files:
                        # --------------------------- #
                        # Remove file from filesystem #
                        # --------------------------- #
                        try:
                            os.remove(log_file + '.' + str(index) + '.gz')
                        except Exception as err:
                            event = 'Error removing oldest archived file from filesystem: {}'.format(err)
                            logger.error('{} - {}'.format(log_id, event))
                            event = 'System error: {}'.format(sys.exc_info()[0:])
                            logger.error('{} - {}'.format(log_id, event))

                    else:
                        # -------------------------------------------- #
                        # Shift other files down one archived position #
                        # -------------------------------------------- #
                        try:
                            os.rename(log_file + '.' + str(index) + '.gz', log_file + '.' + str(index + 1) + '.gz')
                        except Exception as err:
                            event = 'Log file rotation error: {}'.format(err)
                            logger.error('{} - {}'.format(log_id, event))
                            event = 'System error: {}'.format(sys.exc_info()[0:])
                            logger.error('{} - {}'.format(log_id, event))

            # ------------------------------------------------------- #
            # File shouldn't be here at this point, but double check. #
            # Remove current archived file in position '1' if exists. #
            # ------------------------------------------------------- #
            if os.path.exists(log_file + '.1.gz'):
                try:
                    os.remove(log_file + '.1.gz')
                except Exception as err:
                    event = 'Error removing archived file in position [1] from filesystem: {}'.format(err)
                    logger.error('{} - {}'.format(log_id, event))
                    event = 'System error: {}'.format(sys.exc_info()[0:])
                    logger.error('{} - {}'.format(log_id, event))

            # ------------------------------------------------ #
            # Archive current log file as archive position '1' #
            # ------------------------------------------------ #
            if os.path.exists(log_file):
                try:
                    #os.rename(log_file, log_file + '.1')

                    # ------------------ #
                    # Store as gzip file #
                    # ------------------ #
                    try:
                        with open(log_file, 'rb') as file_in, gzip.open(log_file + '.1.gz', 'wb') as file_out:
                            shutil.copyfileobj(file_in, file_out)

                    except Exception as err:
                        event = 'Rotate current log file error: {}'.format(err)
                        logger.error('{} - {}'.format(log_id, event))
                        event = 'System error: {}'.format(sys.exc_info()[0:])
                        logger.error('{} - {}'.format(log_id, event))

                    # ---------------------------------- #
                    # Clear contents of current log file #
                    # ---------------------------------- #
                    try:
                        open(log_file, 'w').close()
                        status = True

                    except Exception as err:
                        event = 'Error clearing current log file: {}'.format(err)
                        logger.error('{} - {}'.format(log_id, event))
                        event = 'System error: {}'.format(sys.exc_info()[0:])
                        logger.error('{} - {}'.format(log_id, event))

                except Exception as err:
                    event = 'Log file rotation error: {}'.format(err)
                    logger.error('{} - {}'.format(log_id, event))
                    event = 'System error: {}'.format(sys.exc_info()[0:])
                    logger.error('{} - {}'.format(log_id, event))
            else:
                event = 'Unable to archive current log file! File in archive position one already exists'
                logger.error('{} - {}'.format(log_id, event))

    return status

# --------------------------------------------------------------------------- #
# FUNCTION: send_rest                                                         #
#                                                                             #
# Send REST API request to server and return response.                        #
#                                                                             #
# Parameters:                                                                 #
#    method    - HTML method type: GET, PUT, or POST                          #
#    url       - Location to send REST request                                #
#    username  - Username for REST authentication on OVOC server              #
#    password  - Password for REST authentication on OVOC server              #
#    data      - data formatted according to 'data_type' to send to           #
#                OVOC server                                                  #
#    data_type - Type of data in the 'data' parameter.                        #
#                Either: 'files' or 'json'                                    #
#                    'files' sends 'Content-Type: multipart/form-data'        #
#                    'json'  sends 'Content-Type: application/json'           #
#                                                                             #
# Return:                                                                     #
#    response - HTML Response Object that contains elements with the          #
#               'status code' and response 'text' from OVOC server            #
# --------------------------------------------------------------------------- #
def send_rest(method, url, username, password, data=None, data_type='json'):
    """Send REST API request to server and return response."""

    # ----------------------------- #
    # Set with Basic Authentication #
    # ----------------------------- #
    pwd = username + ':' + password
    headers = {'Authorization': 'Basic ' + base64.b64encode(pwd.encode('utf-8', 'ignore')).decode('utf-8', 'ignore')}

    # ------------------------------------------ #
    # Send REST request based on the method type #
    # ------------------------------------------ #
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, verify=False, timeout=(3, 6), allow_redirects=False)
        elif method == 'POST':
            if data_type == 'json':
                response = requests.post(url, data, headers=headers, verify=False, timeout=(3, 6), allow_redirects=False)
            elif data_type == 'files':
                response = requests.post(url, files=data, headers=headers, verify=False, timeout=(3, 6), allow_redirects=False)
        elif method == 'PUT':
            if data_type == 'json':
                response = requests.put(url, data, headers=headers, verify=False, timeout=(3, 6), allow_redirects=False)
            elif data_type == 'files':
                response = requests.put(url, files=data, headers=headers, verify=False, timeout=(3, 6), allow_redirects=False)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, verify=False, timeout=(3, 6), allow_redirects=False)

    except Exception as err:
        response = str(err)

    return response

# --------------------------------------------------------------------------- #
# FUNCTION: get_address_type                                                  #
#                                                                             #
# Check is address is a valid IPv4, IPv6, or FQDN.                            #
#                                                                             #
# Parameters:                                                                 #
#     address - IPv4, IPv6, or FQDN address                                   #
#                                                                             #
# Return:                                                                     #
#     address_type - String: 'ipv4', 'ipv6', or 'fqdn'                        #
# --------------------------------------------------------------------------- #
def get_address_type(address):
    """Check for type of address, either IPv4, IPv6, or FQDN."""

    address_type = 'unknown'

    # ----------------- #
    # Check IPv4 format #
    # ----------------- #
    if re.match('^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', address):
        address_type = 'ipv4'

    if address_type == 'unknown':
        # ----------------- #
        # Check IPv6 format #
        # ----------------- #
        if re.match('^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$', address):
            address_type = 'ipv6'

    if address_type == 'unknown':
        # ----------------- #
        # Check FQDN format #
        # ----------------- #
        if re.match('^(?=.{1,254}$)((?=[a-z0-9-]{1,63}\.)(xn--+)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$', address):
            address_type = 'fqdn'

    return address_type

# --------------------------------------------------------------------------- #
# FUNCTION: get_device_id                                                     #
#                                                                             #
# Submit a REST API query to get the ID of a device managed by this OVOC      # 
# server.                                                                     #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     target_device - CPE device stored on OVOC server                        #
#     credentials   - Credentials for REST API account on OVOC server         #
#                                                                             #
# Return:                                                                     #
#    task_info - Dictionary containing the following items:                   #
#        status      - String: 'Success' or 'Fail'                            #
#        statusCode  - Integer: REST response status code. (Ex: 200)          #
#        deviceId    - Integer: -1 for not found, >= 0 for ID of device       #
#        description - String: Description of the task action                 #
# --------------------------------------------------------------------------- #
def get_device_id(logger, log_id, target_device, credentials):
    """Get ID of device managed by OVOC server."""

    # ------------------------------------------- #
    # Create a dictionary to hold the relevant    #
    # information to return for the current task. #
    # ------------------------------------------- #
    task_info = {}
    task_info['task'] = 'Check for Device'
    task_info['status'] = 'Fail'
    task_info['statusCode'] = -1
    task_info['deviceId'] = -1
    task_info['description'] = ''

    # ---------------- #
    # Set REST API URL #
    # ---------------- #
    address_type = get_address_type(target_device)
    if address_type == 'fqdn':
        url = "https://127.0.0.1/ovoc/v1/topology/devices?detail=1&filter=(fqdn='" + target_device + "')"
    else:
        url = "https://127.0.0.1/ovoc/v1/topology/devices?detail=1&filter=(ipAddress='" + target_device + "')"

    event = 'Method [GET]" - Request URL: {}'.format(url)
    logger.info('{} - {}'.format(log_id, event))

    # -------------------------------- #
    # Send REST request to OVOC server #
    # -------------------------------- #
    rest_response = send_rest('GET', url, credentials['username'], credentials['password'])
    rest_response_data = ''
    if type(rest_response) is str:
        rest_response_data = rest_response
        event = 'REST Request Error: {}'.format(rest_response_data)
        logger.error('{} - {}'.format(log_id, event))

        # ------------- #
        # Set task info #
        # ------------- #
        task_info['description'] = event

        event = 'REST request failed. Could not verify if CPE device is on OVOC server.'
        logger.warning('{} - {}'.format(log_id, event))
    else:
        if 'Content-Type' in rest_response.headers:
            if re.search('application/json', rest_response.headers['Content-Type']):
                rest_response_data = {}
                if len(rest_response.text) > 0:
                    rest_response_data = json.loads(rest_response.text)
                event = 'REST Response application/json Content-Type:\n{}'.format(json.dumps(rest_response_data, indent=4))
                logger.info('{} - {}'.format(log_id, event))
            else:
                rest_response_data = rest_response.text
                event = 'REST Response non-application/json Content-Type:\n{}'.format(rest_response_data)
                logger.info('{} - {}'.format(log_id, event))
        else:
            rest_response_data = rest_response.text
            event = 'REST Response no Content-Type:\n{}'.format(rest_response_data)
            logger.info('{} - {}'.format(log_id, event))

        if rest_response.status_code == 200:
            # ---------------------------------------------- #
            # Status Code 200 - Device exists on OVOC server #
            # ---------------------------------------------- #
            if 'devices' in rest_response_data:

                # --------------------------- #
                # Get the device id from OVOC #
                # --------------------------- #
                event = 'CPE device exists on OVOC server'
                logger.info('{} - {}'.format(log_id, event))

                # ------------- #
                # Set task info #
                # ------------- #
                task_info['status'] = 'Success'
                task_info['statusCode'] = rest_response.status_code
                task_info['deviceId'] = rest_response_data['devices'][0]['id']
                task_info['description'] = event

            else:
                event = 'Could not get CPE device ID from OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

                # ------------- #
                # Set task info #
                # ------------- #
                task_info['description'] = event
        else:
            # --------------------------------------------------- #
            # Get ID of CPE device from server was not successful #
            # --------------------------------------------------- #
            if 'description' in rest_response_data:
                event = '{}'.format(rest_response_data['description'])
                logger.warning('{} - {}'.format(log_id, event))
            else:
                event = 'Failed to get CPE device ID from OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

            # ------------- #
            # Set task info #
            # ------------- #
            task_info['statusCode'] = rest_response.status_code
            task_info['description'] = event

    return task_info

# --------------------------------------------------------------------------- #
# FUNCTION: get_fwd_rule_id                                                   #
#                                                                             #
# Submit a REST API query to get the ID of a SNMP alarm forwarding rule that  #
# is defined on this OVOC server.                                             #
#                                                                             #
# Parameters:                                                                 #
#     logger      - File handler for storing logged actions                   #
#     log_id      - Unique identifier for this devices log entries            #
#     rule_name   - SNMP alarm forwarding rule on this OVOC server            #
#     credentials - Credentials for REST API account on OVOC server           #
#                                                                             #
# Return:                                                                     #
#    task_info - Dictionary containing the following items:                   #
#        status      - String: 'Success' or 'Fail'                            #
#        statusCode  - Integer: REST response status code. (Ex: 200)          #
#        ruleId      - Integer: -1 for not found, >= 0 for ID of alarm rule   #
#        description - String: Description of the task action                 #
# --------------------------------------------------------------------------- #
def get_fwd_rule_id(logger, log_id, rule_name, credentials):
    """Get ID of a SNMP alarm forwarding rule defined on OVOC server."""

    # ------------------------------------------- #
    # Create a dictionary to hold the relevant    #
    # information to return for the current task. #
    # ------------------------------------------- #
    task_info = {}
    task_info['task'] = 'Check for Alarm Forwarding Rule'
    task_info['status'] = 'Fail'
    task_info['statusCode'] = -1
    task_info['ruleId'] = -1
    task_info['description'] = ''

    # ---------------- #
    # Set REST API URL #
    # ---------------- #
    url = "https://127.0.0.1/ovoc/v1/alarms/fwdRules?detail=1&filter=(name='" + rule_name + "')"

    event = 'Method [GET]" - Request URL: {}'.format(url)
    logger.info('{} - {}'.format(log_id, event))

    # -------------------------------- #
    # Send REST request to OVOC server #
    # -------------------------------- #
    rest_response = send_rest('GET', url, credentials['username'], credentials['password'])
    rest_response_data = ''
    if type(rest_response) is str:
        rest_response_data = rest_response
        event = 'REST Request Error: {}'.format(rest_response_data)
        logger.error('{} - {}'.format(log_id, event))

        # ------------- #
        # Set task info #
        # ------------- #
        task_info['description'] = event

        event = 'REST request failed. Could not verify if SNMP alarm forwarding rule is on OVOC server.'
        logger.warning('{} - {}'.format(log_id, event))
    else:
        if 'Content-Type' in rest_response.headers:
            if re.search('application/json', rest_response.headers['Content-Type']):
                rest_response_data = {}
                if len(rest_response.text) > 0:
                    rest_response_data = json.loads(rest_response.text)
                event = 'REST Response application/json Content-Type:\n{}'.format(json.dumps(rest_response_data, indent=4))
                logger.info('{} - {}'.format(log_id, event))
            else:
                rest_response_data = rest_response.text
                event = 'REST Response non-application/json Content-Type:\n{}'.format(rest_response_data)
                logger.info('{} - {}'.format(log_id, event))
        else:
            rest_response_data = rest_response.text
            event = 'REST Response no Content-Type:\n{}'.format(rest_response_data)
            logger.info('{} - {}'.format(log_id, event))

        if rest_response.status_code == 200:
            # ------------------------------------------------------- #
            # Status Code 200 - Forwarding rule exists on OVOC server #
            # ------------------------------------------------------- #
            if 'fwdRules' in rest_response_data:

                # ------------------------- #
                # Get the rule id from OVOC #
                # ------------------------- #
                event = 'SNMP alarm forwarding rule exists on OVOC server'
                logger.info('{} - {}'.format(log_id, event))

                # ------------- #
                # Set task info #
                # ------------- #
                task_info['status'] = 'Success'
                task_info['statusCode'] = rest_response.status_code
                task_info['ruleId'] = rest_response_data['fwdRules'][0]['id']
                task_info['description'] = event

            else:
                event = 'Could not get SNMP alarm forwarding rule ID from OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

                # ------------- #
                # Set task info #
                # ------------- #
                task_info['description'] = event
        else:
            # --------------------------------------------------- #
            # Get ID of CPE device from server was not successful #
            # --------------------------------------------------- #
            if 'description' in rest_response_data:
                event = '{}'.format(rest_response_data['description'])
                logger.warning('{} - {}'.format(log_id, event))
            else:
                event = 'Failed to get SNMP alarm forwarding rule ID from OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

            # ------------- #
            # Set task info #
            # ------------- #
            task_info['statusCode'] = rest_response.status_code
            task_info['description'] = event

    return task_info

# --------------------------------------------------------------------------- #
# FUNCTION: update_fwd_rule                                                   #
#                                                                             #
# Submit a REST API request to update the settings of a SNMP alarm forwarding #
# rule that has been defined on this OVOC server.                             #
#                                                                             #
# Parameters:                                                                 #
#     logger      - File handler for storing logged actions                   #
#     log_id      - Unique identifier for this devices log entries            #
#     rule_id     - ID of SNMP alarm forwarding rule on this OVOC server      #
#     device_id   - ID of CPE device that alarm will be forwarded for         #
#                       (-1 for all devices)                                  #
#     address     - IP address to send forwarded alarm to                     #
#     port        - IP port to send forwarded alarm to                        #
#     alarm_list  - List of alarms to forward                                 #
#                       (Refer to the OVOC Alarms Monitoring Guide for the    #
#                        exact value of the alarm name. For instance, the     #
#                        'Connection Alarm' use the SNMP name                 #
#                        'acEMSNodeConnectionLostAlarm' for the value needed  #
#                        in the OVOC alarm rule.)                             #
#     credentials - Credentials for REST API account on OVOC server           #
#                                                                             #
# Return:                                                                     #
#    task_info - Dictionary containing the following items:                   #
#        status      - String: 'Success' or 'Fail'                            #
#        statusCode  - Integer: REST response status code. (Ex: 200)          #
#        description - String: Description of the task action                 #
# --------------------------------------------------------------------------- #
def update_fwd_rule(logger, log_id, rule_id, device_id, address, port, alarm_list, credentials):
    """Update settings of a SNMP alarm forwarding rule defined on OVOC server."""

    # ------------------------------------------- #
    # Create a dictionary to hold the relevant    #
    # information to return for the current task. #
    # ------------------------------------------- #
    task_info = {}
    task_info['task'] = 'Update Alarm Forwarding Rule'
    task_info['status'] = 'Fail'
    task_info['statusCode'] = -1
    task_info['description'] = ''

    # -------------------------------- #
    # The body of the REST API request #
    # -------------------------------- #
    request_body = {}
    request_body['destSyslog'] = {}
    request_body['destSyslog']['syslogServerIP'] = address
    request_body['destSyslog']['syslogServerPort'] = port

    if device_id == -1:
        request_body['alarmTenantsFilter'] = None
        request_body['alarmRegionsFilter'] = None
        request_body['alarmEndpointsFilter'] = None
        request_body['alarmSitesFilter'] = None
        request_body['alarmDevicesFilter'] = None
    else:
        request_body['alarmTenantsFilter'] = None
        request_body['alarmRegionsFilter'] = None
        request_body['alarmEndpointsFilter'] = None
        request_body['alarmSitesFilter'] = None
        request_body['alarmDevicesFilter'] = []
        request_body['alarmDevicesFilter'].append(device_id)

    if len(alarm_list) > 0:
        request_body['alarmNamesFilter'] = alarm_list
    else:
        request_body['alarmNamesFilter'] = None

    request_body = json.dumps(request_body, indent=4)
    event = 'REST API Request Body:\n{}'.format(request_body)
    logger.info('{} - {}'.format(log_id, event))

    # ---------------- #
    # Set REST API URL #
    # ---------------- #
    url = "https://127.0.0.1/ovoc/v1/alarms/fwdRules/" + str(rule_id)

    event = 'Method [PUT]" - Request URL: {}'.format(url)
    logger.info('{} - {}'.format(log_id, event))

    # -------------------------------- #
    # Send REST request to OVOC server #
    # -------------------------------- #
    rest_response = send_rest('PUT', url, credentials['username'], credentials['password'], request_body)
    rest_response_data = ''
    if type(rest_response) is str:
        rest_response_data = rest_response
        event = 'REST Request Error: {}'.format(rest_response_data)
        logger.error('{} - {}'.format(log_id, event))

        # ------------- #
        # Set task info #
        # ------------- #
        task_info['description'] = event

        event = 'REST request failed. Could not update SNMP alarm forwarding rule on OVOC server.'
        logger.warning('{} - {}'.format(log_id, event))
    else:
        if 'Content-Type' in rest_response.headers:
            if re.search('application/json', rest_response.headers['Content-Type']):
                rest_response_data = {}
                if len(rest_response.text) > 0:
                    rest_response_data = json.loads(rest_response.text)
                event = 'REST Response application/json Content-Type:\n{}'.format(json.dumps(rest_response_data, indent=4))
                logger.info('{} - {}'.format(log_id, event))
            else:
                rest_response_data = rest_response.text
                event = 'REST Response non-application/json Content-Type:\n{}'.format(rest_response_data)
                logger.info('{} - {}'.format(log_id, event))
        else:
            rest_response_data = rest_response.text
            event = 'REST Response no Content-Type:\n{}'.format(rest_response_data)
            logger.info('{} - {}'.format(log_id, event))

        if rest_response.status_code == 200:
            # --------------------------------------------------------------------- #
            # Status Code 200 - Successfully updated forwarding rule on OVOC server #
            # --------------------------------------------------------------------- #
            event = 'Successfully updated SNMP alarm forwarding rule on OVOC server'
            logger.info('{} - {}'.format(log_id, event))

            # ------------- #
            # Set task info #
            # ------------- #
            task_info['status'] = 'Success'
            task_info['statusCode'] = rest_response.status_code
            task_info['description'] = event

        else:
            # ------------------------------------------- #
            # Update of rule on server was not successful #
            # ------------------------------------------- #
            if 'description' in rest_response_data:
                event = '{}'.format(rest_response_data['description'])
                logger.warning('{} - {}'.format(log_id, event))
            else:
                event = 'Failed to update SNMP alarm forwarding rule on OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

            # ------------- #
            # Set task info #
            # ------------- #
            task_info['statusCode'] = rest_response.status_code
            task_info['description'] = event

    return task_info

# --------------------------------------------------------------------------- #
# FUNCTION: create_fwd_rule                                                   #
#                                                                             #
# Submit a REST API request to create a new SNMP alarm forwarding rule on     #
# this OVOC server.                                                           #
#                                                                             #
# Parameters:                                                                 #
#     logger      - File handler for storing logged actions                   #
#     log_id      - Unique identifier for this devices log entries            #
#     rule_name   - Unique and descriptive name for this forwarding rule      #
#     device_id   - ID of CPE device that alarm will be forwarded for         #
#                       (-1 for all devices)                                  #
#     address     - IP address to send forwarded alarm to                     #
#     port        - IP port to send forwarded alarm to                        #
#     alarm_list  - List of alarms to forward                                 #
#                       (Refer to the OVOC Alarms Monitoring Guide for the    #
#                        exact value of the alarm name. For instance, the     #
#                        'Connection Alarm' use the SNMP name                 #
#                        'acEMSNodeConnectionLostAlarm' for the value needed  #
#                        in the OVOC alarm rule.)                             #
#     credentials - Credentials for REST API account on OVOC server           #
#                                                                             #
# Return:                                                                     #
#    task_info - Dictionary containing the following items:                   #
#        status      - String: 'Success' or 'Fail'                            #
#        statusCode  - Integer: REST response status code. (Ex: 200)          #
#        description - String: Description of the task action                 #
# --------------------------------------------------------------------------- #
def create_fwd_rule(logger, log_id, rule_name, device_id, address, port, alarm_list, credentials):
    """Create a new SNMP alarm forwarding rule on OVOC server."""

    # ------------------------------------------- #
    # Create a dictionary to hold the relevant    #
    # information to return for the current task. #
    # ------------------------------------------- #
    task_info = {}
    task_info['task'] = 'Create Alarm Forwarding Rule'
    task_info['status'] = 'Fail'
    task_info['statusCode'] = -1
    task_info['description'] = ''

    # -------------------------------- #
    # The body of the REST API request #
    # -------------------------------- #
    request_body = {}
    request_body['ruleDestType'] = 'SYSLOG'
    request_body['destSyslog'] = {}
    request_body['destSyslog']['syslogServerIP'] = address
    request_body['destSyslog']['syslogServerPort'] = port
    request_body['forwardType'] = 'ALLOW'
    request_body['name'] = rule_name
    request_body['tenantId'] = -1
    
    if device_id == -1:
        request_body['alarmTenantsFilter'] = None
        request_body['alarmRegionsFilter'] = None
        request_body['alarmEndpointsFilter'] = None
        request_body['alarmSitesFilter'] = None
        request_body['alarmDevicesFilter'] = None
    else:
        request_body['alarmTenantsFilter'] = None
        request_body['alarmRegionsFilter'] = None
        request_body['alarmEndpointsFilter'] = None
        request_body['alarmSitesFilter'] = None
        request_body['alarmDevicesFilter'] = []
        request_body['alarmDevicesFilter'].append(device_id)

    if len(alarm_list) > 0:
        request_body['alarmNamesFilter'] = alarm_list
    else:
        request_body['alarmNamesFilter'] = None

    request_body = json.dumps(request_body, indent=4)
    event = 'REST API Request Body:\n{}'.format(request_body)
    logger.info('{} - {}'.format(log_id, event))

    # ---------------- #
    # Set REST API URL #
    # ---------------- #
    url = "https://127.0.0.1/ovoc/v1/alarms/fwdRules"

    event = 'Method [POST]" - Request URL: {}'.format(url)
    logger.info('{} - {}'.format(log_id, event))

    # -------------------------------- #
    # Send REST request to OVOC server #
    # -------------------------------- #
    rest_response = send_rest('POST', url, credentials['username'], credentials['password'], request_body)
    rest_response_data = ''
    if type(rest_response) is str:
        rest_response_data = rest_response
        event = 'REST Request Error: {}'.format(rest_response_data)
        logger.error('{} - {}'.format(log_id, event))

        # ------------- #
        # Set task info #
        # ------------- #
        task_info['description'] = event

        event = 'REST request failed. Could not create SNMP alarm forwarding rule on OVOC server.'
        logger.warning('{} - {}'.format(log_id, event))
    else:
        if 'Content-Type' in rest_response.headers:
            if re.search('application/json', rest_response.headers['Content-Type']):
                rest_response_data = {}
                if len(rest_response.text) > 0:
                    rest_response_data = json.loads(rest_response.text)
                event = 'REST Response application/json Content-Type:\n{}'.format(json.dumps(rest_response_data, indent=4))
                logger.info('{} - {}'.format(log_id, event))
            else:
                rest_response_data = rest_response.text
                event = 'REST Response non-application/json Content-Type:\n{}'.format(rest_response_data)
                logger.info('{} - {}'.format(log_id, event))
        else:
            rest_response_data = rest_response.text
            event = 'REST Response no Content-Type:\n{}'.format(rest_response_data)
            logger.info('{} - {}'.format(log_id, event))

        if rest_response.status_code == 201:
            # --------------------------------------------------------------------- #
            # Status Code 201 - Successfully created forwarding rule on OVOC server #
            # --------------------------------------------------------------------- #
            if 'id' in rest_response_data:

                # ------------------------- #
                # Get the rule id from OVOC #
                # ------------------------- #
                event = 'Successfully created SNMP alarm forwarding rule on OVOC server'
                logger.info('{} - {}'.format(log_id, event))

                # ------------- #
                # Set task info #
                # ------------- #
                task_info['status'] = 'Success'
                task_info['statusCode'] = rest_response.status_code
                task_info['ruleId'] = rest_response_data['id']
                task_info['description'] = event

            else:
                event = 'Could not get new SNMP alarm forwarding rule ID from OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

                # ------------- #
                # Set task info #
                # ------------- #
                task_info['description'] = event
        else:
            # ------------------------------------------- #
            # Update of rule on server was not successful #
            # ------------------------------------------- #
            if 'description' in rest_response_data:
                event = '{}'.format(rest_response_data['description'])
                logger.warning('{} - {}'.format(log_id, event))
            else:
                event = 'Failed to create SNMP alarm forwarding rule on OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

            # ------------- #
            # Set task info #
            # ------------- #
            task_info['statusCode'] = rest_response.status_code
            task_info['description'] = event

    return task_info

# --------------------------------------------------------------------------- #
# FUNCTION: set_alarm_fwd_rule                                                #
#                                                                             #
# Check to see  API request to create a new SNMP alarm forwarding rule on     #
# this OVOC server.                                                           #
#                                                                             #
# Parameters:                                                                 #
#     logger         - File handler for storing logged actions                #
#     log_id         - Unique identifier for this devices log entries         #
#     target_device  - CPE device to create an alarm forwarded rule for       #
#                       ("" for all devices)                                  #
#     rule_name      - Unique and descriptive name for this forwarding rule   #
#     alarm_list     - List of alarms to forward                              #
#                       (Refer to the OVOC Alarms Monitoring Guide for the    #
#                        exact value of the alarm name. For instance, the     #
#                        'Connection Alarm' use the SNMP name                 #
#                        'acEMSNodeConnectionLostAlarm' for the value needed  #
#                        in the OVOC alarm rule.)                             #
#     sendto_address - Tuple of address/port of CPE capture app to send resp  #
#     credentials    - Credentials for REST API account on OVOC server        #
#     devices_info   - Dictionary of targeted devices                         #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def set_alarm_fwd_rule(logger, log_id, target_device, rule_name, alarm_list, sendto_address, credentials, devices_info)
    """Set SNMP alarm forwarding rule on OVOC server."""

    address = sendto_address[0]
    port = sendto_address[1]

    # ------------------------------------------ #
    # If setting up a global forwarding rule not #
    # associated with any targted devices.       #
    # ------------------------------------------ #
    if target_device == '':

        device_id = -1
        get_fwd_rule_task = get_fwd_rule_id(logger, log_id, rule_name, credentials)

        # ---------------------------- #
        # Create new rule if not found #
        # ---------------------------- #
        if get_fwd_rule_task['ruleId'] == -1:

            event = 'Creating global SNMP alarm forwarding rule: [{}]'.format(rule_name)
            logger.info('{} - {}'.format(log_id, event))
            print('{}'.format(event))

            create_fwd_rule_task = create_fwd_rule(logger, log_id, rule_name, device_id, address, port, alarm_list, credentials)

            event = create_fwd_rule_task['description']
            if create_fwd_rule_task['status'].lower() == 'success':
                print('  + INFO: {}'.format(event))
            else:
                print('  + CRITICAL: {}'.format(event))

        # -------------------- #
        # Update existing rule #
        # -------------------- #
        else:

            event = 'Updating global SNMP alarm forwarding rule: [{}]'.format(rule_name)
            logger.info('{} - {}'.format(log_id, event))
            print('{}'.format(event))

            update_fwd_rule_task = update_fwd_rule(logger, log_id, get_fwd_rule_task['ruleId'], device_id, address, port, alarm_list, credentials)

            event = update_fwd_rule_task['description']
            if update_fwd_rule_task['status'].lower() == 'success':
                print('  + INFO: {}'.format(event))
            else:
                print('  + WARNING: {}'.format(event))

    # ------------------------------------------ #
    # If setting up a device specific forwarding #
    # rule associated with a targted devices.    #
    # ------------------------------------------ #
    else:
        device_found = False
        device_index = 0
        for device in devices_info['devices']:
            if device['device'] == target_device:

                device_found = True
                event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
                logger.debug('{} - {}'.format(log_id, event))

                # ------------------------------------------------------- #
                # Track information to summarize each devices info record #
                # ------------------------------------------------------- #
                device_status = ''
                device_severity = ''
                last_description = ''

                event = 'Starting network traffic capture for CPE device #{}: [{}]'.format(device_index + 1, target_device)
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                # --------------------------------------------------- #
                # Check for device on OVOC and store task information #
                # --------------------------------------------------- #
                get_device_task = get_device_id(logger, log_id, target_device, credentials)
                task_timestamp = datetime.now()
                get_device_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                device['tasks'].append(get_device_task.copy())
                device_status = get_device_task['status']
                logger.debug('{} - {}'.format(log_id, device_status))
                last_description = get_device_task['description']

                # --------------- #
                # Display results #
                # --------------- #
                event = get_device_task['description']
                if device_status.lower() == 'success':
                    logger.info('{} - {}'.format(log_id, event))
                    print('    - INFO: {}'.format(event))
                else:
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))

                # -------------------------------------- #
                # If device found, setup forwarding rule #
                # -------------------------------------- #
                if get_device_task['deviceId'] != -1:

                    # --------------------------------------------------- #
                    # Check for device SNMP alarm forwarding rule on OVOC #
                    # and store task information.                         #
                    # --------------------------------------------------- #
                    get_fwd_rule_task = get_fwd_rule_id(logger, log_id, rule_name, credentials)
                    task_timestamp = datetime.now()
                    get_fwd_rule_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                    device['tasks'].append(get_fwd_rule_task.copy())
                    device_status = get_fwd_rule_task['status']
                    logger.debug('{} - {}'.format(log_id, device_status))
                    last_description = get_fwd_rule_task['description']

                    # --------------- #
                    # Display results #
                    # --------------- #
                    event = get_device_task['description']
                    if device_status.lower() == 'success':
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))
                    else:
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))

                    # ---------------------------- #
                    # Create new rule if not found #
                    # ---------------------------- #
                    if get_fwd_rule_task['ruleId'] == -1:

                        event = 'Creating SNMP alarm forwarding rule [{}] for device: [{}]'.format(rule_name, target_device)
                        logger.info('{} - {}'.format(log_id, event))
                        print('  + {}'.format(event))

                        create_fwd_rule_task = create_fwd_rule(logger, log_id, rule_name, get_device_task['deviceId'], address, port, alarm_list, credentials)

                        # ---------------------- #
                        # Store task information #
                        # ---------------------- #
                        task_timestamp = datetime.now()
                        create_fwd_rule_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                        device['tasks'].append(create_fwd_rule_task.copy())
                        device_status = create_fwd_rule_task['status']
                        logger.debug('{} - {}'.format(log_id, device_status))
                        last_description = create_fwd_rule_task['description']

                        # --------------- #
                        # Display results #
                        # --------------- #
                        event = create_fwd_rule_task['description']
                        if create_fwd_rule_task['status'].lower() == 'success':
                            logger.info('{} - {}'.format(log_id, event))
                            print('  + INFO: {}'.format(event))
                        else:
                            logger.error('{} - {}'.format(log_id, event))
                            print('  + CRITICAL: {}'.format(event))

                    # -------------------- #
                    # Update existing rule #
                    # -------------------- #
                    else:

                        event = 'Updating global SNMP alarm forwarding rule: [{}]'.format(rule_name)
                        logger.info('{} - {}'.format(log_id, event))
                        print('{}'.format(event))

                        update_fwd_rule_task = update_fwd_rule(logger, log_id, get_fwd_rule_task['ruleId'], get_device_task['deviceId'], address, port, alarm_list, credentials)

                        # ---------------------- #
                        # Store task information #
                        # ---------------------- #
                        task_timestamp = datetime.now()
                        update_fwd_rule_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                        device['tasks'].append(update_fwd_rule_task.copy())
                        device_status = update_fwd_rule_task['status']
                        logger.debug('{} - {}'.format(log_id, device_status))
                        last_description = update_fwd_rule_task['description']

                        # --------------- #
                        # Display results #
                        # --------------- #
                        event = update_fwd_rule_task['description']
                        if update_fwd_rule_task['status'].lower() == 'success':
                            logger.info('{} - {}'.format(log_id, event))
                            print('  + INFO: {}'.format(event))
                        else:
                            logger.error('{} - {}'.format(log_id, event))
                            print('  + WARNING: {}'.format(event))

                # -------------------------------------- #
                # Store task information at device level #
                # -------------------------------------- #
                device['status'] = device_status
                device['description'] = last_description
                device['tempCapture'] = filename

                if started:
                    device['ovocCapture'] = 'active'
                    device['severity'] = 'NORMAL'
                else:
                    device['ovocCapture'] = 'not active'
                    device['severity'] = 'CRITICAL'

                break

            device_index += 1

        if not device_found:
            event = 'Device not found in monitored devices list!'
            logger.error('{} - {}'.format(log_id, event))
            print('  + ERROR: {}'.format(event))

    return

# --------------------------------------------------------------------------- #
# FUNCTION: send_response                                                     #
#                                                                             #
# Send a response to a CPE capture app script.                                #
#                                                                             #
# Parameters:                                                                 #
#     logger     - File handler for storing logged actions                    #
#     log_id     - Unique identifier for this devices log entries             #
#     udp_socket - UDP socket object currenly bound to                        #
#     response   - Response message to send to CPE capture app script         #
#     address    - Tuple of address/port of CPE capture app to send response  #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: 'True' for success, 'False' for failure                #
# --------------------------------------------------------------------------- #
def send_response(logger, log_id, udp_socket, response, address):
    """Send a response to a CPE capture app script."""

    status = False

    # ------------------------------------------ #
    # Send a response on the UDP datagram socket #
    # ------------------------------------------ #
    try:
        this_response = response.encode()
        udp_socket.sendto(this_response, address)
        status = True
    except Exception as err:
        event = '{}'.format(err)
        logger.error('{} - {}'.format(log_id, event))
        print('  - ERROR: {}'.format(event))

    return status

# --------------------------------------------------------------------------- #
# FUNCTION: secure_json_dump                                                  #
#                                                                             #
# Dump devices dictionary in JSON format but mask items that could present a  #
# security issue. The key elements passed in the masked list will be output   #
# with asterisks in the value field.                                          #
#                                                                             #
# Parameters:                                                                 #
#     devices_info - Dictionary to mask targeted output elements              #
#     mask_list    - List of key elements to mask                             #
#                                                                             #
# Return:                                                                     #
#    json_dump - JSON string: JSON output with masked values.                 #
# --------------------------------------------------------------------------- #
def secure_json_dump(logger, log_id, devices_info, mask_list):
    """Mask values with asterisks for the key elements sent in the 'mask_list' parameter."""

    json_dump = ''
    temp_dict = {}
    temp_dict['devices'] = []

    for device in devices_info['devices']:

        temp_dict['devices']
        temp_dict['devices'].append({})
        device_index = len(temp_dict['devices']) - 1

        for key, value in device.items():

            if key in mask_list:
                temp_dict['devices'][device_index][key] = '*****'
                event = 'Masking confidential information key: [{}]'.format(key)
                logger.debug('{} - {}'.format(log_id, event))
            else:
                temp_dict['devices'][device_index][key] = value

    json_dump = json.dumps(temp_dict, indent=4)

    event = 'JSON:\n{}'.format(json_dump)
    logger.debug('{} - {}'.format(log_id, event))

    return json_dump

# --------------------------------------------------------------------------- #
# FUNCTION: update_listen_port                                                #
#                                                                             #
# Update the value stored in the 'config.py' file if necessary that defines   #
# the UDP port this script will listen on CPE capture app requests.           #
#                                                                             #
# Parameters:                                                                 #
#     logger       - File handler for storing logged actions                  #
#     log_id       - Unique identifier for this devices log entries           #
#     listen_port  - UDP port to listen on entered from interactive input     #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: Success or failure of the update action.               #
# --------------------------------------------------------------------------- #
def update_listen_port(logger, log_id, listen_port):
    """Update UDP port to listen on that is stored in 'config.py' file."""

    status = False
    do_update = False

    # --------------------------------------------------------- #
    # Read in current configuration file contents. The contents #
    # will be modified by REGEX substitutions and written back  #
    # the the 'config.py' file if differences exist.            #
    # --------------------------------------------------------- #
    config_file_contents = ''
    event = 'Reading contents of "config.py" file.'
    logger.debug('{} - {}'.format(log_id, event))
    try:
        with open('./config.py', 'r') as fp:
            config_file_contents = fp.read()
    except Exception as err:
        event = 'Unable to read "config.py" file - Error: {}'.format(err)
        logger.error('{} - {}'.format(log_id, event))
        print('  - ERROR: {}'.format(event))

    else:
        event = 'Successfully read in "config.py" file.'
        logger.debug('{} - {}'.format(log_id, event))

        try:
            # ------------------------------- #
            # Check 'listen_port' for changes #
            # ------------------------------- #
            if listen_port != "" and int(listen_port) != config.listen_port:
                result = re.sub("(?s)listen_port = .*?$", "listen_port = " + str(listen_port), config_file_contents, 1, re.MULTILINE)

                if result != config_file_contents:
                    # ------------------------------------------------- #
                    # Configuration file contents successfully modified #
                    # ------------------------------------------------- #
                    config_file_contents = result
                    do_update = True
                    event = 'UDP listen port update successfully prepared.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                else:
                    # -------------------------------------------- #
                    # Failed to modify configuration file contents #
                    # -------------------------------------------- #
                    event = 'Failed to prepare update for UDP listen port!'
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))

            else:
                # -------------------- #
                # No updates necessary #
                # -------------------- #
                status = True

        except Exception as err:
            event = 'Processing Error: {}'.format(err)
            logger.error('{} - {}'.format(log_id, event))
            print('  - ERROR: {}'.format(event))

        else:
            # ------------------------------- #
            # Save configuration file updates #
            # ------------------------------- #
            if do_update:
                try:
                    with open('./config.py', 'w') as fp:
                        fp.write(config_file_contents)
                    status = True
                    event = 'Successfully updated "config.py" file'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                except Exception as err:
                    event = 'Unable to write "config.py" file - Error: {}'.format(err)
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))

    return status

# ---------------------------------------------------------------------------- #
# FUNCTION: get_listen_port                                                    #
#                                                                              #
# Get UDP port to listen on when waiting for CPE capture app requests.         #
#                                                                              #
# Parameters:                                                                  #
#     logger - File handler for storing logged actions                         #
#     log_id - Unique identifier for this devices log entries                  #
#                                                                              #
# Return:                                                                      #
#    listen_port - Integer value in the range (1025 - 65535)                   #
# ---------------------------------------------------------------------------- #
def get_listen_port(logger, log_id):
    """Get UPD port number to listen on for CPE capture app requests."""

    listen_port = 1025

    stored_listen_port = config.listen_port

    event = 'Retrieved stored UDP listen port: [{}]'.format(stored_listen_port)
    logger.info('{} - {}'.format(log_id, event))

    # -------------------------------------------- #
    # Allow modification of stored UDP listen port #
    # -------------------------------------------- #
    print('')
    print(':===============================================================================:')
    print(': UDP port to listen on for incoming CPE capture app requests.                  :')
    print(':                                                                               :')
    print(': NOTE: Entered port should be in the range (1025 - 65535)                      :')
    print(':===============================================================================:')
    got_listen_port = False
    while not got_listen_port:

        this_listen_port = raw_input('Enter UPD port to listen on: (1025-65535) [{}] '.format(stored_listen_port))
        if this_listen_port == '':
            got_listen_port = True
            listen_port = stored_listen_port
        else:
            try:
                this_listen_port = int(this_listen_port)
                if this_listen_port >= 1025 and this_listen_port <= 65535:
                    got_listen_port = True
                    listen_port = this_listen_port
                else:
                    event = 'Invalid setting: [{}]. Must be a value in the range (1025-65535).'.format(this_listen_port)
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {} Try again.\n'.format(event))
                    got_listen_port = False
            except ValueError:
                event = 'Invalid number: [{}]. Must be a value in the range (1025-65535).'.format(this_listen_port)
                logger.error('{} - {}'.format(log_id, event))
                print('  - ERROR: {} Try again.\n'.format(event))
                got_listen_port = False

    event = 'Set UDP port to listen on to: [{}]'.format(listen_port)
    logger.info('{} - {}'.format(log_id, event))
    print('  - INFO: {}'.format(event))

    # ------------------------------------------------------ #
    # Check if updates are necessary to the 'config.py' file #
    # ------------------------------------------------------ #
    if not update_listen_port(logger, log_id, listen_port):
        event = 'Failed to update "config.py" file!'
        logger.warning('{} - {}'.format(log_id, event))
        print('  - WARNING: {} You can continue without saving the value entered.'.format(event))

    return listen_port

# --------------------------------------------------------------------------- #
# FUNCTION: update_prevent_shutdown                                           #
#                                                                             #
# Update the value stored in the 'config.py' file if necessary that defines   #
# the prevent script shutdown setting.                                        #
#                                                                             #
# Parameters:                                                                 #
#     logger           - File handler for storing logged actions              #
#     log_id           - Unique identifier for this devices log entries       #
#     prevent_shutdown - Prevent shutdown entered from interactive input      #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: Success or failure of the update action.               #
# --------------------------------------------------------------------------- #
def update_prevent_shutdown(logger, log_id, prevent_shutdown):
    """Update prevent shutdown setting that is stored in 'config.py' file."""

    status = False
    do_update = False

    # --------------------------------------------------------- #
    # Read in current configuration file contents. The contents #
    # will be modified by REGEX substitutions and written back  #
    # the the 'config.py' file if differences exist.            #
    # --------------------------------------------------------- #
    config_file_contents = ''
    event = 'Reading contents of "config.py" file.'
    logger.debug('{} - {}'.format(log_id, event))
    try:
        with open('./config.py', 'r') as fp:
            config_file_contents = fp.read()
    except Exception as err:
        event = 'Unable to read "config.py" file - Error: {}'.format(err)
        logger.error('{} - {}'.format(log_id, event))
        print('  - ERROR: {}'.format(event))

    else:
        event = 'Successfully read in "config.py" file.'
        logger.debug('{} - {}'.format(log_id, event))

        try:
            # ------------------------------- #
            # Check 'prevent_shutdown' for changes #
            # ------------------------------- #
            if prevent_shutdown != "" and prevent_shutdown != config.prevent_shutdown:
                result = re.sub("(?s)prevent_shutdown = .*?$", "prevent_shutdown = '" + str(prevent_shutdown) + "'", config_file_contents, 1, re.MULTILINE)

                if result != config_file_contents:
                    # ------------------------------------------------- #
                    # Configuration file contents successfully modified #
                    # ------------------------------------------------- #
                    config_file_contents = result
                    do_update = True
                    event = 'Prevent shutdown setting update successfully prepared.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                else:
                    # -------------------------------------------- #
                    # Failed to modify configuration file contents #
                    # -------------------------------------------- #
                    event = 'Failed to prepare update for prevent shutdown setting!'
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))

            else:
                # -------------------- #
                # No updates necessary #
                # -------------------- #
                status = True

        except Exception as err:
            event = 'Processing Error: {}'.format(err)
            logger.error('{} - {}'.format(log_id, event))
            print('  - ERROR: {}'.format(event))

        else:
            # ------------------------------- #
            # Save configuration file updates #
            # ------------------------------- #
            if do_update:
                try:
                    with open('./config.py', 'w') as fp:
                        fp.write(config_file_contents)
                    status = True
                    event = 'Successfully updated "config.py" file'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                except Exception as err:
                    event = 'Unable to write "config.py" file - Error: {}'.format(err)
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))

    return status

# ---------------------------------------------------------------------------- #
# FUNCTION: get_prevent_shutdown                                               #
#                                                                              #
# Get yes/no flag to prevent the script from shutting down when there are no   #
# active captures to manage. The yes/no string is returned from this function  #
# as a boolean True/False value for processing in the rest of script.          #
#                                                                              #
# Setting the value to 'y' prevents this script from shutting down and it will #
# run indefinitely waiting for CPE requests.                                   #
#                                                                              #
# Parameters:                                                                  #
#     logger - File handler for storing logged actions                         #
#     log_id - Unique identifier for this devices log entries                  #
#                                                                              #
# Return:                                                                      #
#    prevent_shutdown - Boolean: True or False                                 #
# ---------------------------------------------------------------------------- #
def get_prevent_shutdown(logger, log_id):
    """Get yes/no flag to enable or disable the script from shutting down."""

    prevent_shutdown = True

    stored_prevent_shutdown = config.prevent_shutdown

    event = 'Retrieved stored prevent shutdown setting: [{}]'.format(stored_prevent_shutdown)
    logger.info('{} - {}'.format(log_id, event))

    # ----------------------------------------------------- #
    # Allow modification of stored prevent shutdown setting #
    # ----------------------------------------------------- #
    print('')
    print(':===============================================================================:')
    print(': Setting to control whether or not shut down this script after all active      :')
    print(': captures have completed. Setting this to "y" prevents the script from         :')
    print(': shutting down and allows this script to run indefinitely waiting for CPE      :')
    print(': capture requests.                                                             :')
    print(':===============================================================================:')
    this_prevent_shutdown = ''
    while this_prevent_shutdown == '':
        this_prevent_shutdown = str(raw_input('Prevent script from shutting down: (y/n) [{}] '.format(stored_prevent_shutdown))).lower().strip()

        if this_prevent_shutdown != '':
            this_prevent_shutdown = this_prevent_shutdown[0]

        event = 'Entered prevent shutdown setting: [{}]'.format(this_prevent_shutdown)
        logger.info('{} - {}'.format(log_id, event))
        if this_prevent_shutdown == '':
            this_prevent_shutdown = stored_prevent_shutdown
            if this_prevent_shutdown != '':
                event = 'Using existing prevent shutdown setting: [{}]'.format(this_prevent_shutdown)
                logger.info('{} - {}'.format(log_id, event))
            else:
                event = 'Must enter a prevent shutdown setting for controlling script behavior.'
                logger.error('{} - {}'.format(log_id, event))
                print('  - ERROR: {} Try again.'.format(event))
        else:
            if this_prevent_shutdown == 'y' or this_prevent_shutdown == 'n':
                event = 'Modifying prevent shutdown setting to: [{}]'.format(this_prevent_shutdown)
                logger.info('{} - {}'.format(log_id, event))
            else:
                event = 'Prevent shutdown setting must be one of the following values: ("y"|"n")'
                logger.error('{} - {}'.format(log_id, event))
                print('  - ERROR: {} Try again.'.format(event))
                this_prevent_shutdown = ''

    event = 'Set prevent script shutdown setting to: [{}]'.format(this_prevent_shutdown)
    logger.info('{} - {}'.format(log_id, event))
    print('  - INFO: {}'.format(event))

    # ------------------------------------------------------ #
    # Check if updates are necessary to the 'config.py' file #
    # ------------------------------------------------------ #
    if not update_prevent_shutdown(logger, log_id, this_prevent_shutdown):
        event = 'Failed to update "config.py" file!'
        logger.warning('{} - {}'.format(log_id, event))
        print('  - WARNING: {} You can continue without saving the value entered.'.format(event))

    if this_prevent_shutdown == 'y':
        prevent_shutdown = True
    else:
        prevent_shutdown = False

    return this_prevent_shutdown

# --------------------------------------------------------------------------- #
# FUNCTION: update_interface_name                                             #
#                                                                             #
# Update the value stored in the 'config.py' file if necessary that defines   #
# the network interface name to use for capturing CPE network traffic.        #
#                                                                             #
# Parameters:                                                                 #
#     logger         - File handler for storing logged actions                #
#     log_id         - Unique identifier for this devices log entries         #
#     interface_name - Network interface name to use for CPE traffic captures #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: Success or failure of the update action.               #
# --------------------------------------------------------------------------- #
def update_interface_name(logger, log_id, interface_name):
    """Update network interface name used for traffic capture that is stored in 'config.py' file."""

    status = False
    do_update = False

    # --------------------------------------------------------- #
    # Read in current configuration file contents. The contents #
    # will be modified by REGEX substitutions and written back  #
    # the the 'config.py' file if differences exist.            #
    # --------------------------------------------------------- #
    config_file_contents = ''
    event = 'Reading contents of "config.py" file.'
    logger.debug('{} - {}'.format(log_id, event))
    try:
        with open('./config.py', 'r') as fp:
            config_file_contents = fp.read()
    except Exception as err:
        event = 'Unable to read "config.py" file - Error: {}'.format(err)
        logger.error('{} - {}'.format(log_id, event))
        print('  - ERROR: {}'.format(event))

    else:
        event = 'Successfully read in "config.py" file.'
        logger.debug('{} - {}'.format(log_id, event))

        try:
            # ---------------------------------- #
            # Check 'interface_name' for changes #
            # ---------------------------------- #
            if interface_name != "" and interface_name != config.interface_name:
                result = re.sub("(?s)interface_name = .*?$", "interface_name = '" + str(interface_name) + "'", config_file_contents, 1, re.MULTILINE)

                if result != config_file_contents:
                    # ------------------------------------------------- #
                    # Configuration file contents successfully modified #
                    # ------------------------------------------------- #
                    config_file_contents = result
                    do_update = True
                    event = 'Network interface name used for traffic captures update successfully prepared.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                else:
                    # -------------------------------------------- #
                    # Failed to modify configuration file contents #
                    # -------------------------------------------- #
                    event = 'Failed to prepare update for network interface name used for traffic captures!'
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))

            else:
                # -------------------- #
                # No updates necessary #
                # -------------------- #
                status = True

        except Exception as err:
            event = 'Processing Error: {}'.format(err)
            logger.error('{} - {}'.format(log_id, event))
            print('  - ERROR: {}'.format(event))

        else:
            # ------------------------------- #
            # Save configuration file updates #
            # ------------------------------- #
            if do_update:
                try:
                    with open('./config.py', 'w') as fp:
                        fp.write(config_file_contents)
                    status = True
                    event = 'Successfully updated "config.py" file'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                except Exception as err:
                    event = 'Unable to write "config.py" file - Error: {}'.format(err)
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))

    return status

# ---------------------------------------------------------------------------- #
# FUNCTION: get_interface_name                                                 #
#                                                                              #
# Get network interface that is used for CPE device network traffic captures.  #
#                                                                              #
# Parameters:                                                                  #
#     logger - File handler for storing logged actions                         #
#     log_id - Unique identifier for this devices log entries                  #
#                                                                              #
# Return:                                                                      #
#    interface_name - String value to identify the network interface name.     #
# ---------------------------------------------------------------------------- #
def get_interface_name(logger, log_id):
    """Get network interface name to use for CPE traffic captures."""

    stored_interface_name = config.interface_name

    event = 'Retrieved stored network interface name: [{}]'.format(stored_interface_name)
    logger.info('{} - {}'.format(log_id, event))

    # ---------------------------------------------------------------- #
    # Get list of valid interfaces from /proc/net/dev on linux systems #
    # ---------------------------------------------------------------- #
    interfaces = os.popen("cat /proc/net/dev | tail -n +3 | awk -F':' '{gsub(/ /, \"\", $0); print $1}' | tr '\n' ','").read().strip(',')
    interface_list = interfaces.split(',')

    # ------------------------------------------- #
    # Allow modification of stored interface name #
    # ------------------------------------------- #
    print('')
    print(':===============================================================================:')
    print(': Name of the network interface to use for CPE traffic captures.                :')
    print(':===============================================================================:')
    this_interface_name = ''
    while this_interface_name == '':
        this_interface_name = str(raw_input('Enter network interface name for capture: ({}) [{}] '.format('|'.join(interface_list), stored_interface_name))).strip()
        event = 'Entered network interface name: [{}]'.format(this_interface_name)
        logger.info('{} - {}'.format(log_id, event))
        if this_interface_name == '':
            this_interface_name = stored_interface_name
            if this_interface_name != '':
                event = 'Using existing network interface name: [{}]'.format(this_interface_name)
                logger.info('{} - {}'.format(log_id, event))
            else:
                event = 'Must enter an interface name to use for capturing CPE traffic.'
                logger.error('{} - {}'.format(log_id, event))
                print('  - ERROR: {} Try again.'.format(event))
        else:
            if this_interface_name in interface_list:
                event = 'Modifying network interface name to: [{}]'.format(this_interface_name)
                logger.info('{} - {}'.format(log_id, event))
            else:
                event = 'Interface name must be a value in this list: ({})'.format('|'.join(interface_list))
                logger.error('{} - {}'.format(log_id, event))
                print('  - ERROR: {} Try again.'.format(event))
                this_interface_name = ''

    event = 'Set network interface name for captures to: [{}]'.format(this_interface_name)
    logger.info('{} - {}'.format(log_id, event))
    print('  - INFO: {}'.format(event))

    # ------------------------------------------------------ #
    # Check if updates are necessary to the 'config.py' file #
    # ------------------------------------------------------ #
    if not update_interface_name(logger, log_id, this_interface_name):
        event = 'Failed to update "config.py" file!'
        logger.warning('{} - {}'.format(log_id, event))
        print('  - WARNING: {} You can continue without saving the value entered.'.format(event))

    return this_interface_name

# --------------------------------------------------------------------------- #
# FUNCTION: update_ovoc_username                                              #
#                                                                             #
# Update the value stored in the 'config.py' file if necessary that defines   #
# the OVOC account username used for performing REST API requests.            #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     ovoc_username - OVOC account username                                   #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: Success or failure of the update action.               #
# --------------------------------------------------------------------------- #
def update_ovoc_username(logger, log_id, ovoc_username):
    """Update OVOC account username used for REST API requests that is stored in 'config.py' file."""

    status = False
    do_update = False

    # --------------------------------------------------------- #
    # Read in current configuration file contents. The contents #
    # will be modified by REGEX substitutions and written back  #
    # the the 'config.py' file if differences exist.            #
    # --------------------------------------------------------- #
    config_file_contents = ''
    event = 'Reading contents of "config.py" file.'
    logger.debug('{} - {}'.format(log_id, event))
    try:
        with open('./config.py', 'r') as fp:
            config_file_contents = fp.read()
    except Exception as err:
        event = 'Unable to read "config.py" file - Error: {}'.format(err)
        logger.error('{} - {}'.format(log_id, event))
        print('  - ERROR: {}'.format(event))

    else:
        event = 'Successfully read in "config.py" file.'
        logger.debug('{} - {}'.format(log_id, event))

        try:
            # --------------------------------- #
            # Check 'ovoc_username' for changes #
            # --------------------------------- #
            if ovoc_username != "" and ovoc_username != config.ovoc_username:
                result = re.sub("(?s)ovoc_username = .*?$", "ovoc_username = '" + str(ovoc_username) + "'", config_file_contents, 1, re.MULTILINE)

                if result != config_file_contents:
                    # ------------------------------------------------- #
                    # Configuration file contents successfully modified #
                    # ------------------------------------------------- #
                    config_file_contents = result
                    do_update = True
                    event = 'OVOC account username used for REST API requests update successfully prepared.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                else:
                    # -------------------------------------------- #
                    # Failed to modify configuration file contents #
                    # -------------------------------------------- #
                    event = 'Failed to prepare update for OVOC account username used for REST API requests!'
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))

            else:
                # -------------------- #
                # No updates necessary #
                # -------------------- #
                status = True

        except Exception as err:
            event = 'Processing Error: {}'.format(err)
            logger.error('{} - {}'.format(log_id, event))
            print('  - ERROR: {}'.format(event))

        else:
            # ------------------------------- #
            # Save configuration file updates #
            # ------------------------------- #
            if do_update:
                try:
                    with open('./config.py', 'w') as fp:
                        fp.write(config_file_contents)
                    status = True
                    event = 'Successfully updated "config.py" file'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                except Exception as err:
                    event = 'Unable to write "config.py" file - Error: {}'.format(err)
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))

    return status

# ---------------------------------------------------------------------------- #
# FUNCTION: get_ovoc_account                                                   #
#                                                                              #
# Get OVOC account username and password used for performing REST API requests #
# to create SNMP alarm forwarding rules in the OVOC server this OVOC capture   #
# app script is running on.                                                    #
#                                                                              #
# Parameters:                                                                  #
#     logger - File handler for storing logged actions                         #
#     log_id - Unique identifier for this devices log entries                  #
#                                                                              #
# Return:                                                                      #
#    credentials - Dictionary with 'username' and 'password' elements.         #
# ---------------------------------------------------------------------------- #
def get_ovoc_account(logger, log_id):
    """Get OVOC account username and password used for performing REST API requests."""

    credentials = {}
    credentials['username'] = ''
    credentials['password'] = ''

    stored_ovoc_username = config.ovoc_username

    event = 'Retrieved stored OVOC account username: [{}]'.format(stored_ovoc_username)
    logger.info('{} - {}'.format(log_id, event))

    # ------------------------------------------ #
    # Allow modification of stored OVOC username #
    # ------------------------------------------ #
    print('')
    print(':===============================================================================:')
    print(': OVOC account username and password that can be used for performing REST API   :')
    print(': requests. This script will use REST API to create the SNMP alarm forwarding   :')
    print(': needed for the CPE capture scripts.                                           :')
    print(':                                                                               :')
    print(': NOTE: The account used must have at least "Operator" security level.          :')
    print(':===============================================================================:')
    this_ovoc_username = ''
    while this_ovoc_username == '':
        this_ovoc_username = str(raw_input('Enter OVOC account username: [{}] '.format(stored_ovoc_username))).strip()
        event = 'Entered OVOC account username: [{}]'.format(this_ovoc_username)
        logger.info('{} - {}'.format(log_id, event))
        if this_ovoc_username == '':
            this_ovoc_username = stored_ovoc_username
            if this_ovoc_username != '':
                event = 'Using existing OVOC account username: [{}]'.format(this_ovoc_username)
                logger.info('{} - {}'.format(log_id, event))
            else:
                event = 'Must enter an OVOC account username used for performing REST API requests.'
                logger.error('{} - {}'.format(log_id, event))
                print('  - ERROR: {} Try again.'.format(event))
        else:
            event = 'Modifying OVOC account username to: [{}]'.format(this_ovoc_username)
            logger.info('{} - {}'.format(log_id, event))

    event = 'Set OVOC account username to: [{}]'.format(this_ovoc_username)
    logger.info('{} - {}'.format(log_id, event))
    print('  - INFO: {}'.format(event))
    credentials['username'] = this_ovoc_username

    # ------------------------- #
    # Get OVOC account password #
    # ------------------------- #
    this_ovoc_password = ''
    while this_ovoc_password == '':
        this_ovoc_password = getpass(prompt='  - Password: ')
        this_ovoc_password_verify = getpass(prompt='    Confirm password: ')
        if this_ovoc_password != this_ovoc_password_verify:
            event = 'Entered passwords do NOT match.'
            logger.error('{} - {}'.format(log_id, event))
            print('    - ERROR: {} Try again.'.format(event))
            this_ovoc_password = ''
        else:
            if this_ovoc_password == '':
                event = 'Passwords can not be empty!'
                logger.error('{} - {}'.format(log_id, event))
                print('    - ERROR: {} Try again.'.format(event))
            else:
                event = 'Entered passwords match!'
                logger.info('{} - {}'.format(log_id, event))
                print('    - INFO: {}'.format(event))

    event = 'Set OVOC account password'
    logger.info('{} - {}'.format(log_id, event))
    print('  - INFO: {}'.format(event))
    credentials['password'] = this_ovoc_password

    # ------------------------------------------------------ #
    # Check if updates are necessary to the 'config.py' file #
    # ------------------------------------------------------ #
    if not update_ovoc_username(logger, log_id, this_ovoc_username):
        event = 'Failed to update "config.py" file!'
        logger.warning('{} - {}'.format(log_id, event))
        print('  - WARNING: {} You can continue without saving the value entered.'.format(event))

    return credentials

# --------------------------------------------------------------------------- #
# FUNCTION: process_register                                                  #
#                                                                             #
# Process a REGISTER request from a CPE capture script.                       #
#                                                                             #
# Parameters:                                                                 #
#     logger         - File handler for storing logged actions                #
#     log_id         - Unique identifier for this devices log entries         #
#     server_socket  - Network socket object currenly bound to                #
#     sendto_address - Tuple of address/port of CPE capture app to send resp  #
#     target_device  - CPE device to start network traffic capture on         #
#     credentials    - Credentials for OVOC account to do REST API requests   #
#     devices_info   - Dictionary of targeted devices                         #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def process_register(logger, log_id, server_socket, sendto_address, target_device, credentials, devices_info):
    """Process REGISTER request from CPE capture script."""

    # --------------------------------------------------------------- #
    # Register device by adding a record in 'devices_info' dictionary #
    # --------------------------------------------------------------- #
    device_index = register_device(logger, log_id, target_device, devices_info)

    for device in devices_info['devices']:
        if device['device'] == target_device:

            # ---------------------------------------------- #
            # Save this request in 'devices_info' dictionary #
            # ---------------------------------------------- #
            device['lastRequest'] = 'REGISTER'

            # ------------------------------------------------------ #
            # Set SNMP alarm forwarding rule for a 'Connection Lost' #
            # event for this device. Alarm names in the list must be #
            # named according to the SNMP OID name. Refer to the     #
            # OVOC Alarms Monitoring Guide for mapping alarm names.  #
            # ------------------------------------------------------ #
            rule_name = 'Forward Connection Lost - {}'.format(target_device)
            alarm_list = ['acEMSNodeConnectionLostAlarm']
            set_alarm_fwd_rule(logger, log_id, target_device, rule_name, alarm_list, sendto_address, credentials, devices_info)

            for send in range(0, 10, 1):
                if device['ruleAdded'] == True:
                    # ----------------------------------------------- #
                    # Send 200 OK response to CPE capture app script. #
                    # ----------------------------------------------- #
                    this_response = '200 OK {}'.format(target_device)
                    response_type = '200 OK'
                else:
                    this_response = '503 Service Unavailable {}'.format(target_device)
                    response_type = '503 Service Unavailable'

                event = 'Sending response for registering device on OVOC server: [{}]'.format(this_response)
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))
                if send_response(logger, log_id, server_socket, this_response, sendto_address):
                    event = 'Sent response for registering device on OVOC server.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('    - INFO: {}'.format(event))

                    # ----------------------------------------------- #
                    # Save this response in 'devices_info' dictionary #
                    # ----------------------------------------------- #
                    device['lastResponse'] = response_type

                else:
                    event = 'Failed to send response for registering device on OVOC server!'
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))
                    device['lastResponse'] = ''

    return

# --------------------------------------------------------------------------- #
# FUNCTION: process_capture                                                   #
#                                                                             #
# Process a CAPTURE request from a CPE capture script.                        #
#                                                                             #
# Parameters:                                                                 #
#     logger         - File handler for storing logged actions                #
#     log_id         - Unique identifier for this devices log entries         #
#     server_socket  - Network socket object currenly bound to                #
#     sendto_address - Tuple of address/port of CPE capture app to send resp  #
#     target_device  - CPE device to start network traffic capture on         #
#     interface_name - Network interface name to start CPE capture on         #
#     devices_info   - Dictionary of targeted devices                         #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def process_capture(logger, log_id, server_socket, sendto_address, target_device, interface_name, devices_info):
    """Process CAPTURE request from CPE capture script."""

    device_found = False
    for device in devices_info['devices']:
        if device['device'] == target_device:

            device_found = True

            # ---------------------------------------------- #
            # Save this request in 'devices_info' dictionary #
            # ---------------------------------------------- #
            device['lastRequest'] = 'CAPTURE'

            # --------------------------------------------------- #
            # Send 100 Trying response to CPE capture app script. #
            # --------------------------------------------------- #
            this_response = '100 Trying {}'.format(target_device)
            response_type = '100 Trying'
            event = 'Sending [100 Trying] response for starting capture for device: [{}]'.format(target_device)
            logger.info('{} - {}'.format(log_id, event))
            print('  + {}'.format(event))
            if send_response(logger, log_id, server_socket, this_response, sendto_address):
                event = 'Sent response for starting capture on OVOC server.'
                logger.info('{} - {}'.format(log_id, event))
                print('    - INFO: {}'.format(event))

                # ----------------------------------------------- #
                # Save this response in 'devices_info' dictionary #
                # ----------------------------------------------- #
                device['lastResponse'] = response_type

            else:
                event = 'Failed to send response for starting capture on OVOC server!'
                logger.error('{} - {}'.format(log_id, event))
                print('    - ERROR: {}'.format(event))
                device['lastResponse'] = ''

            # ---------------------------------------------------- #
            # Check if last capture for device is still running.   #
            # This would indicate that the CPE capture app was     #
            # terminated before sending a STOP request to this     #
            # script. If so, then we need to clean up the previous #
            # tcpdump process.                                     #
            # ---------------------------------------------------- #
            if device['ovocCapture'].lower() == 'active' and device['lastRequest'] == 'CAPTURE':

                # ---------------------- #
                # Abort previous capture #
                # ---------------------- #
                event = 'Previous capture for this device is still active.'
                logger.warning('{} - {}'.format(log_id, event))
                print('    - WARNING: {}'.format(event))
                event = 'Aborting previous capture to start new capture request.'
                logger.warning('{} - {}'.format(log_id, event))
                print('    - INFO: {}'.format(event))

                # --------------------------------- #
                # Abort capture for this CPE device #
                # --------------------------------- #
                abort_capture(logger, log_id, target_device, devices_info)

            # ----------------------------------------- #
            # Start tcpdump capture for this CPE device #
            # ----------------------------------------- #
            start_capture(logger, log_id, target_device, interface_name, devices_info)

            if devices['ovocCapture'].lower() == 'active':
                # ----------------------------------------------- #
                # Send 200 OK response to CPE capture app script. #
                # ----------------------------------------------- #
                this_response = '200 OK {}'.format(target_device)
                response_type = '200 OK'
            else:
                this_response = '503 Service Unavailable {}'.format(target_device)
                response_type = '503 Service Unavailable'

            event = 'Sending response for starting capture on OVOC server: [{}]'.format(this_response)
            logger.info('{} - {}'.format(log_id, event))
            print('  + {}'.format(event))
            if send_response(logger, log_id, server_socket, this_response, sendto_address):
                event = 'Sent response for starting capture on OVOC server.'
                logger.info('{} - {}'.format(log_id, event))
                print('    - INFO: {}'.format(event))

                # ----------------------------------------------- #
                # Save this response in 'devices_info' dictionary #
                # ----------------------------------------------- #
                device['lastResponse'] = response_type

            else:
                event = 'Failed to send response for starting capture on OVOC server!'
                logger.error('{} - {}'.format(log_id, event))
                print('    - ERROR: {}'.format(event))
                device['lastResponse'] = ''

    # ---------------------------------------------------------- #
    # Received a CAPTURE request for a device not yet registered #
    # ---------------------------------------------------------- #
    if not device_found:

        this_response = '404 Not Found {}'.format(target_device)
        response_type = '404 Not Found'
        event = 'Sending response for starting capture on OVOC server: [{}]'.format(this_response)
        logger.info('{} - {}'.format(log_id, event))
        print('  + {}'.format(event))
        if send_response(logger, log_id, server_socket, this_response, sendto_address):
            event = 'Sent response for starting capture on OVOC server.'
            logger.info('{} - {}'.format(log_id, event))
            print('    - INFO: {}'.format(event))

            # ----------------------------------------------- #
            # Save this response in 'devices_info' dictionary #
            # ----------------------------------------------- #
            device['lastResponse'] = response_type

        else:
            event = 'Failed to send response for starting capture on OVOC server!'
            logger.error('{} - {}'.format(log_id, event))
            print('    - ERROR: {}'.format(event))
            device['lastResponse'] = ''

    return

# --------------------------------------------------------------------------- #
# FUNCTION: start_capture                                                     #
#                                                                             #
# Start network traffic capture on a specifc CPE device. The capture is       #
# started by sending the appropriate shell script command that will spawn the #
# 'tcpdump' application.                                                      #
#                                                                             #
# Parameters:                                                                 #
#     logger         - File handler for storing logged actions                #
#     log_id         - Unique identifier for this devices log entries         #
#     target_device  - CPE device to start network traffic capture on         #
#     interface_name - Network interface name to start CPE capture on         #
#     devices_info   - Dictionary of targeted devices                         #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def start_capture(logger, log_id, target_device, interface_name, devices_info):
    """Start network traffic capture on specific device in the 'devices_info' dictionary."""

    device_found = False
    device_index = 0
    for device in devices_info['devices']:
        if device['device'] == target_device:

            device_found = True
            event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
            logger.debug('{} - {}'.format(log_id, event))

            # ------------------------------------------------------- #
            # Track information to summarize each devices info record #
            # ------------------------------------------------------- #
            device_status = ''
            device_severity = ''
            last_description = ''
            filename = ''

            started = False

            if device['ovocCapture'].lower() == 'not active':

                event = 'Starting network traffic capture for CPE device #{}: [{}]'.format(device_index + 1, target_device)
                logger.info('{} - {}'.format(log_id, event))
                print('{}'.format(event))

                # -------------------------------- #
                # Create filename to store pcap as #
                # -------------------------------- #
                file_timestamp = datetime.now()
                file_timestamp = file_timestamp.strftime('%Y-%m-%dT%H.%M.%S.%f%z')
                filename = 'tmp_device_{}_{}.pcap'.format(target_device, file_timestamp)
                filename = re.sub(':', '.', filename)

                # ------------------------------------------- #
                # Attempt to start tcpdump capture for device #
                # ------------------------------------------- #
                event = 'Attempting to start tcpdump capture on CPE device...'
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                start_capture_task = {}
                start_capture_task['task'] = 'Start capture'
                start_capture_task['description'] = 'Failed to start tcpdump capture for device!'
                task_timestamp = datetime.now()
                start_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                start_capture_task['filename'] = filename

                # --------------------------------------------------------------------- #
                # Create captures with with rotating files for the targeted CPE device. #
                #   -i    : <interface name> from the interactive entry                 #
                #   -w    : Temporary base capture filename. Will be renamed after a    #
                #           STOP request is received from the CPE capture app.          #
                #   -W 3  : Number of files to save before overwriting older files      #
                #   -C 10 : Max file size in MB before creating a new file              #
                #   host  : Target CPE device to filter on                              #
                #                                                                       #
                # Send normal output to /dev/null and echo out the PID number to save   #
                # --------------------------------------------------------------------- #
                capture_cmd = "nohup tcpdump -i {} -w ./captures/{} -W 3 -C 10 host {} > /dev/null 2>&1 & echo $!".format(interface_name, filename, target_device)

                pid = os.popen(capture_cmd).read().strip()

                # ------------------------------------------------------------ #
                # Save PID in 'devices_info' dictionary record for this device #
                # ------------------------------------------------------------ #
                device['pid'] = pid

                try:
                    os.kill(int(pid), 0)
                except OSError:
                    event = '{}'.format(err)
                    logger.error('{} - {}'.format(log_id, event))
                    start_capture_task['status'] = 'Failure'
                    start_capture_task['description'] = event
                    print('  - ERROR: {}'.format(event))
                else:
                    start_capture_task['status'] = 'Success'
                    event = 'Started capture on device as file: [{}]'.format(filename)
                    start_capture_task['description'] = event
                    started = True

                # ---------------------- #
                # Store task information #
                # ---------------------- #
                device['tasks'].append(start_capture_task.copy())
                device_status = start_capture_task['status']
                logger.debug('{} - {}'.format(log_id, device_status))
                last_description = start_capture_task['description']

                # --------------- #
                # Display results #
                # --------------- #
                event = start_capture_task['description']
                if device_status.lower() == 'success':
                    logger.info('{} - {}'.format(log_id, event))
                    print('    - INFO: {}'.format(event))
                else:
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))

            else:
                device_status = 'Failure'
                last_description = 'Traffic capture is still active for CPE device!'

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            device['status'] = device_status
            device['description'] = last_description
            device['tempCapture'] = filename

            if started:
                device['ovocCapture'] = 'active'
                device['severity'] = 'NORMAL'
            else:
                device['ovocCapture'] = 'not active'
                device['severity'] = 'CRITICAL'

            break

        device_index += 1

    if not device_found:
        event = 'Device not found in monitored devices list!'
        logger.error('{} - {}'.format(log_id, event))
        print('  + ERROR: {}'.format(event))

    return

# --------------------------------------------------------------------------- #
# FUNCTION: process_stop                                                      #
#                                                                             #
# Process a STOP request from a CPE capture script.                           #
#                                                                             #
# Parameters:                                                                 #
#     logger         - File handler for storing logged actions                #
#     log_id         - Unique identifier for this devices log entries         #
#     server_socket  - Network socket object currenly bound to                #
#     sendto_address - Tuple of address/port of CPE capture app to send resp  #
#     target_device  - CPE device to start network traffic capture on         #
#     filename       - Capture filename used for the CPE capture app script   #
#     devices_info   - Dictionary of targeted devices                         #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def process_stop(logger, log_id, server_socket, sendto_address, target_device, filename, devices_info):
    """Process STOP request from CPE capture script."""

    device_found = False
    for device in devices_info['devices']:
        if device['device'] == target_device:

            device_found = True

            # ---------------------------------------------- #
            # Save this request in 'devices_info' dictionary #
            # ---------------------------------------------- #
            device['lastRequest'] = 'STOP'
            device['cpeFilename'] = filename

            # --------------------------------------------------- #
            # Send 100 Trying response to CPE capture app script. #
            # --------------------------------------------------- #
            this_response = '100 Trying {}'.format(target_device)
            response_type = '100 Trying'
            event = 'Sending [100 Trying] response for stopping capture for device: [{}]'.format(target_device)
            logger.info('{} - {}'.format(log_id, event))
            print('  + {}'.format(event))
            if send_response(logger, log_id, server_socket, this_response, sendto_address):
                event = 'Sent response for stopping capture on OVOC server.'
                logger.info('{} - {}'.format(log_id, event))
                print('    - INFO: {}'.format(event))

                # ----------------------------------------------- #
                # Save this response in 'devices_info' dictionary #
                # ----------------------------------------------- #
                device['lastResponse'] = response_type

            else:
                event = 'Failed to send response for stopping capture on OVOC server!'
                logger.error('{} - {}'.format(log_id, event))
                print('    - ERROR: {}'.format(event))
                device['lastResponse'] = ''

            # -------------------------------- #
            # Stop capture for this CPE device #
            # -------------------------------- #
            stop_capture(logger, log_id, target_device, filename, devices_info)

            if device['ovocCapture'].lower() == 'not active':
                # ----------------------------------------------- #
                # Send 200 OK response to CPE capture app script. #
                # ----------------------------------------------- #
                this_response = '200 OK {}'.format(target_device)
                response_type = '200 OK'
            else:
                this_response = '503 Service Unavailable {}'.format(target_device)
                response_type = '503 Service Unavailable'

            event = 'Sending response for stopping capture on OVOC server: [{}]'.format(this_response)
            logger.info('{} - {}'.format(log_id, event))
            print('  + {}'.format(event))
            if send_response(logger, log_id, server_socket, this_response, sendto_address):
                event = 'Sent response for stopping capture on OVOC server.'
                logger.info('{} - {}'.format(log_id, event))
                print('    - INFO: {}'.format(event))

                # ----------------------------------------------- #
                # Save this response in 'devices_info' dictionary #
                # ----------------------------------------------- #
                device['lastResponse'] = response_type

            else:
                event = 'Failed to send response for stopping capture on OVOC server!'
                logger.error('{} - {}'.format(log_id, event))
                print('    - ERROR: {}'.format(event))
                device['lastResponse'] = ''

    # ------------------------------------------------------- #
    # Received a STOP request for a device not yet registered #
    # ------------------------------------------------------- #
    if not device_found:

        this_response = '404 Not Found {}'.format(target_device)
        response_type = '404 Not Found'
        event = 'Sending response for starting capture on OVOC server: [{}]'.format(this_response)
        logger.info('{} - {}'.format(log_id, event))
        print('  + {}'.format(event))
        if send_response(logger, log_id, server_socket, this_response, sendto_address):
            event = 'Sent response for starting capture on OVOC server.'
            logger.info('{} - {}'.format(log_id, event))
            print('    - INFO: {}'.format(event))

            # ----------------------------------------------- #
            # Save this response in 'devices_info' dictionary #
            # ----------------------------------------------- #
            device['lastResponse'] = response_type

        else:
            event = 'Failed to send response for starting capture on OVOC server!'
            logger.error('{} - {}'.format(log_id, event))
            print('    - ERROR: {}'.format(event))
            device['lastResponse'] = ''

    return

# --------------------------------------------------------------------------- #
# FUNCTION: stop_capture                                                      #
#                                                                             #
# Stop network traffic capture on a specifc CPE device. The capture is        #
# stopped by sending the appropriate os.kill command to the running 'tcpdump' #
# application.                                                                #
#                                                                             #
# The filename used on the CPE capture app script is used here so that there  #
# is alignment and and easy way to correlate the capture files that were      #
# synchronized.                                                               #
#                                                                             #
# Parameters:                                                                 #
#     logger         - File handler for storing logged actions                #
#     log_id         - Unique identifier for this devices log entries         #
#     target_device  - CPE device to stop network traffic capture on          #
#     filename       - Capture filename used for the CPE capture app script   #
#     devices_info   - Dictionary of targeted devices                         #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def stop_capture(logger, log_id, target_device, filename, devices_info):
    """Stop network traffic capture on specific device in the 'devices_info' dictionary."""

    task_count = 0
    fail_count = 0

    device_found = False
    device_index = 0
    for device in devices_info['devices']:
        if device['device'] == target_device:

            device_found = True
            event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
            logger.debug('{} - {}'.format(log_id, event))

            # ------------------------------------------------------- #
            # Track information to summarize each devices info record #
            # ------------------------------------------------------- #
            device_status = 'Success'
            device_severity = 'Normal'
            device_description = ''

            stopped = False

            if device['ovocCapture'].lower() == 'active':

                task_count += 1
                event = 'Stopping network traffic capture for CPE device #{}: [{}]'.format(device_index + 1, target_device)
                logger.info('{} - {}'.format(log_id, event))
                print('{}'.format(event))

                # ------------------------------------------ #
                # Attempt to stop tcpdump capture for device #
                # ------------------------------------------ #
                event = 'Attempting to stop tcpdump capture on CPE device...'
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                stop_capture_task = {}
                stop_capture_task['task'] = 'Stop capture'
                task_timestamp = datetime.now()
                stop_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                stop_capture_task['filename'] = filename

                # ----------------------------------------------------------- #
                # Get PID in 'devices_info' dictionary record for this device #
                # ----------------------------------------------------------- #
                pid = device['pid']

                if pid != '':

                    try:
                        os.kill(int(pid), 15)
                    except OSError:
                        event = '{}'.format(err)
                        logger.error('{} - {}'.format(log_id, event))
                        stop_capture_task['status'] = 'Failure'
                        stop_capture_task['description'] = event
                        # ----------------------------------- #
                        # Set failure status for device level #
                        # ----------------------------------- #
                        device_status = stop_capture_task['status']
                        device_description = event
                        logger.debug('{} - {}'.format(log_id, device_status))
                        fail_count += 1
                        print('  - ERROR: {}'.format(event))
                    else:
                        stop_capture_task['status'] = 'Success'
                        event = 'Stopped capture on device as file: [{}]'.format(filename)
                        stop_capture_task['description'] = event
                        device_description = event
                        stopped = True

                else:
                    abort_capture_task['status'] = 'Failure'
                    event = 'PID not found. Unable to identify tcpdump capture file to terminate.'
                    abort_capture_task['description'] = event
                    device_description = event

                # ---------------------- #
                # Store task information #
                # ---------------------- #
                device['tasks'].append(stop_capture_task.copy())

                # --------------- #
                # Display results #
                # --------------- #
                event = stop_capture_task['description']
                if device_status.lower() == 'success':
                    logger.info('{} - {}'.format(log_id, event))
                    print('    - INFO: {}'.format(event))
                else:
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))

                # --------------------------------------------------------------- #
                # Rename temporary tcpdump capture filenames to match CPE capture #
                # --------------------------------------------------------------- #
                renamed = True
                if stopped:

                    # ----------------------------------------------------------- #
                    # Get temporary base filename used when starting the tcpdump  #
                    # captures. If there are multiple files (up to 3) then each   #
                    # file will have a '0', '1', or '2' appended to the filename. #
                    # ----------------------------------------------------------- #
                    path = './captures/'
                    temp_filename = device['tempCapture']

                    # -------------------------------------------------- #
                    # Rename up to 3 pcap files. The '-W 3' parameter on #
                    # the tcdump command in 'start_capture' sets the     #
                    # number of pcap files that are created per device.  #
                    # -------------------------------------------------- #
                    for index in range(0, 3, 1):

                        if os.path.exists(path + temp_filename + str(index)):

                            task_count += 1

                            base_file = temp_filename + str(index)

                            # ------------------ #
                            # Default to success #
                            # ------------------ #
                            rename_capture_task = {}
                            rename_capture_task['task'] = 'Rename temporary capture file'
                            task_timestamp = datetime.now()
                            rename_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

                            # ------------------------------------------ #
                            # Set base filename for local files. Tcpdump #
                            # rotating filenames are in the format:      #
                            #     basename.pcap0                         #
                            #     basename.pcap1                         #
                            #     basename.pcap2                         #
                            # Change to be as follows:                   #
                            #     basename-0.pcap                        #
                            #     basename-1.pcap                        #
                            #     basename-2.pcap                        #
                            # ------------------------------------------ #
                            base_name = filename.lstrip('CPE_')
                            base_name = base_name.rstrip('.pcap')
                            local_file = path + 'OVOC_' + base_name + '-' + str(index) + '.pcap'
                            rename_capture_task['filename'] = local_file

                            # ------------------------------------------- #
                            # Rename to match CPE capture script filename #
                            # ------------------------------------------- #
                            try:
                                os.rename(path + temp_filename + str(index), local_file)
                            except Exception as err:
                                event = 'Capture file renaming error: {}'.format(err)
                                logger.error('{} - {}'.format(log_id, event))
                                rename_capture_task['status'] = 'Failure'
                                rename_capture_task['description'] = event
                                # ----------------------------------- #
                                # Set failure status for device level #
                                # ----------------------------------- #
                                device_status = rename_capture_task['status']
                                device_description = event
                                logger.debug('{} - {}'.format(log_id, device_status))
                                fail_count += 1
                                renamed = False
                                print('    - ERROR: {}'.format(event))
                            else:
                                rename_capture_task['status'] = 'Success'
                                event = 'Successfully renamed capture file to match CPE capture script: [{}]'.format(base_file)
                                logger.info('{} - {}'.format(log_id, event))
                                event = 'Successfully renamed capture file: [{}]'.format(base_file)
                                rename_capture_task['description'] = event
                                device_description = event

                            # ---------------------- #
                            # Store task information #
                            # ---------------------- #
                            device['tasks'].append(rename_capture_task.copy())
                            device['ovocCapture' + str(index)] = local_file

                            # --------------- #
                            # Display results #
                            # --------------- #
                            event = rename_capture_task['description']
                            if rename_capture_task['status'].lower() == 'success':
                                logger.info('{} - {}'.format(log_id, event))
                                print('    - INFO: {}'.format(event))
                            else:
                                logger.error('{} - {}'.format(log_id, event))
                                print('    - ERROR: {}'.format(event))

                        else:
                            event = 'Capture file may not exist: [{}]'.format(path + temp_filename + str(index))
                            logger.info('{} - {}'.format(log_id, event))

            else:
                device_status = 'Failure'
                device_description = 'Traffic capture is not active for CPE device!'

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            device['status'] = device_status
            device['description'] = device_description

            if stopped:
                device['ovocCapture'] = 'not active'
                device['pid'] = ''
                if renamed:
                    device['severity'] = 'NORMAL'
                else:
                    device['severity'] = 'MINOR'
            else:
                device['ovocCapture'] = 'active'
                device['severity'] = 'MAJOR'

            break

        device_index += 1

    if not device_found:
        event = 'Device not found in monitored devices list!'
        logger.error('{} - {}'.format(log_id, event))
        print('  + ERROR: {}'.format(event))

    return

# --------------------------------------------------------------------------- #
# FUNCTION: abort_capture                                                     #
#                                                                             #
# Abort network traffic capture on a specifc CPE device. This function is     #
# called when a second CAPTURE message is received by this script before      #
# receiving a STOP for a previously active capture.                           #
#                                                                             #
# This would occur if the CPE capture app script terminated for some reason   #
# prior to sending the STOP for any of its active capture sessions.           #
#                                                                             #
# Parameters:                                                                 #
#     logger         - File handler for storing logged actions                #
#     log_id         - Unique identifier for this devices log entries         #
#     target_device  - CPE device to abort network traffic capture on         #
#     devices_info   - Dictionary of targeted devices                         #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def abort_capture(logger, log_id, target_device, devices_info):
    """Abort network traffic capture on specific device in the 'devices_info' dictionary."""

    task_count = 0
    fail_count = 0

    device_found = False
    device_index = 0
    for device in devices_info['devices']:
        if device['device'] == target_device:

            device_found = True
            event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
            logger.debug('{} - {}'.format(log_id, event))

            # ------------------------------------------------------- #
            # Track information to summarize each devices info record #
            # ------------------------------------------------------- #
            device_status = 'Success'
            device_severity = 'Normal'
            device_description = ''

            aborted = False

            if device['ovocCapture'].lower() == 'active':

                task_count += 1
                event = 'Aborting network traffic capture for CPE device #{}: [{}]'.format(device_index + 1, target_device)
                logger.info('{} - {}'.format(log_id, event))
                print('{}'.format(event))

                # ------------------------------------------ #
                # Attempt to stop tcpdump capture for device #
                # ------------------------------------------ #
                event = 'Attempting to stop and delete active tcpdump capture on CPE device...'
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                abort_capture_task = {}
                abort_capture_task['task'] = 'Abort capture'
                task_timestamp = datetime.now()
                abort_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

                # ----------------------------------------------------------- #
                # Get PID in 'devices_info' dictionary record for this device #
                # ----------------------------------------------------------- #
                pid = device['pid']

                if pid != '':

                    # ------------------------------------------------------ #
                    # Get temporary base filename of current tcpdump capture #
                    # ------------------------------------------------------ #
                    temp_filename = device['tempCapture']

                    try:
                        os.kill(int(pid), 15)
                    except OSError:
                        event = '{}'.format(err)
                        logger.error('{} - {}'.format(log_id, event))
                        abort_capture_task['status'] = 'Failure'
                        abort_capture_task['description'] = event
                        # ----------------------------------- #
                        # Set failure status for device level #
                        # ----------------------------------- #
                        device_status = abort_capture_task['status']
                        device_description = event
                        logger.debug('{} - {}'.format(log_id, device_status))
                        fail_count += 1
                        print('  - ERROR: {}'.format(event))
                    else:
                        abort_capture_task['status'] = 'Success'
                        event = 'Aborted capture on device writing to base temporary file: [{}]'.format(temp_filename)
                        abort_capture_task['description'] = event
                        device_description = event
                        aborted = True

                else:
                    abort_capture_task['status'] = 'Failure'
                    event = 'PID not found. Unable to identify tcpdump capture file to terminate.'
                    abort_capture_task['description'] = event
                    device_description = event

                # ---------------------- #
                # Store task information #
                # ---------------------- #
                device['tasks'].append(abort_capture_task.copy())

                # --------------- #
                # Display results #
                # --------------- #
                event = abort_capture_task['description']
                if device_status.lower() == 'success':
                    logger.info('{} - {}'.format(log_id, event))
                    print('    - INFO: {}'.format(event))
                else:
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))

                # -------------------------------------- #
                # Remove temporary tcpdump capture files #
                # -------------------------------------- #
                removed = True
                if aborted:

                    path = './captures/'

                    # -------------------------------------------------- #
                    # Remove up to 3 pcap files. The '-W 3' parameter on #
                    # the tcdump command in 'start_capture' sets the     #
                    # number of pcap files that are created per device.  #
                    # -------------------------------------------------- #
                    for this_file in glob.glob(path + temp_filename + '*'):

                        task_count += 1

                        base_file = os.path.basename(this_file)

                        # ------------------ #
                        # Default to success #
                        # ------------------ #
                        remove_capture_task = {}
                        remove_capture_task['task'] = 'Delete temporary capture file'
                        task_timestamp = datetime.now()
                        remove_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                        remove_capture_task['filename'] = base_file

                        # ------------------------------------- #
                        # Remove temporary tcpdump capture file #
                        # ------------------------------------- #
                        try:
                            os.remove(this_file)
                        except Exception as err:
                            event = 'Capture file deletion error: {}'.format(err)
                            logger.error('{} - {}'.format(log_id, event))
                            remove_capture_task['status'] = 'Failure'
                            remove_capture_task['description'] = event
                            # ----------------------------------- #
                            # Set failure status for device level #
                            # ----------------------------------- #
                            device_status = remove_capture_task['status']
                            device_description = event
                            logger.debug('{} - {}'.format(log_id, device_status))
                            fail_count += 1
                            removed = False
                            print('    - ERROR: {}'.format(event))
                        else:
                            remove_capture_task['status'] = 'Success'
                            event = 'Successfully deleted temporary capture file: [{}]'.format(base_file)
                            remove_capture_task['description'] = event
                            device_description = event

                        # ---------------------- #
                        # Store task information #
                        # ---------------------- #
                        device['tasks'].append(remove_capture_task.copy())

                        # --------------- #
                        # Display results #
                        # --------------- #
                        event = remove_capture_task['description']
                        if remove_capture_task['status'].lower() == 'success':
                            logger.info('{} - {}'.format(log_id, event))
                            print('    - INFO: {}'.format(event))
                        else:
                            logger.error('{} - {}'.format(log_id, event))
                            print('    - ERROR: {}'.format(event))

            else:
                device_status = 'Failure'
                device_description = 'Traffic capture is not active for CPE device!'

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            device['status'] = device_status
            device['description'] = device_description

            if aborted:
                device['ovocCapture'] = 'not active'
                device['pid'] = ''
                if removed:
                    device['severity'] = 'NORMAL'
                else:
                    device['severity'] = 'MINOR'
            else:
                device['ovocCapture'] = 'active'
                device['severity'] = 'MAJOR'

            break

        device_index += 1

    if not device_found:
        event = 'Device not found in monitored devices list!'
        logger.error('{} - {}'.format(log_id, event))
        print('  + ERROR: {}'.format(event))

    return

# --------------------------------------------------------------------------- #
# FUNCTION: parse_message                                                     #
#                                                                             #
# Parse the received message to determine the type (health check, OVOC alarm, #
# status from other applications, etc.) Add the elements to a dictionary to   #
# return.                                                                     #
#                                                                             #
# Parameters:                                                                 #
#     logger   - File handler for storing logged actions                      #
#     log_id   - Unique identifier for this devices log entries               #
#     message  - Received message from UDP socket                             #
#                                                                             #
# Return:                                                                     #
#    msg_info - Dictionary containing the parsed items from the message.      #
# --------------------------------------------------------------------------- #
def parse_message(logger, log_id, message):
    """Parse the elements of a message and add to a dictionary."""

    message = message.rstrip('\x00')
    event = 'Received Message:\n{}'.format(message)
    logger.debug('{} - {}'.format(log_id, event))

    msg_info = {}
    msg_info['type'] = 'unknown'

    # ---------------------------------- #
    # Match OVOC alarms in syslog format #
    # ---------------------------------- #
    if re.search('New Alarm -', message):

        # ------------ #
        # Set defaults #
        # ------------ #
        #msg_info['type'] = 'alarm'
        #msg_info['timestamp'] = ''
        #msg_info['alarmType'] = ''
        #msg_info['alarmMessage'] = ''
        #msg_info['alarmSource'] = ''
        #msg_info['alarm'] = ''
        #msg_info['deviceName'] = ''
        #msg_info['tenant'] = ''
        #msg_info['region'] = ''
        #msg_info['ipAddress'] = ''
        #msg_info['deviceType'] = ''
        #msg_info['deviceSerial'] = ''
        #msg_info['deviceDescription'] = ''

        #event = 'Matched OVOC alarm'
        #logger.debug('{} - {}'.format(log_id, event))

        #match = re.search('<\d+>(.*?)\s*:\s*New Alarm\s*-\s*(.*?),\s*(.*)\s*Source:(.*?),\s*Description:(.*?),\s*Device Name:(.*?),\s*Tenant:(.*?),\s*Region:(.*?),\s*IP Address:(.*?),\s*Device Type:(.*?),\s*Device Serial:(.*?),\s*Device Description:(.*$)', message)
        #if match:
        #    msg_info['timestamp'] = match.group(1).strip()
        #    msg_info['alarmType'] = match.group(2).strip()
        #    msg_info['alarmMessage'] = match.group(3).strip()
        #    msg_info['alarmSource'] = match.group(4).strip()
        #    msg_info['alarm'] = match.group(5).strip()
        #    msg_info['deviceName'] = match.group(6).strip()
        #    msg_info['tenant'] = match.group(7).strip()
        #    msg_info['region'] = match.group(8).strip()
        #    msg_info['ipAddress'] = match.group(9).strip()
        #    msg_info['deviceType'] = match.group(10).strip()
        #    msg_info['deviceSerial'] = match.group(11).strip()
        #    msg_info['deviceDescription'] = match.group(12).strip()

        # ------------ #
        # Set defaults #
        # ------------ #
        msg_info['type'] = 'alarm'
        msg_info['alarmType'] = ''
        msg_info['alarm'] = ''
        msg_info['alarmSource'] = ''
        msg_info['ipAddress'] = ''

        event = 'Matched OVOC alarm'
        logger.debug('{} - {}'.format(log_id, event))

        match = re.search('New Alarm\s*-\s*(.*?),', message)
        if match:
            msg_info['alarmType'] = match.group(1).strip()

        match = re.search('\s*Source:(.*?),', message)
        if match:
            msg_info['alarmSource'] = match.group(1).strip()

        match = re.search(',\s*Description:(.*?),', message)
        if match:
            msg_info['alarm'] = match.group(1).strip()

        match = re.search(',\s*IP Address:(.*?),', message)
        if match:
            msg_info['ipAddress'] = match.group(1).strip()

    # --------------------------------------- #
    # Match requests from CPE capture scripts #
    # --------------------------------------- #
    elif re.search('^REGISTER', message):

        event = 'Matched CPE capture script [REGISTER] request'
        logger.debug('{} - {}'.format(log_id, event))

        # ------------ #
        # Set defaults #
        # ------------ #
        msg_info['type'] = 'request'
        msg_info['request'] = ''
        msg_info['device'] = ''

        match = re.search('(REGISTER)\s+(.*$)', message)
        if match:
            msg_info['request'] = match.group(1).strip()
            msg_info['device'] = match.group(2).strip()

    elif re.search('^CAPTURE', message):

        event = 'Matched CPE capture script [CAPTURE] request'
        logger.debug('{} - {}'.format(log_id, event))

        # ------------ #
        # Set defaults #
        # ------------ #
        msg_info['type'] = 'request'
        msg_info['request'] = ''
        msg_info['device'] = ''

        match = re.search('(CAPTURE)\s+(.*$)', message)
        if match:
            msg_info['request'] = match.group(1).strip()
            msg_info['device'] = match.group(2).strip()

    elif re.search('^STOP', message):

        # ------------ #
        # Set defaults #
        # ------------ #
        msg_info['type'] = 'request'
        msg_info['request'] = ''
        msg_info['device'] = ''
        msg_info['filename'] = ''

        event = 'Matched CPE capture script [STOP] request'
        logger.debug('{} - {}'.format(log_id, event))

        match = re.search('(STOP)\s+(.*?)\s+(.*$)', message)

        if match:
            msg_info['request'] = match.group(1).strip()
            msg_info['device'] = match.group(2).strip()
            msg_info['filename'] = match.group(3).strip()

    event = 'Parsed message elements:\n{}'.format(json.dumps(msg_info, indent=4))
    logger.debug('{} - {}'.format(log_id, event))

    return msg_info

# --------------------------------------------------------------------------- #
# FUNCTION: register_device                                                   #
#                                                                             #
# Search for target device in records of 'devices_info' dictionary and return #
# the index if found and if not found create a new record and return the new  #
# record index.                                                               #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     target_device - Target device to locate in 'devices_info' dictionary    #
#     devices_info  - Dictionary of targeted devices                          #
#                                                                             #
# Return:                                                                     #
#     device_index - Index of device record in 'devices_info' dictionary      #
# --------------------------------------------------------------------------- #
def register_device(logger, log_id, target_device, devices_info):
    """Return the index of the device record in the 'devices_info' dictionary."""

    device_index = -1

    # ---------------------------------------------- #
    # Search for device in 'devices_info' dictionary #
    # ---------------------------------------------- #
    device_found = False
    index = 0
    for device in devices_info['devices']:
        if device['device'] == target_device:
            device_found = True
            device_index = index

            event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
            logger.debug('{} - {}'.format(log_id, event))

        index += 1

    # ----------------------------------- #
    # If not found, add new device record #
    # ----------------------------------- #
    if not device_found:

        # ------------------------ #
        # Create CPE device record #
        # ------------------------ #
        devices_info['devices'].append({})
        device_index = len(devices_info['devices']) - 1
        devices_info['devices'][device_index]['device'] = target_device
        devices_info['devices'][device_index]['ruleAdded'] = False
        devices_info['devices'][device_index]['tasks'] = []

        # ------------------------------------------------------ #
        # Default the OVOC traffic capture state to 'not active' #
        # to indicate the device is currently not performing a   #
        # network capture.                                       #
        # ------------------------------------------------------ #
        devices_info['devices'][device_index]['ovocCapture'] = 'not active'

        event = 'Created new CPE record for device: [{}]'.format(target_device)
        logger.info('{} - {}'.format(log_id, event))

        event = 'Created new device in devices information dictionary at index: [{}]'.format(device_index)
        logger.debug('{} - {}'.format(log_id, event))

    return device_index

# --------------------------------------------------------------------------- #
# FUNCTION: create_csv_file                                                   #
#                                                                             #
# Extract the configuration files stored in the ZIP file that match the file  #
# name format: <MAC address>.cli. Read in the contents of each matching file  #
# and sedn the file to the defined OVOC server repositories using REST API.   #
#                                                                             #
# Parameters:                                                                 #
#     logger   - File handler for storing logged actions                      #
#     log_id   - Unique identifier for this devices log entries               #
#     output   - Flag to indicate if CSV will be written or not               #
#     tstamp   - Timestamp used to make filename of CSV file unique           #
#     devices_info - Dictionary of tasks attempted by devices                 #
#                                                                             #
# Return:                                                                     #
#     csv_records - List of CSV line dictionary records.                      #
# --------------------------------------------------------------------------- #
def create_csv_file(logger, log_id, output, tstamp, job_info):
    """Create CSV file from job inforamtion dictionary."""

    print('')
    event = 'Creating CSV file...'
    logger.info('{} - {}'.format(log_id, event))
    print('{}'.format(event))

    # ------------------------------------------ #
    # List to hold the CSV records for the files #
    # ------------------------------------------ #
    csv_records = []

    # ----------------------------------------------- #
    # Create output CSV file with file upload details #
    # ----------------------------------------------- #
    csv_created = False

    if output:
        date_time = tstamp.strftime("%Y-%m-%d_%H.%M.%S")
        csv_filename = 'upload_files_log_' + date_time + '.csv'
        event = 'CSV filename: [{}]'.format(csv_filename)
        logger.info('{} - {}'.format(log_id, event))

        try:
            csvfile = open(csv_filename, 'w', newline='')
            event = 'Opened CSV file for writing'
            logger.debug('{} - {}'.format(log_id, event))

            if not csvfile.closed:
                # ---------------- #
                # Write CSV Header #
                # ---------------- #
                writer = csv.writer(csvfile)
                writer.writerow( ('Row', 'Filename', 'Overall Status', 'Overall Severity', 'Overall Description', 'Total Servers', 'Server Number', 'Server', 'Server Status', 'Server Severity', 'Server Description', 'Server Total Tasks', 'Task Number', 'Task', 'Task Status', 'Task Status Code', 'Task Description') )

                csv_create = True

        except Exception as err:
            event = '{}'.format(err)
            logger.error('{} - {}'.format(log_id, event))
            print('  - ERROR: {}'.format(event))

    # ------------------------------------------------------------- #
    # Iterate over all tasks and files in the 'job_info' dictionary #
    # ------------------------------------------------------------- #
    row = 0
    for file in job_info['files']:

        # ------------------------------------- #
        # Create CSV record with default values #
        # ------------------------------------- #
        csv_record = {}
        csv_record['row'] = str(row)
        csv_record['filename'] = file['baseFilename']
        csv_record['overallStatus'] = file['status']
        csv_record['overallSeverity'] = file['severity']
        csv_record['overallDescription'] = file['description']
        csv_record['totalServers'] = '0'
        csv_record['serverNumber'] = ''
        csv_record['server'] = ''
        csv_record['serverStatus'] = ''
        csv_record['serverSeverity'] = ''
        csv_record['serverDescription'] = ''
        csv_record['totalTasks'] = '0'
        csv_record['taskNumber'] = ''
        csv_record['task'] = ''
        csv_record['taskStatus'] = ''
        csv_record['taskStatusCode'] = ''
        csv_record['taskDescription'] = ''

        # ------------------------------------------------ #
        # Overwrite defaults with information if it exists #
        # ------------------------------------------------ #
        if 'servers' in file:
            csv_record['totalServers'] = str(len(file['servers']))
            server_index = 0
            for server in file['servers']:
                server_index += 1
                csv_record['serverNumber'] = str(server_index)
                csv_record['server'] = server['server']
                csv_record['serverStatus'] = server['status']
                csv_record['serverSeverity'] = server['severity']
                csv_record['serverDescription'] = server['description']

                if 'tasks' in server:
                    csv_record['totalTasks'] = str(len(server['tasks']))
                    task_index = 0
                    for task in server['tasks']:
                        task_index += 1
                        csv_record['taskNumber'] = str(task_index)
                        csv_record['task'] = task['task']
                        csv_record['taskStatus'] = task['status']
                        csv_record['taskStatusCode'] = str(task['statusCode'])
                        csv_record['taskDescription'] = task['description']

                        row += 1
                        csv_record['row'] = str(row)
                        if output:
                            writer.writerow( ( \
                                csv_record['row'], \
                                csv_record['filename'], \
                                csv_record['overallStatus'], \
                                csv_record['overallSeverity'], \
                                csv_record['overallDescription'], \
                                csv_record['totalServers'], \
                                csv_record['serverNumber'], \
                                csv_record['server'], \
                                csv_record['serverStatus'], \
                                csv_record['serverSeverity'], \
                                csv_record['serverDescription'], \
                                csv_record['totalTasks'], \
                                csv_record['taskNumber'], \
                                csv_record['task'], \
                                csv_record['taskStatus'], \
                                csv_record['taskStatusCode'], \
                                csv_record['taskDescription'] \
                            ) )

                        csv_records.append(csv_record.copy())
    
                else:
                    row += 1
                    csv_record['row'] = str(row)
                    if output:
                        writer.writerow( ( \
                            csv_record['row'], \
                            csv_record['filename'], \
                            csv_record['overallStatus'], \
                            csv_record['overallSeverity'], \
                            csv_record['overallDescription'], \
                            csv_record['totalServers'], \
                            csv_record['serverNumber'], \
                            csv_record['server'], \
                            csv_record['serverStatus'], \
                            csv_record['serverSeverity'], \
                            csv_record['serverDescription'], \
                            csv_record['totalTasks'], \
                            csv_record['taskNumber'], \
                            csv_record['task'], \
                            csv_record['taskStatus'], \
                            csv_record['taskStatusCode'], \
                            csv_record['taskDescription'] \
                        ) )

                    csv_records.append(csv_record.copy())

        else:
            row += 1
            csv_record['row'] = str(row)
            if output:
                writer.writerow( ( \
                    csv_record['row'], \
                    csv_record['filename'], \
                    csv_record['overallStatus'], \
                    csv_record['overallSeverity'], \
                    csv_record['overallDescription'], \
                    csv_record['totalServers'], \
                    csv_record['serverNumber'], \
                    csv_record['server'], \
                    csv_record['serverStatus'], \
                    csv_record['serverSeverity'], \
                    csv_record['serverDescription'], \
                    csv_record['totalTasks'], \
                    csv_record['taskNumber'], \
                    csv_record['task'], \
                    csv_record['taskStatus'], \
                    csv_record['taskStatusCode'], \
                    csv_record['taskDescription'] \
                ) )

            csv_records.append(csv_record.copy())

    if output:
        if not csvfile.closed:
            csvfile.close()

    event = 'Create CSV file completed'
    logger.info('{} - {}'.format(log_id, event))

    print('  + Finished')

    return csv_records

# --------------- #
# Main Processing #
# --------------- #
def main(argv):

    # ------------------ #
    # Set version number #
    # ------------------ #
    version = config.version

    print('')
    print('=================================================================================')
    print(' Version: {:10s}            OVOC CAPTURE APP'.format(version))
    print('=================================================================================')

    # ------------------------------------------- #
    # Check if rotation of log files is necessary #
    # ------------------------------------------- #
    if rotate_logs(logger, log_id, config.app_log_file, config.app_max_log_file_size, config.app_archived_files):
        event = 'Rotation of log files completed'
        logger.info('{} - {}'.format(log_id, event))

    # ----------------------------- #
    # Prepare captures subdirectory #
    # ----------------------------- #
    #pathlib.Path('./captures').mkdir(parents=True, exist_ok=True)
    try:
        if not os.path.isdir('./captures'):
            os.makedirs('./captures')
            event = 'Capture directory [./captures] created successfully.'
            logger.info('{} - {}'.format(log_id, event))
    except OSError as error:
        event = 'Capture directory [./captures] can not be created!'
        logger.error('{} - {}'.format(log_id, event))
        print('CRITICAL: {}'.format(event))
        exit(1)

    # ------------------------------------------------------------------- #
    # When the CPE capture app script sucessfully started a traffic       #
    # capture for a CPE device, it then sends a request 'CAPTURE'         #
    # to this script to start a capture on an OVOC server at the same     #
    # time. A dictionary record is also created to track information on   #
    # the CPE that is being monitored. The following dictionary elements  #
    # are used to track the activity of the CPE devices:                  #
    # {                                                                   #
    #     "devices": [                                                    #
    #         {                                                           #
    #             "device": "<device address>",                           #
    #             "status": "Success|Failure",                            #
    #             "ovocCapture": "not active",                            #
    #             "description": "<some description>",                    #
    #             "severity": "NORMAL|MINOR|MAJOR|CRITICAL",              #
    #             "tasks": []                                             #
    #         },                                                          #
    #         ...                                                         #
    #         <Next Device>                                               #
    #     ]                                                               #
    # }                                                                   #
    # ------------------------------------------------------------------- #
    devices_info = {}
    devices_info['devices'] = []

    # ------------------------------------ #
    # Get parameters via interactive input #
    # ------------------------------------ #
    try:
        listen_port = get_listen_port(logger, log_id)
        prevent_shutdown = get_prevent_shutdown(logger, log_id)
        interface_name = get_interface_name(logger, log_id)
        ovoc_credentials = get_ovoc_account(logger, log_id)

    except KeyboardInterrupt:
        print('')
        print('=================')
        print('>>>> Aborted <<<<')
        print('=================')
        exit(1)

    begin_time = time.time()
    begin_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f%z')
    print('')
    print('=================================================================================')
    print('                         OVOC NETWORK TRAFFIC CAPTURES')
    #print(' Version: {:10s}     OVOC NETWORK TRAFFIC CAPTURES'.format(version))
    print('=================================================================================')
    print('Start Time: {}'.format(begin_timestamp))
    print('---------------------------------------------------------------------------------')

    # ------------------------------------------------- #
    # Prepare UDP socket to receive requests and send   #
    # and send responses to complimentary CPE capture   #
    # app scripts that control the triggers for         #
    # preforming network traffic captures.              #
    # ------------------------------------------------- #
    buffer_size = 16384

    # -------------------------------------- #
    # Create a UDP datagram socket to listen #
    # on any IPv4 interface on this host.    #
    # -------------------------------------- #
    try:
        server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
        server_socket.bind(('0.0.0.0', listen_port))
    except Exception as err:
        event = '{}'.format(err)
        logger.error('{} - {}'.format(log_id, event))
        print('  - ERROR: {}'.format(event))

    else:

        event = 'Listening for script messaging on UDP port: [{}]'.format(listen_port)
        logger.info('{} - {}'.format(log_id, event))
        print('{}'.format(event))

        active_captures = 0

        while (len(devices_info['devices']) == 0 or active_captures > 0):

            bytes_address_pair = server_socket.recvfrom(buffer_size)
            message = bytes_address_pair[0]
            from_address = bytes_address_pair[1]

            event = 'UDP message from: [{}]'.format(from_address)
            logger.info('{} - {}'.format(log_id, event))

            # ---------------------- #
            # Parse received message #
            # ---------------------- #
            msg_info = parse_message(logger, log_id, message.decode('utf-8'))

            # --------------------------------------- #
            # Process CPE capture app script requests #
            # --------------------------------------- #
            if msg_info['type'] == 'request':

                target_device = msg_info['device']
                event = 'Received [{}] request from CPE script controlling device: [{}]'.format(msg_info['request'], target_device)
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                # ------------------------------------------------- #
                # Get index for device in 'devices_info' dictionary #
                # ------------------------------------------------- #
                #device_index = get_device_index(logger, log_id, target_device, devices_info)

                # ------------------------------------------------------- #
                # If a 'REGISTER' request has been received, then add the #
                # device to the 'devices_info' dictionary and then create #
                # an SNMP alarm forwarding rule to send 'Connection Lost' #
                # events to the devices CPE capture script.               #
                # ------------------------------------------------------- #
                if msg_info['request'] == 'REGISTER':

                    process_register(logger, log_id, server_socket, from_address, target_device, ovoc_credentials, devices_info)

                # ---------------------------------------------------- #
                # If a 'CAPTURE' request has been received, then start #
                # 'tcpdump' capturing for this specific device.        #
                # ---------------------------------------------------- #
                elif msg_info['request'] == 'CAPTURE':

                    process_capture(logger, log_id, server_socket, from_address, target_device, interface_name, devices_info)

                # ------------------------------------------------ #
                # If a 'STOP' request has been received, then stop #
                # 'tcpdump' capturing for this specific device.    #
                # ------------------------------------------------ #
                elif msg_info['request'] == 'STOP':

                    process_stop(logger, log_id, server_socket, from_address, target_device, msg_info['filename'], devices_info)

                else:
                    event = 'Received unknown request [{}] to process!'.format(msg_info['request'])
                    logger.warning('{} - {}'.format(log_id, event))
                    print('  + WARNING: {}'.format(event))

            else:
                event = 'Received unknown message to process! Check logs for details.'
                logger.warning('{} - {}'.format(log_id, event))
                print('  + WARNING: {}'.format(event))

            # ------------------------------------------------- #
            # Check for any CPE devices actively being captured #
            # ------------------------------------------------- #
            if prevent_shutdown:
                active_captures = 1
            else:
                active_captures = 0
                for device in devices_info['devices']:
                    if device['ovocCapture'].lower() == 'active':
                        active_captures += 1

            # ------------------------------------------------ #
            # For debugging - Output 'devices_info' dictionary #
            # ------------------------------------------------ #
            event = 'Devices Info:\n{}'.format(secure_json_dump(logger, log_id, devices_info, ['password']))
            logger.debug('{} - {}'.format(log_id, event))

            #event = 'Listening for script messaging on UDP port: [{}]'.format(listen_port)
            #logger.info('{} - {}'.format(log_id, event))
            #print('{}'.format(event))

        event = 'All devices have completed'
        logger.info('{} - {}'.format(log_id, event))
        print('  - INFO: {}'.format(event))

    event = 'Finished'
    logger.info('{} - {}'.format(log_id, event))
    print('{}'.format(event))

    # ---------------------- #
    # Create CSV output file #
    # ---------------------- #
    #csv_records = create_csv_file(logger, log_id, output_csv, begin_timestamp, devices_info)

    end_time = time.time()
    #end_timestamp = datetime.now()
    end_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f%z')
    print('')
    print('=================================================================================')
    print('                              PROCESSING SUMMARY')
    print('=================================================================================')
    print('Completed: '.format(end_timestamp))
    print('Total Duration: {0:.3f} seconds'.format(end_time - begin_time))
    print('')

if __name__ == "__main__":
   main(sys.argv[1:])


