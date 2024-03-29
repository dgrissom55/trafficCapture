"""CPE APP: Syncrhonize network captures between OVOC server and CPE device."""

"""
-------------------------------------------------------------------------------
Script: cpe_capture_app.py

Description:

This script starts network traffic captures on both targeted audiocodes CPE 
devices and their associated OVOC servers. The traffic captures are started
on the CPE and the associated OVOC server and terminate after receiving a
'Connection Lost' SNMP alarm from the OVOC server that manages the CPE.

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

Running the 'cpe_capture_app.py' script on a separate server other than an
OVOC server is required since the goal is to understand why an OVOC server
may be losing connectivity to the CPE devices. The intent is that the
separate server will not lose connectivity to the CPE device and be able to
remain in communications with the CPE to issue REST API commands to control
and retrieve debug captures without failure.

The goal is the attempt catch an event where SNMP traffic is not being seen
on the CPE device and it loses management connectivity with the OVOC server.

A major part of the interactive input to this script is the creation of a 
list of CPE devices and their associated OVOC servers. The commands to 
start/stop the debug capture on the audiocodes CPE is sent via REST API to
the devices defined from the interactive entries. The traffic captures on
the CPE's associated OVOC servers are started and stopped using UDP signaling.
Commands are sent from this script to the 'ovoc_listen_port' defined for
the complementatry Python script ('ovoc_capture_app.py') running on the
appropriate OVOC servers.

On the CPE devices, the network captures are performed by sending REST API
request to the targeted CPE. The REST API request contains the necessary CLI
script to start the debug capture on the selected interfaces. Also, an SNMP
v3 user is created to enable this script and the OVOC capture script to send
SNMP traffic to the device after OVOC has placed the device(s) in a 
'Connection Lost' state. In addition to the SNMP traffic, ICMP pings and TCP 
connection requests are sent. This is to force network traffic to the device
that will be captured by the CPE debug capture and the OVOC tcpdumps.

On the OVOC servers, the network captures are performed by issuing system
calls to the 'tcpdump' app. To start a capture on the OVOC server, this script
first registers the target devices by sending a 'REGISTER' message for each
device. The OVOC capture script receives the devices registration and creates
an SNMP forwarding alarm on the OVOC servers for each device in order to send
'Connection Lost' events to this CPE capture script. The OVOC capture script
sends a '200 OK' once the device setup is complete and the alarm forwarding
rule is setup on the OVOC server. If the forwarding rule fails to be created
or updated, the OVOC capture script sends a '503 Service Unavailable'
response.

After the registration the CPE capture script sends a 'CAPTURE' command to
the OVOC capture script for each targeted device to inform it which CPE
traffic should be captured. The OVOC capture script responds with a
'100 TRYING' when setting up the tcpdump, and a '200 OK' when the tcpdump
process is running. The response will be a '503 Service Unavailable'
if the tcpdump fails to start on the server.

To generate ICMP, SNMPv3, and TCP connections to the target device that
OVOC triggered the `Connection Lost` alarm on, a 'VERIFY' message is sent
from the CPE capture script to the OVOC capture script. The `VERIFY` message
is sent to the OVOC capture script so that both the server that is running
the CPE capture script and the OVOC server can create traffic to send to
the targeted CPE device. The debug capture running on the device and the
tcpdump running on the OVOC server should capture this generated traffic.
If there truly is a network connectivity issue, this generated traffic
should help isolate any issues.

The captures are stopped on the OVOC server after this script receives the 
'Connection Lost' SNMP alarm. This script will send a 'STOP' message to the
OVOC capture script to trigger it to kill the tcpdump process for that CPE
device.

For a normal flow, the following messages are exchanged:

  CPE script                                 This script
       |                                           |
       |-------- REGISTER <device address> ------->|
       |                                           |
       |<-------- 200 OK <device address> ---------|
       |                                           |
       |-------- CAPTURE <device address> -------->|
       |                                           |
       |<------ 100 TRYING <device address> -------|
       |                                           |
       |<-------- 200 OK <device address> ---------|
       |                                           |
       |     (WAIT FOR CONNECTION LOST EVENT)      |
       |                                           |
       |--------- VERIFY <device address> -------->|
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

If the OVOC capture script receives a request and the device address is not
found in the devices information dictionary, then a '404 Not Found' is
returned.

If the OVOC capture fails to be started or fails to stop, then the response
will be a '503 Service Unavailable'.

This script tracks capture states, all tasks, and other information for each
targeted CPE device. The 'devices_info' dictionary is created to track each
devices information.

The following is an example of what is tracked:

  {
      "devices": [
          {
              "device": "<device address>",
              "status": "Success|Failure",
              "severity": "NORMAL|MINOR|MAJOR|CRITICAL",
              "description": "<some descriptive text>",
              "type": "MSBR|GWSBC",
              "interfaces": [
                  "eth-lan",
                  <NEXT INTERFACE>
              ],
              "username": "<some username>",
              "password": "*****",             <- Hidden password
              "ovoc": "<associated OVOC address>",
              "completed": true|false,
              "tasks": [
                  {
                      "task": "<some task name>",
                      "status": "Success|Fail",
                      "statusCode": <some HTTP response code>,
                      "description": "<some CLI descriptive text>",
                      "timestamp": "2022-06-22T16:13:39.895358"

                      <OTHER TASK SPECIFIC ITEMS, For instance>
                      "output": "<some CLI output text>",
                      "filename": "<stored CPE debug capture filename>",

                  },

                  <NEXT TASK>

              ],
              "cpeCapture": "active|not active",
              "cpeEvent": "active|not active",
              "events": <some value>,
              "ovocCapture": "active|not active",
              "registration": "active|not active|aborted",
              "registerAttempts": <some value>,
              "lastRequest": "REGISTER|CAPTURE|VERIFY|STOP",
              "lastResponse": "100 Trying|200 OK|404 Not Found|503 Service Unavailable",
              "awaitingResponse": "True|False",
              "lastCapture": "<stored CPE capture filename>
          },

          <NEXT DEVICE>

      ]
  }

-------------------------------------------------------------------------------
"""

import io
import os
import sys
assert sys.version_info >= (3, 6), "Use Python 3.6 or newer"

import re
import csv
import json
import logging
import requests
import base64
import subprocess
import json
import time
import socket
import urllib3
import gzip
import shutil
import pathlib
import paramiko

from datetime import datetime
from getpass import getpass

# Import config.py
import config

urllib3.disable_warnings()

# ---------------------------- #
# Log File Format and Settings #
# ---------------------------- #
pathlib.Path(config.storage_dir).mkdir(parents=True, exist_ok=True)
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
# FUNCTION: send_cli_script                                                   #
#                                                                             #
# Submit a REST API request to a device to execute the desired CLI script.    #
#                                                                             #
# Parameters:                                                                 #
#     logger   - File handler for storing logged actions                      #
#     log_id   - Unique identifier for this devices log entries               #
#     script   - CLI script to execute on device in TEXT format               #
#     device   - Address of CPE device to run script on                       #
#     username - Username for account on CPE device                           #
#     password - Password for account on CPE device                           #
#                                                                             #
# Return:                                                                     #
#    task_info - Dictionary containing the following items:                   #
#        status      - String: 'Success' or 'Fail'                            #
#        statusCode  - Integer: REST response status code. (Ex: 200)          #
#        output      - Detailed information of execution of CLI script        #
#        description - String: Description of the task action                 #
# --------------------------------------------------------------------------- #
def send_cli_script(logger, log_id, script, device, username, password):
    """Submit REST API PUT request to execute CLI script on device."""

    # ------------------------------------------- #
    # Create a dictionary to hold the relevant    #
    # information to return for the current task. #
    # ------------------------------------------- #
    task_info = {}
    task_info['status'] = 'Failure'
    task_info['statusCode'] = -1
    task_info['output'] = ''
    task_info['description'] = ''

    # -------------------------------------------------------- #
    # The body of the REST API request is made up of the plain #
    # text file part.                                          #
    # -------------------------------------------------------- #
    file_contents = {'file': ('cli.txt', script)}
    event = 'REST API CLI Script:\n{}'.format(json.dumps(file_contents, indent=4))
    logger.info('{} - {}'.format(log_id, event))

    # ---------------- #
    # Set REST API URL #
    # ---------------- #
    url = "https://" + device + "/api/v1/files/cliScript/incremental"

    event = 'Method [PUT] - Request URL: {}'.format(url)
    logger.info('{} - {}'.format(log_id, event))

    # -------------------------------- #
    # Send REST request to OVOC server #
    # -------------------------------- #
    rest_response = send_rest('PUT', url, username, password, file_contents, 'files')
    rest_response_data = ''
    if type(rest_response) is str:
        rest_response_data = rest_response
        # --------------------- #
        # Truncate if necessary #
        # --------------------- #
        rest_response_data = re.sub('\s+\(Caused by.*', '', rest_response_data)
        event = 'REST Request Error: {}'.format(rest_response_data)
        logger.error('{} - {}'.format(log_id, event))

        # ------------- #
        # Set task info #
        # ------------- #
        task_info['description'] = event

        event = 'REST request failed. Could not send CLI script to device.'
        logger.error('{} - {}'.format(log_id, event))
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
            # --------------------------------------- #
            # Status Code 200 - CLI script was loaded #
            # --------------------------------------- #
            if 'status' in rest_response_data:
                if rest_response_data['status'].lower() == 'success':

                    # ------------------------------------------ #
                    # Successfully executed CLI script on device #
                    # ------------------------------------------ #
                    event = 'Successfully executed CLI script on device.'
                    logger.info('{} - {}'.format(log_id, event))

                else:

                    # ------------------------------------- #
                    # CLI script execution failed on device #
                    # ------------------------------------- #
                    event = 'CLI script execution failed on device.'
                    logger.error('{} - {}'.format(log_id, event))

                # ------------- #
                # Set task info #
                # ------------- #
                task_info['status'] = rest_response_data['status'].capitalize()
                task_info['statusCode'] = rest_response.status_code
                task_info['output'] = rest_response_data['output']
                task_info['description'] = event

            else:
                event = 'Response status was 200, but unable to extract CLI execution status!'
                logger.warning('{} - {}'.format(log_id, event))

                # ------------- #
                # Set task info #
                # ------------- #
                task_info['description'] = event

        else:
            # ---------------------------------------------- #
            # REST request to this device was not successful #
            # ---------------------------------------------- #
            if 'description' in rest_response_data:
                event = '{}'.format(rest_response_data['description'])
                logger.error('{} - {}'.format(log_id, event))
            else:
                event = 'Unexpected response received from device. Status code: [{}]'.format(rest_response.status_code)
                logger.error('{} - {}'.format(log_id, event))

            # ------------- #
            # Set task info #
            # ------------- #
            task_info['status_code'] = rest_response.status_code
            task_info['description'] = event

    return task_info

# --------------------------------------------------------------------------- #
# FUNCTION: send_request                                                      #
#                                                                             #
# Send a request command to an OVOC capture app script.                       #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     server_socket - Network socket object currenly bound to                 #
#     request       - Command request sent to OVOC capture app script         #
#     address       - Address of OVOC capture app to send request to          #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: 'True' for success, 'False' for failure                #
# --------------------------------------------------------------------------- #
def send_request(logger, log_id, server_socket, request, address):
    """Send a request command to an OVOC capture app script."""

    status = False

    event = 'Sending message to OVOC capture script: [{}]'.format(request)
    logger.info('{} - {}'.format(log_id, event))
    print('  + {}'.format(event))

    # -------------------------------------- #
    # Send the request on the network socket #
    # -------------------------------------- #
    try:
        request = request.encode()
        server_socket.sendto(request, (address, config.ovoc_listen_port))
    except Exception as err:
        event = '{}'.format(err)
        logger.error('{} - {}'.format(log_id, event))
        print('  - ERROR: {}'.format(event))

        event = 'Failed to send request to OVOC capture script!'
        logger.debug('{} - {}'.format(log_id, event))
    else:
        status = True
        event = 'Sent request to OVOC capture script.'
        logger.debug('{} - {}'.format(log_id, event))

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

    #event = 'JSON:\n{}'.format(json_dump)
    #logger.debug('{} - {}'.format(log_id, event))

    return json_dump

# --------------------------------------------------------------------------- #
# FUNCTION: validate_address                                                  #
#                                                                             #
# Verify that the address entered is either a valid IPv4, IPv6, or FQDN       #
# address and return the status of the validation.                            #
#                                                                             #
# Parameters:                                                                 #
#     address - IPv4, IPv6, or FQDN address                                   #
#                                                                             #
# Return:                                                                     #
#    valid - Boolean: True for valid, False for invalid                       #
# --------------------------------------------------------------------------- #
def validate_address(address):
    """Verify that the address entered is either a valid IPv4, IPv6, or FQDN."""

    valid = False

    # ----------------- #
    # Check IPv4 format #
    # ----------------- #
    if re.match('^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', address):
        valid = True

    if not valid:
        # ----------------- #
        # Check IPv6 format #
        # ----------------- #
        if re.match('^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$', address):
            valid = True

    if not valid:
        # ----------------- #
        # Check FQDN format #
        # ----------------- #
        if re.match('^(?=.{1,254}$)((?=[a-z0-9-]{1,63}\.)(xn--+)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$', address):
            valid = True

    return valid

# --------------------------------------------------------------------------- #
# FUNCTION: update_cpe_devices                                                #
#                                                                             #
# Update the list of CPE devices stored in the 'config.py' file if necessary. #
#                                                                             #
# Parameters:                                                                 #
#     logger       - File handler for storing logged actions                  #
#     log_id       - Unique identifier for this devices log entries           #
#     cpe_devices  - List of dicitionaries containing targeted CPE devices    #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: Success or failure of the update action.               #
# --------------------------------------------------------------------------- #
def update_cpe_devices(logger, log_id, cpe_devices):
    """Update list of CPE devices in 'config.py' file."""

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
        event = 'Success'
        logger.debug('{} - {}'.format(log_id, event))

        try:
            # -------------------------------------------------------------------- #
            # Iterate over both the entered list of CPE devices and compare it to  #
            # the list of CPE devices stored in the 'config.py' file.              #
            # The results of the 'compares iterations below will be > 0 if lists   #
            # of dictionaries are different.                                       #
            #                                                                      #
            # 'cpe_devices' is list of dictionaries from interactive entries.      #
            # 'config.cpe_devices' is list of dictionaries from the 'config.py'    #
            # file.                                                                #
            # -------------------------------------------------------------------- #
            compare_entered_to_stored = [i for i in cpe_devices if i not in config.cpe_devices]
            compare_stored_to_entered = [i for i in config.cpe_devices if i not in cpe_devices]
            if len(compare_entered_to_stored) != 0 or len(compare_stored_to_entered) != 0:
                result = re.sub("(?s)cpe_devices = (\[.*?\]\n+)", "cpe_devices = " + json.dumps(cpe_devices, indent=4) + "\n", config_file_contents, 1)

                if result != config_file_contents:
                    # ------------------------------------------------- #
                    # Configuration file contents successfully modified #
                    # ------------------------------------------------- #
                    config_file_contents = result
                    do_update = True
                    event = 'Updates for list of targeted CPE devices successfully prepared.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                else:
                    # -------------------------------------------- #
                    # Failed to modify configuration file contents #
                    # -------------------------------------------- #
                    event = 'Failed to prepare updates for list of targeted CPE devices!'
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

# --------------------------------------------------------------------------- #
# FUNCTION: get_cpe_devices                                                   #
#                                                                             #
# Build list of dictionaries that contains the CPE devices to target for      #
# network traffic captures. For each CPE device store the IP address or FQDN, #
# username and password. Any stored CPE devices in the 'config.py' file will  #
# be presented first and allowed to be modified if necessary.                 #
#                                                                             #
# Parameters:                                                                 #
#     logger - File handler for storing logged actions                        #
#     log_id - Unique identifier for this devices log entries                 #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a new record for each      #
#                   device to target.                                         #
# --------------------------------------------------------------------------- #
def get_cpe_devices(logger, log_id):
    """Build list of CPE devices to target for network captures."""
    
    devices_info = {}
    devices_info['devices'] = []

    # ------------------------------------- #
    # Valid interface lists per device type #
    # ------------------------------------- #
    msbr_interface_list = ['cellular-wan', 'fiber-wan', 'xdsl-wan', 'shdsl-wan', 't1-e1-wan', 'eth-wan', 'eth-lan']

    # ------------------------------------------------------------ #
    # This list holds the contents of the created list of CPE      #
    # devices ('devices_info') without the 'password' field being  #
    # present. This list will be stored in the 'config.py' file    #
    # for future executions of this script.                        #
    # ------------------------------------------------------------ #
    config_cpe_devices = []

    print('')
    print(':=============================================================================:')
    print(': Create a set of CPE devices to target for network traffic captures. Enter   :')
    print(': the required information to use when connecting to each device.             :')
    print(':                                                                             :')
    print(': NOTE: Previously entered CPE devices are recalled and can  be modified if   :')
    print(':       desired.                                                              :')
    print(':                                                                             :')
    print(': NOTE: To remove a stored device, type "delete" for the CPE device address.  :')
    print(':=============================================================================:')
    if len(config.cpe_devices) == 0:
        event = 'No stored CPE devices were found.'
        logger.info('{} - {}'.format(log_id, event))
        print('  - INFO: {}'.format(event))

    stored_device_index = 0
    used_device_index = 0
    while len(devices_info['devices']) == 0:

        # ------------------------------------------ #
        # Get existing CPE devices previously stored #
        # in the 'config.py' file.                   #
        # ------------------------------------------ #
        while stored_device_index < len(config.cpe_devices):

            stored_device_address = ''
            if 'device' in config.cpe_devices[stored_device_index]:
                stored_device_address = config.cpe_devices[stored_device_index]['device']
                event = 'Retrieved stored CPE device address: [{}]'.format(stored_device_address)
                logger.info('{} - {}'.format(log_id, event))
            stored_device_type = ''
            if 'type' in config.cpe_devices[stored_device_index]:
                stored_device_type = config.cpe_devices[stored_device_index]['type']
                event = 'Retrieved stored CPE device type: [{}]'.format(stored_device_type)
                logger.info('{} - {}'.format(log_id, event))
            stored_device_interfaces = []
            if 'interfaces' in config.cpe_devices[stored_device_index]:
                stored_device_interfaces = config.cpe_devices[stored_device_index]['interfaces']
                event = 'Retrieved stored CPE device interfaces: [{}]'.format(', '.join(stored_device_interfaces))
                logger.info('{} - {}'.format(log_id, event))
            stored_device_user = ''
            if 'username' in config.cpe_devices[stored_device_index]:
                stored_device_user = config.cpe_devices[stored_device_index]['username']
                event = 'Retrieved stored CPE device username: [{}]'.format(stored_device_user)
                logger.info('{} - {}'.format(log_id, event))
            stored_ovoc_address = ''
            if 'ovoc' in config.cpe_devices[stored_device_index]:
                stored_ovoc_address = config.cpe_devices[stored_device_index]['ovoc']
                event = 'Retrieved stored CPE associated OVOC address: [{}]'.format(stored_ovoc_address)
                logger.info('{} - {}'.format(log_id, event))

            # --------------------------------------------- #
            # Output CPE device entries are associated with #
            # --------------------------------------------- #
            print('CPE device #{}:'.format(used_device_index + 1))

            # ------------------------------------------- #
            # Allow modification of stored device address #
            # ------------------------------------------- #
            skip_device = False
            got_address = False
            while not got_address:
                this_device_address = str(input('  - IP address or FQDN: (delete) [{}] '.format(stored_device_address))).strip()
                event = 'Entered CPE device: [{}]'.format(this_device_address)
                logger.info('{} - {}'.format(log_id, event))
                if this_device_address == '':
                    this_device_address = stored_device_address
                    event = 'Using existing CPE device address: [{}]'.format(this_device_address)
                    logger.info('{} - {}'.format(log_id, event))
                    got_address = True

                elif this_device_address.lower() == 'delete':
                    skip_device = True
                    got_address = True
                    event = 'Removed CPE device [{}] from list of targeted devices.'.format(stored_device_address)
                    logger.info('{} - {}'.format(log_id, event))
                    print('    - INFO: {}'.format(event))

                else:
                    # ------------------------------------------------------ #
                    # Validate entered address is either IPv4, IPv6, or FQDN #
                    # ------------------------------------------------------ #
                    valid_address = validate_address(this_device_address)
                    if valid_address:
                        event = 'Modifying CPE device address to: [{}]'.format(this_device_address)
                        logger.info('{} - {}'.format(log_id, event))
                        got_address = True
                    else:
                        event = 'Must enter an valid IPv4/IPv6 address or FQDN to use for accessing the CPE device.'
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))

            if not skip_device:
                # ---------------------------------------- #
                # Allow modification of stored device type #
                # ---------------------------------------- #
                this_device_type = ''
                while this_device_type == '':
                    this_device_type = str(input('  - Type: (msbr|gwsbc) [{}] '.format(stored_device_type))).strip().upper()
                    event = 'Entered CPE device type: [{}]'.format(this_device_type)
                    logger.info('{} - {}'.format(log_id, event))
                    if this_device_type == '':
                        this_device_type = stored_device_type
                        if this_device_type != '':
                            event = 'Using existing CPE device type: [{}]'.format(this_device_type)
                            logger.info('{} - {}'.format(log_id, event))
                        else:
                            event = 'Must enter a device type for the CPE device.'
                            logger.error('{} - {}'.format(log_id, event))
                            print('    - ERROR: {} Try again.'.format(event))
                    else:
                        if this_device_type == 'MSBR' or this_device_type == 'GWSBC':
                            event = 'Modifying CPE device type to: [{}]'.format(this_device_type)
                            logger.info('{} - {}'.format(log_id, event))
                        else:
                            event = 'Device type must be one of the following values: ("msbr"|"gwsbc")'
                            logger.error('{} - {}'.format(log_id, event))
                            print('    - ERROR: {} Try again.'.format(event))
                            this_device_type = ''

                # --------------------------------------------------- #
                # Allow modification of stored device interfaces list #
                # --------------------------------------------------- #
                this_device_interfaces = []
                if this_device_type == 'MSBR':
                    print('')
                    print('  MSBR capture interface options:')
                    print('  :-----------------------------------------------------------------------------:')
                    print('  : Valid Options: "cellular-wan", "fiber-wan", "xdsl-wan", "shdsl-wan",        :')
                    print('  :                "t1-e1-wan", "eth-wan", or "eth-lan"                         :')
                    print('  :                                                                             :')
                    print('  : NOTE: To remove a stored interface, type "delete" for the entry.            :')
                    print('  :-----------------------------------------------------------------------------:')

                    # ------------------------- #
                    # Display stored interfaces #
                    # ------------------------- #
                    print('  Stored interfaces: [{}]'.format(', '.join(stored_device_interfaces)))

                    interface_index = 0
                    for stored_device_interface in stored_device_interfaces:
                        skip_interface = False
                        got_interface = False
                        while not got_interface:
                            this_device_interface = str(input('  - Capture interface #{}: (delete) [{}] '.format(interface_index + 1, stored_device_interface))).strip().lower()

                            event = 'Entered capture interface #{}: [{}]'.format(interface_index + 1, this_device_interface)
                            logger.info('{} - {}'.format(log_id, event))

                            if this_device_interface == '':

                                this_device_interface = stored_device_interface
                                if this_device_interface in msbr_interface_list:
                                    if this_device_interface not in this_device_interfaces:
                                        event = 'Using existing capture interface: [{}]'.format(this_device_interface)
                                        logger.info('{} - {}'.format(log_id, event))
                                        this_device_interfaces.append(this_device_interface)
                                        got_interface = True
                                        interface_index += 1
                                    else:
                                        event = 'Interface already in list for capturing traffic.'
                                        logger.error('{} - {}'.format(log_id, event))
                                        print('    - ERROR: {} Try again.'.format(event))
                                else:
                                    event = 'Capture interface option no longer valid. Must be one of the valid options above.'
                                    logger.error('{} - {}'.format(log_id, event))
                                    print('    - ERROR: {} Try again.'.format(event))

                            elif this_device_interface.lower() == 'delete':
                                skip_interface = True
                                got_interface = True
                                event = 'Removed interface [{}] from list to capture.'.format(stored_device_interface)
                                logger.info('{} - {}'.format(log_id, event))
                                print('    - INFO: {}'.format(event))

                            else:
                                # ------------------------------------------- #
                                # Validate entered is in MSBR interfaces list #
                                # ------------------------------------------- #
                                if this_device_interface in msbr_interface_list:
                                    if this_device_interface not in this_device_interfaces:
                                        event = 'Modifying capture interface to: [{}]'.format(this_device_interface)
                                        logger.info('{} - {}'.format(log_id, event))
                                        this_device_interfaces.append(this_device_interface)
                                        got_interface = True
                                        interface_index += 1
                                    else:
                                        event = 'Interface already in list for capturing traffic.'
                                        logger.error('{} - {}'.format(log_id, event))
                                        print('    - ERROR: {} Try again.'.format(event))
                                else:
                                    event = 'Capture interface must be one of the valid options above.'
                                    logger.error('{} - {}'.format(log_id, event))
                                    print('    - ERROR: {} Try again.'.format(event))
                                    this_device_interface = ''

                    if len(this_device_interfaces) != 0:
                        #print('')
                        reply = ''
                        while reply != 'y' and reply != 'n':
                            reply = str(input('    Add another capture interface: (y/n) [n] ')).lower().strip()
                            if reply == '':
                                reply = 'n'
                            else:
                                reply = reply[0]
                    else:
                        reply = 'y'

                    while reply == 'y':

                        this_device_interface = ''
                        while this_device_interface == '':
                            this_device_interface = str(input('  - Capture interface #{}: '.format(interface_index + 1))).strip()
                            event = 'Entered capture interface #{}: [{}]'.format(interface_index + 1, this_device_interface)
                            logger.info('{} - {}'.format(log_id, event))
                            # ------------------------------------------- #
                            # Validate entered is in MSBR interfaces list #
                            # ------------------------------------------- #
                            if this_device_interface in msbr_interface_list:
                                if this_device_interface not in this_device_interfaces:
                                    event = 'Adding capture interface: [{}]'.format(this_device_interface)
                                    logger.info('{} - {}'.format(log_id, event))
                                    this_device_interfaces.append(this_device_interface)
                                else:
                                    event = 'Interface already in list for capturing traffic.'
                                    logger.error('{} - {}'.format(log_id, event))
                                    print('    - ERROR: {} Try again.'.format(event))
                                    this_device_interface = ''
                            else:
                                event = 'Capture interface must be one of the valid options above.'
                                logger.error('{} - {}'.format(log_id, event))
                                print('    - ERROR: {} Try again.'.format(event))
                                this_device_interface = ''

                        event = 'Set new capture interface #{} to: [{}]'.format(interface_index + 1, this_device_interface)
                        logger.info('{} - {}'.format(log_id, event))

                        interface_index += 1

                        #print('')
                        reply = ''
                        while reply != 'y' and reply != 'n':
                            reply = str(input('    Add another capture interface: (y/n) [n] ')).lower().strip()
                            if reply == '':
                                reply = 'n'
                            else:
                                reply = reply[0]

                else:
                    # -------------------------------------------------- #
                    # Only allowed interface for gateway and SBC devices #
                    # -------------------------------------------------- #
                    this_device_interfaces = ['eth-lan']

                # -------------------------------------------- #
                # Allow modification of stored device username #
                # -------------------------------------------- #
                this_device_user = ''
                while this_device_user == '':
                    this_device_user = str(input('  - Username: [{}] '.format(stored_device_user))).strip()
                    event = 'Entered CPE device username: [{}]'.format(this_device_user)
                    logger.info('{} - {}'.format(log_id, event))
                    if this_device_user == '':
                        this_device_user = stored_device_user
                        if this_device_user != '':
                            event = 'Using existing CPE device username: [{}]'.format(this_device_user)
                            logger.info('{} - {}'.format(log_id, event))
                        else:
                            event = 'Must enter a username to use for accessing an account on the CPE device.'
                            logger.error('{} - {}'.format(log_id, event))
                            print('    - ERROR: {} Try again.'.format(event))
                    else:
                        event = 'Modifying CPE device username to: [{}]'.format(this_device_user)
                        logger.info('{} - {}'.format(log_id, event))

                # ------------------------------ #
                # Get password for stored device #
                # ------------------------------ #
                this_device_pass = ''
                while this_device_pass == '':
                    this_device_pass = getpass(prompt='  - Password: ')
                    this_device_pass_verify = getpass(prompt='    Confirm password: ')
                    if this_device_pass != this_device_pass_verify:
                        event = 'Entered passwords do NOT match.'
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {} Try again.'.format(event))
                        this_device_pass = ''
                    else:
                        if this_device_pass == '':
                            event = 'Passwords can not be empty!'
                            logger.error('{} - {}'.format(log_id, event))
                            print('    - ERROR: {} Try again.'.format(event))
                        else:
                            event = 'Entered passwords match!'
                            logger.info('{} - {}'.format(log_id, event))
                            print('    - INFO: {}'.format(event))

                # --------------------------- #
                # Get associated OVOC address #
                # --------------------------- #
                got_address = False
                while not got_address:
                    this_ovoc_address = str(input('  - Associated OVOC IP address or FQDN: [{}] '.format(stored_ovoc_address))).strip()
                    event = 'Entered CPE associated OVOC: [{}]'.format(this_ovoc_address)
                    logger.info('{} - {}'.format(log_id, event))
                    if this_ovoc_address == '':
                        this_ovoc_address = stored_ovoc_address
                        event = 'Using existing CPE associated OVOC address: [{}]'.format(this_ovoc_address)
                        logger.info('{} - {}'.format(log_id, event))
                        got_address = True
                    else:
                        # ------------------------------------------------------ #
                        # Validate entered address is either IPv4, IPv6, or FQDN #
                        # ------------------------------------------------------ #
                        valid_address = validate_address(this_ovoc_address)
                        if valid_address:
                            event = 'Modifying CPE associated OVOC address to: [{}]'.format(this_ovoc_address)
                            logger.info('{} - {}'.format(log_id, event))
                            got_address = True
                        else:
                            event = 'Must enter an valid IPv4/IPv6 address or FQDN to use for the CPE associated OVOC address.'
                            logger.error('{} - {}'.format(log_id, event))
                            print('    - ERROR: {}'.format(event))

                used_device_index += 1

                # ------------------------ #
                # Create CPE device record #
                # ------------------------ #
                devices_info['devices'].append({})
                device_index = len(devices_info['devices']) - 1
                devices_info['devices'][device_index]['device'] = this_device_address
                devices_info['devices'][device_index]['type'] = this_device_type
                devices_info['devices'][device_index]['interfaces'] = this_device_interfaces
                devices_info['devices'][device_index]['username'] = this_device_user
                devices_info['devices'][device_index]['password'] = this_device_pass
                devices_info['devices'][device_index]['ovoc'] = this_ovoc_address
                devices_info['devices'][device_index]['awaitingResponse'] = False
                devices_info['devices'][device_index]['completed'] = False
                devices_info['devices'][device_index]['tasks'] = []

                # ---------------------------------------------------- #
                # Default 'cpeCapture' to 'not active' to indicate the #
                # device isn't currently performing a network capture. #
                # ---------------------------------------------------- #
                devices_info['devices'][device_index]['cpeCapture'] = 'not active'

                # -------------------------------------------------- #
                # Default 'cpeEvent' to 'not active' to indicate the #
                # device isn't currently in a triggered event state. #
                # -------------------------------------------------- #
                devices_info['devices'][device_index]['cpeEvent'] = 'not active'

                # --------------------------------------------------------- #
                # Default 'ovocCapture' to 'not active' to indicate the     #
                # OVOC server isn't currently performing a network capture. #
                # --------------------------------------------------------- #
                devices_info['devices'][device_index]['ovocCapture'] = 'not active'

                # ------------------------------------------------------ #
                # Also default the 'registration' status to 'not active' #
                # to indicate that the device has not yet successfully   #
                # communicated to the associated OVOC capture script.    #
                # ------------------------------------------------------ #
                devices_info['devices'][device_index]['registration'] = 'not active'
                devices_info['devices'][device_index]['registerAttempts'] = 0

                # ------------------------------------------------ #
                # Default the number of alarm events seen for this #
                # device to 0. Each device will restart the        #
                # capture after receiving an alarm from OVOC.      #
                # ------------------------------------------------ #
                devices_info['devices'][device_index]['events'] = 0

                # ------------------------------------------------ #
                # Create OVOC server record to store in the        #
                # 'config.py' file. Do not store the OVOC          #
                # password since it would be stored in plain text. #
                # ------------------------------------------------ #
                config_cpe_devices.append({})
                device_index = len(devices_info['devices']) - 1
                config_cpe_devices[device_index]['device'] = this_device_address
                config_cpe_devices[device_index]['type'] = this_device_type
                config_cpe_devices[device_index]['interfaces'] = this_device_interfaces
                config_cpe_devices[device_index]['username'] = this_device_user
                config_cpe_devices[device_index]['ovoc'] = this_ovoc_address

            stored_device_index += 1

        # ------------------------------ #
        # Option to add more CPE devices #
        # ------------------------------ #
        if len(devices_info['devices']) != 0:
            print('')
            reply = ''
            while reply != 'y' and reply != 'n':
                reply = str(input('Add another targeted CPE device: (y/n) [n] ')).lower().strip()
                if reply == '':
                    reply = 'n'
                else:
                    reply = reply[0]
        else:
            reply = 'y'

        while reply == 'y':

            # --------------------------------------------- #
            # Output CPE device entries are associated with #
            # --------------------------------------------- #
            print('CPE device #{}:'.format(used_device_index + 1))

            # ---------------------------- #
            # Enter new CPE device address #
            # ---------------------------- #
            this_device_address = ''
            while this_device_address == '':
                this_device_address = str(input('  - IP address or FQDN: ')).strip()
                event = 'Entered CPE device: [{}]'.format(this_device_address)
                logger.info('{} - {}'.format(log_id, event))
                # ------------------------------------------------------ #
                # Validate entered address is either IPv4, IPv6, or FQDN #
                # ------------------------------------------------------ #
                valid_address = validate_address(this_device_address)
                if not valid_address:
                    event = 'Must enter an valid IPv4/IPv6 address or FQDN to use for accessing the CPE device.'
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))
                    this_device_address = ''

            event = 'Set new CPE device address to: [{}]'.format(this_device_address)
            logger.info('{} - {}'.format(log_id, event))

            # ------------------------- #
            # Enter new CPE device type #
            # ------------------------- #
            this_device_type = ''
            while this_device_type == '':
                this_device_type = str(input('  - Type: (msbr|gwsbc) ')).strip().upper()
                event = 'Entered CPE device type: [{}]'.format(this_device_address)
                logger.info('{} - {}'.format(log_id, event))
                if this_device_type == '':
                    event = 'Must enter a device type for the CPE device.'
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))

            event = 'Set new CPE device type to: [{}]'.format(this_device_type)
            logger.info('{} - {}'.format(log_id, event))

            # ----------------------------------------------------- #
            # Enter new CPE capture interfaces if device is an MSBR #
            # ----------------------------------------------------- #
            this_device_interfaces = []
            if this_device_type == 'MSBR':

                print('')
                print('  MSBR capture interface options:')
                print('  :-----------------------------------------------------------------------------:')
                print('  : Valid Options: "cellular-wan", "fiber-wan", "xdsl-wan", "shdsl-wan",        :')
                print('  :                "t1-e1-wan", "eth-wan", or "eth-lan"                         :')
                print('  :                                                                             :')
                print('  : NOTE: To remove a stored interface, type "delete" for the entry.            :')
                print('  :-----------------------------------------------------------------------------:')

                interface_index = 0
                reply = 'y'

                while reply == 'y':

                    this_device_interface = ''
                    while this_device_interface == '':
                        this_device_interface = str(input('  - Capture interface #{}: '.format(interface_index + 1))).strip()
                        event = 'Entered capture interface #{}: [{}]'.format(interface_index + 1, this_device_interface)
                        logger.info('{} - {}'.format(log_id, event))
                        # ------------------------------------------- #
                        # Validate entered is in MSBR interfaces list #
                        # ------------------------------------------- #
                        if this_device_interface in msbr_interface_list:
                            if this_device_interface not in this_device_interfaces:
                                event = 'Adding capture interface: [{}]'.format(this_device_interface)
                                logger.info('{} - {}'.format(log_id, event))
                                this_device_interfaces.append(this_device_interface)
                            else:
                                event = 'Interface already in list for capturing traffic.'
                                logger.error('{} - {}'.format(log_id, event))
                                print('    - ERROR: {} Try again.'.format(event))
                                this_device_interface = ''
                        else:
                            event = 'Capture interface must be one of the valid options above.'
                            logger.error('{} - {}'.format(log_id, event))
                            print('    - ERROR: {} Try again.'.format(event))
                            this_device_interface = ''

                    event = 'Set new capture interface #{} to: [{}]'.format(interface_index + 1, this_device_interface)
                    logger.info('{} - {}'.format(log_id, event))

                    interface_index += 1

                    #print('')
                    reply = ''
                    while reply != 'y' and reply != 'n':
                        reply = str(input('    Add another capture interface: (y/n) [n] ')).lower().strip()
                        if reply == '':
                            reply = 'n'
                        else:
                            reply = reply[0]

            else:
                # -------------------------------------------------- #
                # Only allowed interface for gateway and SBC devices #
                # -------------------------------------------------- #
                this_device_interfaces = ['eth-lan']
                event = 'Set new capture interface to: [eth-lan]'
                logger.info('{} - {}'.format(log_id, event))

            # ----------------------------- #
            # Enter new CPE device username #
            # ----------------------------- #
            this_device_user = ''
            while this_device_user == '':
                this_device_user = str(input('  - Username: ')).strip()
                event = 'Entered CPE device username: [{}]'.format(this_device_address)
                logger.info('{} - {}'.format(log_id, event))
                if this_device_user == '':
                    event = 'Must enter a username to use for accessing an account on the CPE device.'
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))

            event = 'Set new CPE device username to: [{}]'.format(this_device_user)
            logger.info('{} - {}'.format(log_id, event))

            # ----------------------------- #
            # Enter new CPE device password #
            # ----------------------------- #
            this_device_pass = ''
            while this_device_pass == '':
                this_device_pass = getpass(prompt='  - Password: ')
                this_device_pass_verify = getpass(prompt='    Confirm password: ')
                if this_device_pass != this_device_pass_verify:
                    event = 'Entered passwords to NOT match.'
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {} Try again.'.format(event))
                    this_device_pass = ''
                else:
                    if this_device_pass == '':
                        event = 'Passwords can not be empty!'
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {} Try again.'.format(event))
                    else:
                        event = 'Entered passwords match!'
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

            event = 'Set CPE device password.'
            logger.info('{} - {}'.format(log_id, event))

            # ------------------------------------ #
            # Enter new CPE device associated OVOC #
            # ------------------------------------ #
            this_ovoc_address = ''
            while this_ovoc_address == '':
                this_ovoc_address = str(input('  - Associated OVOC IP address or FQDN: ')).strip()
                event = 'Entered CPE associated OVOC: [{}]'.format(this_ovoc_address)
                logger.info('{} - {}'.format(log_id, event))
                # ------------------------------------------------------ #
                # Validate entered address is either IPv4, IPv6, or FQDN #
                # ------------------------------------------------------ #
                valid_address = validate_address(this_ovoc_address)
                if not valid_address:
                    event = 'Must enter an valid IPv4/IPv6 address or FQDN to use for the CPE associated OVOC address.'
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))
                    this_ovoc_address = ''

            event = 'Set new CPE associated OVOC address to: [{}]'.format(this_ovoc_address)
            logger.info('{} - {}'.format(log_id, event))

            # ------------------------ #
            # Create CPE device record #
            # ------------------------ #
            devices_info['devices'].append({})
            device_index = len(devices_info['devices']) - 1
            devices_info['devices'][device_index]['device'] = this_device_address
            devices_info['devices'][device_index]['type'] = this_device_type
            devices_info['devices'][device_index]['interfaces'] = this_device_interfaces
            devices_info['devices'][device_index]['username'] = this_device_user
            devices_info['devices'][device_index]['password'] = this_device_pass
            devices_info['devices'][device_index]['ovoc'] = this_ovoc_address
            devices_info['devices'][device_index]['awaitingResponse'] = False
            devices_info['devices'][device_index]['completed'] = False
            devices_info['devices'][device_index]['tasks'] = []

            # ---------------------------------------------------- #
            # Default 'cpeCapture' to 'not active' to indicate the #
            # device isn't currently performing a network capture. #
            # ---------------------------------------------------- #
            devices_info['devices'][device_index]['cpeCapture'] = 'not active'

            # -------------------------------------------------- #
            # Default 'cpeEvent' to 'not active' to indicate the #
            # device isn't currently in a triggered event state. #
            # -------------------------------------------------- #
            devices_info['devices'][device_index]['cpeEvent'] = 'not active'

            # --------------------------------------------------------- #
            # Default 'ovocCapture' to 'not active' to indicate the     #
            # OVOC server isn't currently performing a network capture. #
            # --------------------------------------------------------- #
            devices_info['devices'][device_index]['ovocCapture'] = 'not active'

            # ------------------------------------------------------ #
            # Also default the 'registration' status to 'not active' #
            # to indicate that the device has not yet successfully   #
            # communicated to the associated OVOC capture script.    #
            # ------------------------------------------------------ #
            devices_info['devices'][device_index]['registration'] = 'not active'
            devices_info['devices'][device_index]['registerAttempts'] = 0

            # ------------------------------------------------ #
            # Default the number of alarm events seen for this #
            # device to 0. Each device will restart the        #
            # capture after receiving an alarm from OVOC.      #
            # ------------------------------------------------ #
            devices_info['devices'][device_index]['events'] = 0

            # ------------------------------------------------ #
            # Create OVOC server record to store in the        #
            # 'config.py' file. Do not store the OVOC          #
            # password since it would be stored in plain text. #
            # ------------------------------------------------ #
            config_cpe_devices.append({})
            device_index = len(devices_info['devices']) - 1
            config_cpe_devices[device_index]['device'] = this_device_address
            config_cpe_devices[device_index]['type'] = this_device_type
            config_cpe_devices[device_index]['interfaces'] = this_device_interfaces
            config_cpe_devices[device_index]['username'] = this_device_user
            config_cpe_devices[device_index]['ovoc'] = this_ovoc_address

            used_device_index += 1

            print('')
            reply = ''
            while reply != 'y' and reply != 'n':
                reply = str(input('Add another targeted CPE device: (y/n) [n] ')).lower().strip()
                if reply == '':
                    reply = 'n'
                else:
                    reply = reply[0]

        if len(devices_info['devices']) == 0:
            event = 'Must enter at least one CPE device to target for the network traffic capture.'
            logger.error('{} - {}'.format(log_id, event))
            print('  - ERROR: {} Try again.'.format(event))

    event = 'Set targeted CPE devices:\n{}'.format(json.dumps(config_cpe_devices, indent=4))
    logger.debug('{} - {}'.format(log_id, event))

    # ------------------------------------------------------ #
    # Check if updates are necessary to the 'config.py' file #
    # ------------------------------------------------------ #
    if not update_cpe_devices(logger, log_id, config_cpe_devices):
        event = 'Failed to update CPE devices in "config.py" file!'
        logger.warning('{} - {}'.format(log_id, event))
        print('  - WARNING: {} You can continue without saving the values entered.'.format(event))

    return devices_info

# --------------------------------------------------------------------------- #
# FUNCTION: update_listen_port                                                #
#                                                                             #
# Update the value stored in the 'config.py' file if necessary that defines   #
# the UDP port this script will listen on for forwarded SYSLOG format alarms  #
# and other OVOC server command responses when starting captures on the       #
# appropriate OVOC servers.                                                   #
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

# --------------------------------------------------------------------------- #
# FUNCTION: get_listen_port                                                   #
#                                                                             #
# Get UDP port to listen on when waiting for forwarded alarms from an OVOC    #
# server.                                                                     #
#                                                                             #
# Parameters:                                                                 #
#     logger - File handler for storing logged actions                        #
#     log_id - Unique identifier for this devices log entries                 #
#                                                                             #
# Return:                                                                     #
#    listen_port - Integer value in the range (1025 - 65535)                  #
# --------------------------------------------------------------------------- #
def get_listen_port(logger, log_id):
    """Get UDP port number to listen on for forwarded alarms from and OVOC server."""

    listen_port = 1025

    stored_listen_port = config.listen_port

    event = 'Retrieved stored UDP listen port: [{}]'.format(stored_listen_port)
    logger.info('{} - {}'.format(log_id, event))

    # -------------------------------------------- #
    # Allow modification of stored UDP listen port #
    # -------------------------------------------- #
    print('')
    print(':=============================================================================:')
    print(': UDP port to listen on for incoming alarms forwarded by an OVOC server.      :')
    print(': Alarms are expected to be in SYSLOG format.                                 :')
    print(':                                                                             :')
    print(': NOTE: Entered port should be in the range (1025 - 65535)                    :')
    print(':=============================================================================:')
    got_listen_port = False
    while not got_listen_port:

        this_listen_port = input('Enter UDP port to listen on: (1025-65535) [{}] '.format(stored_listen_port))
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
# FUNCTION: update_max_reg_attempts                                           #
#                                                                             #
# Update the value stored in the 'config.py' file if necessary that defines   #
# the maximum number of registration attempts that are made before aborting   #
# the captures for this device on this current session.                       #
#                                                                             #
# Parameters:                                                                 #
#     logger           - File handler for storing logged actions              #
#     log_id           - Unique identifier for this devices log entries       #
#     max_reg_attempts - Maximum number of REST API retry attempts            #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: Success or failure of the update action.               #
# --------------------------------------------------------------------------- #
def update_max_reg_attempts(logger, log_id, max_reg_attempts):
    """Update max registration attempts value that is stored in 'config.py' file."""

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
            # ------------------------------------ #
            # Check 'max_reg_attempts' for changes #
            # ------------------------------------ #
            if max_reg_attempts != "" and int(max_reg_attempts) != config.max_reg_attempts:
                result = re.sub("(?s)max_reg_attempts = .*?$", "max_reg_attempts = " + str(max_reg_attempts), config_file_contents, 1, re.MULTILINE)

                if result != config_file_contents:
                    # ------------------------------------------------- #
                    # Configuration file contents successfully modified #
                    # ------------------------------------------------- #
                    config_file_contents = result
                    do_update = True
                    event = 'Max allowed registration retry attempts update successfully prepared.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                else:
                    # -------------------------------------------- #
                    # Failed to modify configuration file contents #
                    # -------------------------------------------- #
                    event = 'Failed to prepare update for max allowed registration retry attempts!'
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

# --------------------------------------------------------------------------- #
# FUNCTION: get_max_reg_attempts                                              #
#                                                                             #
# Get value for maximum number of registration attempts will be made to an    #
# OVOC capture app script before the task is marked as failed.                #
#                                                                             #
# Parameters:                                                                 #
#     logger - File handler for storing logged actions                        #
#     log_id - Unique identifier for this devices log entries                 #
#                                                                             #
# Return:                                                                     #
#    max_reg_attempts - Integer value in the range (1 - 25)                   #
# --------------------------------------------------------------------------- #
def get_max_reg_attempts(logger, log_id):
    """Get value for max allowed registration attempts to an OVOC capture app script."""

    max_reg_attempts = 5

    stored_max_reg_attempts = config.max_reg_attempts

    event = 'Retrieved stored max allowed registration attempts value: [{}]'.format(stored_max_reg_attempts)
    logger.info('{} - {}'.format(log_id, event))

    # ---------------------------------------------------- #
    # Allow modification of stored REST API retry attempts #
    # ---------------------------------------------------- #
    print('')
    print(':=============================================================================:')
    print(': Maximum number of registration attempts allowed when sending connection     :')
    print(': requests to an associated OVOC capture app script. If the registration is   :')
    print(': unsuccessful, then no capture will be performed for the device that failed  :')
    print(': to register for this session of the CPE capture script.                     :')
    print(':                                                                             :')
    print(': NOTE: Entered value should be in the range (1 - 25)                         :')
    print(':=============================================================================:')
    got_max_reg_attempts = False
    while not got_max_reg_attempts:

        this_max_reg_attempts = input('Enter CPE registration attempts: (1-25) [{}] '.format(stored_max_reg_attempts))
        if this_max_reg_attempts == '':
            got_max_reg_attempts = True
            max_reg_attempts = stored_max_reg_attempts
        else:
            try:
                this_max_reg_attempts = int(this_max_reg_attempts)
                if this_max_reg_attempts >= 1 and this_max_reg_attempts <= 25:
                    got_max_reg_attempts = True
                    max_reg_attempts = this_max_reg_attempts
                else:
                    event = 'Invalid setting: [{}]. Must be a value in the range (1-25).'.format(this_max_reg_attempts)
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {} Try again.\n'.format(event))
                    got_max_reg_attempts = False
            except ValueError:
                event = 'Invalid number: [{}]. Must be a value in the range (1-25).'.format(this_max_reg_attempts)
                logger.error('{} - {}'.format(log_id, event))
                print('  - ERROR: {} Try again.\n'.format(event))
                got_max_reg_attempts = False

    event = 'Set CPE registration attempts to: [{}]'.format(max_reg_attempts)
    logger.info('{} - {}'.format(log_id, event))
    print('  - INFO: {}'.format(event))

    # ------------------------------------------------------ #
    # Check if updates are necessary to the 'config.py' file #
    # ------------------------------------------------------ #
    if not update_max_reg_attempts(logger, log_id, max_reg_attempts):
        event = 'Failed to update "config.py" file!'
        logger.warning('{} - {}'.format(log_id, event))
        print('  - WARNING: {} You can continue without saving the value entered.'.format(event))

    return max_reg_attempts

# --------------------------------------------------------------------------- #
# FUNCTION: update_max_retries                                                #
#                                                                             #
# Update the value stored in the 'config.py' file if necessary that defines   #
# the maximum number of REST API retry attempts that are made before failing  #
# the task.                                                                   #
#                                                                             #
# Parameters:                                                                 #
#     logger       - File handler for storing logged actions                  #
#     log_id       - Unique identifier for this devices log entries           #
#     max_retries  - Maximum number of REST API retry attempts                #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: Success or failure of the update action.               #
# --------------------------------------------------------------------------- #
def update_max_retries(logger, log_id, max_retries):
    """Update max REST API retry attempts value that is stored in 'config.py' file."""

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
            # Check 'max_retries' for changes #
            # ------------------------------- #
            if max_retries != "" and int(max_retries) != config.max_retries:
                result = re.sub("(?s)max_retries = .*?$", "max_retries = " + str(max_retries), config_file_contents, 1, re.MULTILINE)

                if result != config_file_contents:
                    # ------------------------------------------------- #
                    # Configuration file contents successfully modified #
                    # ------------------------------------------------- #
                    config_file_contents = result
                    do_update = True
                    event = 'Max allowed REST API retry attempts update successfully prepared.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                else:
                    # -------------------------------------------- #
                    # Failed to modify configuration file contents #
                    # -------------------------------------------- #
                    event = 'Failed to prepare update for max allowed REST API retry attempts!'
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

# --------------------------------------------------------------------------- #
# FUNCTION: get_max_retries                                                   #
#                                                                             #
# Get value for maximum number of REST API retry attempts will be made to a   #
# CPE device before the task is marked as failed.                             #
#                                                                             #
# Parameters:                                                                 #
#     logger - File handler for storing logged actions                        #
#     log_id - Unique identifier for this devices log entries                 #
#                                                                             #
# Return:                                                                     #
#    max_retries - Integer value in the range (1 - 100)                       #
# --------------------------------------------------------------------------- #
def get_max_retries(logger, log_id):
    """Get value for max allowed REST API retry attempts to a CPE device."""

    max_retries = 5

    stored_max_retries = config.max_retries

    event = 'Retrieved stored max allowed REST API retry attempts value: [{}]'.format(stored_max_retries)
    logger.info('{} - {}'.format(log_id, event))

    # ---------------------------------------------------- #
    # Allow modification of stored REST API retry attempts #
    # ---------------------------------------------------- #
    print('')
    print(':=============================================================================:')
    print(': Maximum number of REST API retry attempts allowed when sending requests to  :')
    print(': CPE devices.                                                                :')
    print(':                                                                             :')
    print(': NOTE: Entered value should be in the range (1 - 100)                        :')
    print(':=============================================================================:')
    got_max_retries = False
    while not got_max_retries:

        this_max_retries = input('Enter REST API retry attempts: (1-100) [{}] '.format(stored_max_retries))
        if this_max_retries == '':
            got_max_retries = True
            max_retries = stored_max_retries
        else:
            try:
                this_max_retries = int(this_max_retries)
                if this_max_retries >= 1 and this_max_retries <= 100:
                    got_max_retries = True
                    max_retries = this_max_retries
                else:
                    event = 'Invalid setting: [{}]. Must be a value in the range (1-100).'.format(this_max_retries)
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {} Try again.\n'.format(event))
                    got_max_retries = False
            except ValueError:
                event = 'Invalid number: [{}]. Must be a value in the range (1-100).'.format(this_max_retries)
                logger.error('{} - {}'.format(log_id, event))
                print('  - ERROR: {} Try again.\n'.format(event))
                got_max_retries = False

    event = 'Set REST API retry attempts to: [{}]'.format(max_retries)
    logger.info('{} - {}'.format(log_id, event))
    print('  - INFO: {}'.format(event))

    # ------------------------------------------------------ #
    # Check if updates are necessary to the 'config.py' file #
    # ------------------------------------------------------ #
    if not update_max_retries(logger, log_id, max_retries):
        event = 'Failed to update "config.py" file!'
        logger.warning('{} - {}'.format(log_id, event))
        print('  - WARNING: {} You can continue without saving the value entered.'.format(event))

    return max_retries

# --------------------------------------------------------------------------- #
# FUNCTION: update_max_events_per_device                                      #
#                                                                             #
# Update the value stored in the 'config.py' file if necessary that defines   #
# the maximum number of OVOC alarm trigger events that can be received for a  #
# CPE device and have its network traffic capture restarted. After the max    #
# number of events is reached, the traffic capture on that device is not      #
# restarted.                                                                  #
#                                                                             #
# Parameters:                                                                 #
#     logger       - File handler for storing logged actions                  #
#     log_id       - Unique identifier for this devices log entries           #
#     max_events_per_device - Maximum number of events for each device        #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: Success or failure of the update action.               #
# --------------------------------------------------------------------------- #
def update_max_events_per_device(logger, log_id, max_events_per_device):
    """Update max OVOC trigger events per device value that is stored in the 'config.py' file."""

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
            # ----------------------------------------- #
            # Check 'max_events_per_device' for changes #
            # ----------------------------------------- #
            if max_events_per_device != "" and int(max_events_per_device) != config.max_events_per_device:
                result = re.sub("(?s)max_events_per_device = .*?$", "max_events_per_device = " + str(max_events_per_device), config_file_contents, 1, re.MULTILINE)

                if result != config_file_contents:
                    # ------------------------------------------------- #
                    # Configuration file contents successfully modified #
                    # ------------------------------------------------- #
                    config_file_contents = result
                    do_update = True
                    event = 'Max allowed events per device update successfully prepared.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  - INFO: {}'.format(event))
                else:
                    # -------------------------------------------- #
                    # Failed to modify configuration file contents #
                    # -------------------------------------------- #
                    event = 'Failed to prepare update for max allowed events per device!'
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

# --------------------------------------------------------------------------- #
# FUNCTION: get_max_events_per_device                                         #
#                                                                             #
# Get value for maximum number of OVOC alarm events that can be received that #
# trigger the retrieval of the network capture from a CPE device. If the      #
# events received counter is less than this value, then the network traffic   #
# capture is restarted on the CPE device.                                     #
#                                                                             #
# Parameters:                                                                 #
#     logger - File handler for storing logged actions                        #
#     log_id - Unique identifier for this devices log entries                 #
#                                                                             #
# Return:                                                                     #
#    max_events_per_device - Integer value in the range (1 - 50)              #
# --------------------------------------------------------------------------- #
def get_max_events_per_device(logger, log_id):
    """Get value for max allowed events per device that trigger a pull of the network capture from a CPE device."""

    max_retries = 5

    stored_max_events_per_device = config.max_events_per_device

    event = 'Retrieved stored max allowed OVOC alarm trigger events per device value: [{}]'.format(stored_max_events_per_device)
    logger.info('{} - {}'.format(log_id, event))

    # ---------------------------------------------------- #
    # Allow modification of stored REST API retry attempts #
    # ---------------------------------------------------- #
    print('')
    print(':=============================================================================:')
    print(': Maximum number of OVOC alarm events that can be received per device that    :')
    print(': trigger the retrieval of the network capture from a CPE device.             :')
    print(':                                                                             :')
    print(': If the triggering events counter is less than the value, then the network   :')
    print(': traffic capture is restarted on the CPE device.                             :')
    print(':                                                                             :')
    print(': NOTE: Currently triggering on "Connection Lost" alarm.                      :')
    print(':                                                                             :')
    print(': NOTE: Entered value should be in the range (1 - 50)                         :')
    print(':=============================================================================:')
    got_max_events_per_device = False
    while not got_max_events_per_device:

        this_max_events_per_device = input('Enter OVOC alarm trigger events per device: (1-50) [{}] '.format(stored_max_events_per_device))
        if this_max_events_per_device == '':
            got_max_events_per_device = True
            max_events_per_device = stored_max_events_per_device
        else:
            try:
                this_max_events_per_device = int(this_max_events_per_device)
                if this_max_events_per_device >= 1 and this_max_events_per_device <= 50:
                    got_max_events_per_device = True
                    max_events_per_device = this_max_events_per_device
                else:
                    event = 'Invalid setting: [{}]. Must be a value in the range (1-50).'.format(this_max_events_per_device)
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {} Try again.\n'.format(event))
                    got_max_events_per_device = False
            except ValueError:
                event = 'Invalid number: [{}]. Must be a value in the range (1-50).'.format(this_max_events_per_device)
                logger.error('{} - {}'.format(log_id, event))
                print('  - ERROR: {} Try again.\n'.format(event))
                got_max_events_per_device = False

    event = 'Set OVOC alarm trigger events per device to: [{}]'.format(max_events_per_device)
    logger.info('{} - {}'.format(log_id, event))
    print('  - INFO: {}'.format(event))

    # ------------------------------------------------------ #
    # Check if updates are necessary to the 'config.py' file #
    # ------------------------------------------------------ #
    if not update_max_events_per_device(logger, log_id, max_events_per_device):
        event = 'Failed to update "config.py" file!'
        logger.warning('{} - {}'.format(log_id, event))
        print('  - WARNING: {} You can continue without saving the value entered.'.format(event))

    return max_events_per_device

# --------------------------------------------------------------------------- #
# FUNCTION: register_devices                                                  #
#                                                                             #
# Send a 'REGISTER' request message to each devices associated OVOC server.   #
# After the OVOC capture script app receives the 'REGISTER' request, it will  #
# add the device to its processing list and create an SNMP alarm forwarding   #
# rule specific for each device so that OVOC will sent 'Connection Lost'      #
# alarms to this CPE capture script. If all is setup properly on the OVOC     #
# capture script, then a '200 OK' message is returned.                        #
#                                                                             #
# If no response is received, then it indicates that either the script is not #
# running, the message is being blocked by a firewall, or the message was     #
# lost during transport.                                                      #
#                                                                             #
# When a response is received, then the 'devices_info' will be updated to let #
# this script know to start the captures for that device. If not, then this   #
# function will try again on the next loop of network message processing.     #
#                                                                             #
# The key 'deviceRegister' will be updated with one of the following values   #
# based on either receiving a '200 OK' or no reponses from the OVOC script:   #
#                                                                             #
#     'not active' - No response received yet from OVOC capture script.       #
#                    (Registration attempts < 'max_reg_attempts' setting)     #
#     'aborted'    - No response received from OVOC capture script.           #
#                    (Registration attempts = 'max_reg_attempts' setting)     #
#     'active'     - OVOC capture script received and responded with '200 OK' #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     max_attempts  - Max registration attempts entered                       #
#     server_socket - Network socket to use for sending request               #
#     devices_info  - Dictionary of targeted devices                          #
#                                                                             #
# Return:                                                                     #
#     devices_info - Modified dictionary containing records for each device   #
#                    that contain all the tasks executed against each device. #
#                    (Mutable dictionary passed by reference)                 #
# --------------------------------------------------------------------------- #
def register_devices(logger, log_id, server_socket, max_attempts, devices_info):
    """Register each device on associated OVOC capture scripts."""

    for device in devices_info['devices']:

        if device['registration'] == 'not active':

            event = 'Registering CPE devices to their associated OVOC capture script'
            logger.info('{} - {}'.format(log_id, event))
            print('{}'.format(event))

            if device['registerAttempts'] == max_attempts:
                device['registration'] = 'aborted'
                device['completed'] = True

                event = 'Device [{}] failed to register to its OVOC capture script!'.format(device['device'])
                logger.critical('{} - {}'.format(log_id, event))
                print('  - CRITICAL: {}'.format(event))

            else:
                # -------------------------------------------------------- #
                # Send REGISTER command to OVOC capture app script to      #
                # trigger it to send a '200 OK' response if it is running. #
                # -------------------------------------------------------- #
                this_request = 'REGISTER {}'.format(device['device'])
                event = 'Registering device [{}] to OVOC capture script on server: [{}]'.format(device['device'], device['ovoc'])
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))
                if send_request(logger, log_id, server_socket, this_request, device['ovoc']):
                    event = 'Sent registration request to OVOC capture script.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('    - INFO: {}'.format(event))

                    # ------------------------------------------------------ #
                    # Save this command request in 'devices_info' dictionary #
                    # ------------------------------------------------------ #
                    device['lastRequest'] = 'REGISTER'
                    device['awaitingResponse'] = True

                else:
                    event = 'Failed to send registration request to OVOC capture script!'
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))
                    device['lastRequest'] = ''

                device['registerAttempts'] += 1

    return

# --------------------------------------------------------------------------- #
# FUNCTION: start_captures                                                    #
#                                                                             #
# Send a 'CAPTURE' request message to each devices associated OVOC server.    #
# When the OVOC capture script receives the 'CAPTURE' request it attempt to   #
# start a 'tcpdump' on the OVOC server for the device submitting the request. #
# Possible response values from the OVOC capture script:                      #
#                                                                             #
#     '200 OK'                  - Successfully started 'tcpdump'              #
#     '404 Not Found'           - Device not registered with OVOC script      #
#     '503 Service Unavailable' - Failed to start 'tcpdump'                   #
#                                                                             #
# When a response is received, then the 'devices_info' will be updated to let #
# this script know about the OVOC status for the 'tcpdump' capture for that   #
# device.                                                                     #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     max_retries   - Max retry attempts allowed                              #
#     server_socket - Network socket to use for sending request               #
#     devices_info  - Dictionary of targeted devices                          #
#                                                                             #
# Return:                                                                     #
#     devices_info - Modified dictionary containing records for each device   #
#                    that contain all the tasks executed against each device. #
#                    (Mutable dictionary passed by reference)                 #
# --------------------------------------------------------------------------- #
def start_captures(logger, log_id, max_retries, server_socket, devices_info):
    """Start CPE captures for each device that is registered with an OVOC capture script."""

    for device in devices_info['devices']:

        if device['registration'] == 'active':

            event = 'Checking if captures need to be started on registered CPE devices'
            logger.debug('{} - {}'.format(log_id, event))

            if device['cpeCapture'] == 'not active' and device['cpeEvent'] == 'not active' and not device['completed']:

                # -------------------------------- #
                # Start capture on this CPE device #
                # -------------------------------- #
                start_capture(logger, log_id, max_retries, device['device'], devices_info)

                if device['cpeCapture'] == 'active':

                    # ------------------------------------------------------- #
                    # Send CAPTURE command to OVOC capture app script to      #
                    # trigger it to start a 'tcpdump' capture on this device. #
                    # ------------------------------------------------------- #
                    this_request = 'CAPTURE {}'.format(device['device'])
                    event = 'Sending message to start capture on OVOC server: [{}]'.format(this_request)
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + {}'.format(event))
                    if send_request(logger, log_id, server_socket, this_request, device['ovoc']):
                        event = 'Sent request to start capture on OVOC server.'
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

                        # ------------------------------------------------------ #
                        # Save this command request in 'devices_info' dictionary #
                        # ------------------------------------------------------ #
                        device['lastRequest'] = 'CAPTURE'
                        device['awaitingResponse'] = True

                    else:
                        event = 'Failed to send request to start capture on OVOC server!'
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))
                        device['lastRequest'] = ''
                else:
                    device['completed'] = True
                    event = 'Failed to start capture on device!'
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))
            else:
                if device['cpeCapture'] == 'not active' and device['cpeEvent'] == 'active':
                    event = 'Starting new capture is not allowed. Currently in a triggered alarm event state.'
                    logger.warning('{} - {}'.format(log_id, event))

    return

# --------------------------------------------------------------------------- #
# FUNCTION: start_capture                                                     #
#                                                                             #
# Start network traffic capture on a specifc CPE device. The capture is       #
# started by sending the appropriate CLI script command to the devices using  #
# a REST API request.                                                         #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     max_retries   - Max retry attempts allowed                              #
#     target_device - CPE device to start network traffic capture on          #
#     devices_info  - Dictionary of targeted devices                          #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def start_capture(logger, log_id, max_retries, target_device, devices_info):
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

            event = 'Starting debug capture on CPE device #{}: [{}]'.format(device_index + 1, target_device)
            logger.info('{} - {}'.format(log_id, event))
            print('{}'.format(event))

            # ---------------------------------- #
            # Start debug capture on this device #
            # ---------------------------------- #
            submitted = False
            attempt = 1
            while attempt <= max_retries and not submitted:

                cli_script = ''

                # ---------------------------------------- #
                # Attempt to start debug capture on device #
                # ---------------------------------------- #
                event = 'Attempting to start debug capture...'
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                # ---------------------------------------------- #
                # Define SNMPv3 user that will later be used for #
                # verifying SNMP connectivity after a Connection #
                # Lost event is triggered from an OVOC server.   #
                # ---------------------------------------------- #
                cli_script += 'configure system\n'
                cli_script += ' no snmp v3-users where username CaptureScript\n'
                cli_script += ' snmp v3-users new\n'
                cli_script += '  user CaptureScript\n'
                cli_script += '  auth-protocol sha-1\n'
                cli_script += '  priv-protocol aes-128\n'
                cli_script += '  auth-key Capture01!\n'
                cli_script += '  priv-key Capture01!\n'
                cli_script += ' exit\n'
                cli_script += 'exit\n'
                cli_script += 'write\n'

                if device['type'] == 'MSBR':

                    # ---------------------------------------------------------- #
                    # Build commands to start capture on defined MSBR interfaces #
                    # ---------------------------------------------------------- #
                    cli_script += 'debug capture data physical stop\n'
                    for interface in device['interfaces']:
                        cli_script += 'debug capture data physical {}\n'.format(interface)
                    cli_script += 'debug capture data physical start\n'

                else:

                    # ------------------------------------------------------------ #
                    # Build commands to start capture on defined GW/SBC interfaces #
                    # ------------------------------------------------------------ #
                    cli_script += 'debug_capture voip physical stop\n'
                    for interface in device['interfaces']:
                        cli_script += 'debug capture voip physical {}\n'.format(interface)
                    cli_script += 'debug_capture voip physical start\n'

                start_capture_task = send_cli_script(logger, log_id, cli_script, target_device, device['username'], device['password'])

                # ---------------------- #
                # Store task information #
                # ---------------------- #
                start_capture_task['task'] = 'Start capture'
                task_timestamp = datetime.now()
                start_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                device['tasks'].append(start_capture_task.copy())

                device_status = start_capture_task['status']
                last_description = start_capture_task['description']

                # --------------- #
                # Display results #
                # --------------- #
                if device_status.lower() == 'success':
                    submitted = True

                attempt += 1

            started = False
            if submitted:
                attempt = 1
                while attempt <= max_retries and not started:
                    # --------------------------------- #
                    # Attempt to verify capture started #
                    # --------------------------------- #
                    event = 'Verifying debug capture started...'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + {}'.format(event))

                    if device['type'] == 'MSBR':
                        cli_script = 'debug capture data physical show\n'
                    else:
                        cli_script = 'debug capture voip physical show\n'

                    verify_started_task = send_cli_script(logger, log_id, cli_script, target_device, device['username'], device['password'])

                    # --------------- #
                    # Display results #
                    # --------------- #
                    if re.search('Debug capture physical is active', verify_started_task['output']):
                        started = True
                        event = 'Debug capture is active.'
                        verify_started_task['description'] = event
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))
                    elif re.search('Debug capture physical is not active', verify_started_task['output']):
                        started = False
                        event = 'Failed to start debug capture on device!'
                        verify_started_task['description'] = event
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))
                    else:
                        event = verify_started_task['description']
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))

                    # ---------------------- #
                    # Store task information #
                    # ---------------------- #
                    verify_started_task['task'] = 'Verify started'
                    task_timestamp = datetime.now()
                    verify_started_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                    device['tasks'].append(verify_started_task.copy())

                    device_status = verify_started_task['status']
                    last_description = verify_started_task['description']

                attempt += 1

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            device['status'] = device_status
            device['description'] = last_description

            if started:
                device['cpeCapture'] = 'active'
                device['severity'] = 'NORMAL'
            else:
                device['cpeCapture'] = 'not active'
                device['severity'] = 'CRITICAL'

            break

        device_index += 1

    if not device_found:
        device['status'] = 'Failure'
        device['severity'] = 'CRITICAL'
        event = 'Device not found in monitored devices list!'
        logger.error('{} - {}'.format(log_id, event))
        print('  + ERROR: {}'.format(event))

    return

# --------------------------------------------------------------------------- #
# FUNCTION: verify_connectivity                                               #
#                                                                             #
# Send different types of network traffic to the device so that it is loogged #
# in the traffic captures. Traffic generated can be ICMP pings, SNMPv3 UDP    #
# packets, and simple TCP connection attempts to port 443. The devices that   #
# are targeted for this traffic are ones that are currently in a triggered    #
# alarm event state.                                                          #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     max_retries   - Max retry attempts allowed                              #
#     server_socket - Network socket to use for sending request               #
#     devices_info  - Dictionary of targeted devices                          #
#                                                                             #
# Return:                                                                     #
#     devices_info - Modified dictionary containing records for each device   #
#                    that contain all the tasks executed against each device. #
#                    (Mutable dictionary passed by reference)                 #
# --------------------------------------------------------------------------- #
def verify_connectivity(logger, log_id, max_retries, server_socket, devices_info):
    """Send ICMP, SNMPv3, and TCP traffic to devices that are have triggered an alarm event."""

    for device in devices_info['devices']:

        if device['registration'] == 'active':

            event = 'Checking for devices with active events to send generated traffic'
            logger.debug('{} - {}'.format(log_id, event))

            if device['cpeCapture'] == 'active' and device['cpeEvent'] == 'active' and not device['completed']:

                # ------------------------------------------------------ #
                # Send VERIFY command to OVOC capture app script. This   #
                # will trigger the script that is running on the OVOC    #
                # server to generate multiple traffic types (ICMP, SNMP, #
                # and TCP) to send to the target device. This will help  #
                # verify whether or not the OVOC server has network      #
                # connectivity to the CPE device.                        #
                # ------------------------------------------------------ #
                this_request = 'VERIFY {}'.format(device['device'])
                event = 'Sending message to verify network communication from OVOC server: [{}]'.format(this_request)
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))
                if send_request(logger, log_id, server_socket, this_request, device['ovoc']):
                    event = 'Sent request to verify network communication from OVOC server.'
                    logger.info('{} - {}'.format(log_id, event))
                    print('    - INFO: {}'.format(event))

                    # ------------------------------------------------------ #
                    # Save this command request in 'devices_info' dictionary #
                    # ------------------------------------------------------ #
                    device['lastRequest'] = 'VERIFY'
                    #device['awaitingResponse'] = True

                else:
                    event = 'Failed to send request to verify network communication from OVOC server!'
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))
                    device['lastRequest'] = ''

                # ----------------------------------------------- #
                # Generate and send ICMP, SNMP, and TCP traffic   #
                # from this server as well to verify network      #
                # connectivity to the CPE. This will give another #
                # point in the network to verify communications.  #
                # ----------------------------------------------- #
                send_traffic(logger, log_id, device['device'], devices_info)

    return

# --------------------------------------------------------------------------- #
# FUNCTION: send_traffic                                                      #
#                                                                             #
# This function sends three types of network traffic to the targeted CPE      #
# device once a Connection Lost event is received. The ICMP traffic and the   #
# SNMPv3 GET requests are sent in parallel. TCP traffic is generated by       #
# sending multiple connection attempts to the CPE on port 22 simulating an    #
# SSH login attempt.                                                          #
#                                                                             #
# This function will wait until all the traffic has been sent to the device   #
# before returning.                                                           #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     target_device - CPE device to start network traffic capture on          #
#     devices_info  - Dictionary of targeted devices                          #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def send_traffic(logger, log_id, target_device, devices_info):
    """Generate ICMP, SNMP, and TCP traffic to send to the target CPE device."""

    # ------------------------------ #
    # Attempts for each traffic type #
    # ------------------------------ #
    attempts = 10

    icmp_description = ''
    snmp_description = ''
    tcp_description = ''

    device_found = False
    device_index = 0
    for device in devices_info['devices']:
        if device['device'] == target_device:

            device_found = True
            event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
            logger.debug('{} - {}'.format(log_id, event))

            event = 'Sending network traffic to CPE device #{}: [{}]'.format(device_index + 1, target_device)
            logger.info('{} - {}'.format(log_id, event))
            print('{}'.format(event))

            # ------------------------------------------------------- #
            # Track information to summarize each devices info record #
            # ------------------------------------------------------- #
            device_status = ''
            device_severity = ''
            description = ''

            # ------------------------------------------------------ #
            # List to hold the objects returned from the calls to    #
            # 'subprocess' below for the ICMP and SNMP traffic. Will #
            # be used to wait for those spawned processes to finish. #
            # ------------------------------------------------------ #
            processes = []

            DEVNULL = open(os.devnull, 'w')

            if config.send_icmp:
                # ------------------------------------------- #
                # Create a dictionary to hold the relevant    #
                # information to return for the current task. #
                # ------------------------------------------- #
                send_icmp_task = {}
                send_icmp_task['task'] = 'Send ICMP (Ping)'
                send_icmp_task['status'] = 'Failure'
                send_icmp_task['output'] = ''
                send_icmp_task['description'] = ''
                task_timestamp = datetime.now()
                send_icmp_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

                # ------------------------------------ #
                # Send ICMP pings to the target device #
                # ------------------------------------ #
                event = 'Sending {} ICMP pings to target CPE device...'.format(attempts)
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                attempt = 1
                while attempt <= attempts:

                    command = 'sleep ' + str(attempt) + '; ping -c 1 ' + target_device
                    event = 'Command: ' + command
                    logger.debug('{} - {}'.format(log_id, event))
                    icmp_process = subprocess.Popen(command, shell=True, stdout=DEVNULL, stderr=DEVNULL)
                    processes.append(icmp_process)

                    attempt += 1

            if config.send_snmp:
                # ------------------------------------------- #
                # Create a dictionary to hold the relevant    #
                # information to return for the current task. #
                # ------------------------------------------- #
                send_snmp_task = {}
                send_snmp_task['task'] = 'Send UDP (SNMPv3)'
                send_snmp_task['status'] = 'Failure'
                send_snmp_task['output'] = ''
                send_snmp_task['description'] = ''
                task_timestamp = datetime.now()
                send_snmp_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

                # ----------------------------------- #
                # Send SNMPv3 request to get system   #
                # description from the target device. #
                # ----------------------------------- #
                event = 'Sending {} SNMPv3 GET requests for sysDescr.0 to target CPE device...'.format(attempts)
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                attempt = 1
                while attempt <= attempts:

                    command = 'sleep ' + str(attempt) + '; snmpget -v 3 -r 0 -n "" -u CaptureScript -a SHA -l authPriv -A Capture01! -X Capture01! -x AES ' + target_device + ' sysDescr.0'
                    event = 'Command: ' + command
                    logger.debug('{} - {}'.format(log_id, event))
                    snmp_process = subprocess.Popen(command, shell=True, stdout=DEVNULL, stderr=DEVNULL)
                    processes.append(snmp_process)

                    attempt += 1

            tcp_failures = 0
            if config.send_tcp:
                # ------------------------------------------- #
                # Create a dictionary to hold the relevant    #
                # information to return for the current task. #
                # ------------------------------------------- #
                send_tcp_task = {}
                send_tcp_task['task'] = 'Send TCP (Port 443)'
                send_tcp_task['status'] = 'Failure'
                send_tcp_task['output'] = ''
                send_tcp_task['description'] = ''
                task_timestamp = datetime.now()
                send_tcp_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

                # ------------------------------------ #
                # Send TCP connection attempts to port #
                # 443 on target device.                #
                # ------------------------------------ #
                event = 'Sending {} TCP connection requests to port 443 on target CPE device...'.format(attempts)
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                attempt = 1
                while attempt <= attempts:

                    # ----------------------------------------------- #
                    # Attempt to connect to port 443 on target device #
                    # ----------------------------------------------- #
                    event = 'Attempting to connect to port 443 on CPE device...'
                    logger.info('{} - {}'.format(log_id, event))
                    #print('  + {}'.format(event))

                    try:
                        socket.setdefaulttimeout(1)
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect((target_device, 443))
                    except Exception as error:
                        tcp_failures += 1
                        if type(error) is list:
                            if len(error) > 1:
                                error = str(error[1])
                            else:
                                error = str(error[0])
                        error = str(error)
                        error = re.sub('\[|\]', '', error)
                        event = 'TCP attempt {} failed: {}.'.format(attempt, error)
                        logger.warning('{} - {}'.format(log_id, event))
                        send_tcp_task['output'] += error + ' '
                    else:
                        event = 'TCP attempt {} SYN ACK received.'.format(attempt)
                        logger.info('{} - {}'.format(log_id, event))
                        send_tcp_task['output'] += event + ' '
                        s.close()

                    attempt += 1

            # -------------------------------------------------------- #
            # Wait for spawned tasks to complete if necessary and get  #
            # their shell status. Status '0' means the spawned process #
            # executed with no errors.                                 #
            # -------------------------------------------------------- #
            results = [p.wait() for p in processes]
            event = 'Results list: {}'.format(results)
            logger.debug('{} - {}'.format(log_id, event))

            device_status = 'Success'

            # ---------------------------------------- #
            # Results 0 to (attempts-1) are associated #
            # with the ICMP pings attempts.            #
            # ---------------------------------------- #
            icmp_failures = 0
            if config.send_icmp:
                begin_icmp_index = 0
                end_icmp_index = attempts

                attempt = 1
                for index in range(begin_icmp_index, end_icmp_index):
                    if len(results) - 1 >= index:
                        if results[index] != 0:
                            icmp_failures += 1
                            event = 'ICMP attempt {} failed.'.format(attempt)
                            logger.warning('{} - {}'.format(log_id, event))
                        else:
                            event = 'ICMP attempt {} received response.'.format(attempt)
                            logger.info('{} - {}'.format(log_id, event))
                        send_icmp_task['output'] += event + ' '
                    else:
                        event = 'Result not found for ICMP request {}'.format(attempt)
                        logger.error('{} - {}'.format(log_id, event))

                    attempt += 1

                if icmp_failures == 0:
                    event = 'Successfully sent all ICMP pings to device.'
                    logger.info('{} - {}'.format(log_id, event))
                    send_icmp_task['status'] = 'Success'
                    print('    - INFO: {}'.format(event))
                else:
                    device_status = 'Failure'
                    event = 'Failed to receive response to {} out of 10 ICMP pings!'.format(icmp_failures)
                    logger.warning('{} - {}'.format(log_id, event))
                    print('    - WARNING: {}'.format(event))
                send_icmp_task['description'] = event
                icmp_description = event
                device['tasks'].append(send_icmp_task.copy())
            else:
                icmp_description = 'Sending ICMP PING requests is disabled.'

            # ----------------------------------------- #
            # Results (attempts) to (attempts*2) are    #
            # associated with the 10 SNMP GET attempts. #
            # ----------------------------------------- #
            snmp_failures = 0
            begin_snmp_index = attempts
            end_snmp_index = attempts * 2
            if not config.send_icmp:
                begin_snmp_index = 0
                end_snmp_index = attempts

            if config.send_snmp:
                attempt = 1
                for index in range(begin_snmp_index, end_snmp_index):
                    if len(results) - 1 >= index:
                        if results[index] != 0:
                            snmp_failures += 1
                            event = 'SNMP attempt {} failed'.format(attempt)
                            logger.warning('{} - {}'.format(log_id, event))
                        else:
                            event = 'SNMP attempt {} received response.'.format(attempt)
                            logger.info('{} - {}'.format(log_id, event))
                        send_snmp_task['output'] += event + ' '
                    else:
                        event = 'Result not found for SNMP request {}'.format(attempt)
                        logger.error('{} - {}'.format(log_id, event))

                    attempt += 1

                if snmp_failures == 0:
                    event = 'Successfully sent all SNMP GET requests to device.'
                    logger.info('{} - {}'.format(log_id, event))
                    send_snmp_task['status'] = 'Success'
                    print('    - INFO: {}'.format(event))
                else:
                    device_status = 'Failure'
                    event = 'Failed to receive response to {} out of 10 SNMP GET requests!'.format(snmp_failures)
                    logger.warning('{} - {}'.format(log_id, event))
                    print('    - WARNING: {}'.format(event))
                send_snmp_task['description'] = event
                snmp_description = event
                device['tasks'].append(send_snmp_task.copy())
            else:
                snmp_description = 'Sending UDP SNMPv3 GET requests is disabled.'

            # ----------------------------------- #
            # Results for TCP connection attempts #
            # ----------------------------------- #
            if config.send_tcp:
                if tcp_failures == 0:
                    event = 'Successfully sent all TCP connection requests to device.'
                    logger.info('{} - {}'.format(log_id, event))
                    send_tcp_task['status'] = 'Success'
                    print('    - INFO: {}'.format(event))
                else:
                    device_status = 'Failure'
                    event = 'Failed to receive response to {} out of 10 TCP connection requests!'.format(tcp_failures)
                    logger.warning('{} - {}'.format(log_id, event))
                    print('    - WARNING: {}'.format(event))
                send_tcp_task['description'] = event
                tcp_description = event
                device['tasks'].append(send_tcp_task.copy())
            else:
                tcp_description = 'Sending TCP connection attempts is disabled.'

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            device['status'] = device_status
            device['description'] = icmp_description + ' ' + snmp_description + ' ' + tcp_description

            if icmp_failures == 0 and snmp_failures == 0 and tcp_failures == 0:
                device['severity'] = 'NORMAL'
            else:
                device['severity'] = 'CRITICAL'

            break

        device_index += 1

    if not device_found:
        device['status'] = 'Failure'
        device['severity'] = 'CRITICAL'
        event = 'Device not found in monitored devices list!'
        logger.error('{} - {}'.format(log_id, event))
        print('  + ERROR: {}'.format(event))

    return

# --------------------------------------------------------------------------- #
# FUNCTION: stop_captures                                                     #
#                                                                             #
# Send CLI script commands to any device with an active triggered alarm event #
# to stop their network captures.                                             #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     max_retries   - Max retry attempts allowed                              #
#     server_socket - Network socket to use for sending request               #
#     devices_info  - Dictionary of targeted devices                          #
#                                                                             #
# Return:                                                                     #
#     devices_info - Modified dictionary containing records for each device   #
#                    that contain all the tasks executed against each device. #
#                    (Mutable dictionary passed by reference)                 #
# --------------------------------------------------------------------------- #
def stop_captures(logger, log_id, max_retries, server_socket, devices_info):
    """Stop CPE captures for each device that has its last request set to 'VERIFY'."""

    for device in devices_info['devices']:

        if device['registration'] == 'active':

            event = 'Checking for devices that need their captures stopped'
            logger.debug('{} - {}'.format(log_id, event))

            if device['cpeCapture'] == 'active' and device['cpeEvent'] == 'active' and not device['completed']:

                # -------------------------- #
                # Stop capture on CPE device #
                # -------------------------- #
                stop_capture(logger, log_id, max_retries, device['device'], devices_info)

    return

# --------------------------------------------------------------------------- #
# FUNCTION: stop_capture                                                      #
#                                                                             #
# Stop network traffic capture on a specifc CPE device. The capture is        #
# stopped by sending the appropriate CLI script command to the devices using  #
# a REST API request.                                                         #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     max_retries   - Max retry attempts allowed                              #
#     target_device - CPE device to start network traffic capture on          #
#     devices_info  - Dictionary of targeted devices                          #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def stop_capture(logger, log_id, max_retries, target_device, devices_info):
    """Stop network traffic capture on specific device in the 'devices' list."""

    device_found = False
    device_index = 0
    for device in devices_info['devices']:
        if device['device'] == target_device:

            device_found = True
            event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
            logger.debug('{} - {}'.format(log_id, event))

            event = 'Stopping network traffic capture on CPE device #{}: [{}]'.format(device_index + 1, target_device)
            logger.info('{} - {}'.format(log_id, event))
            print('{}'.format(event))

            # ------------------------------------------------------- #
            # Track information to summarize each devices info record #
            # ------------------------------------------------------- #
            device_status = ''
            device_severity = ''
            last_description = ''

            # --------------------------------- #
            # Stop debug capture on this device #
            # --------------------------------- #
            submitted = False
            attempt = 1
            while attempt <= max_retries and not submitted:

                cli_script = ''

                # --------------------------------------- #
                # Attempt to stop debug capture on device #
                # --------------------------------------- #
                event = 'Attempting to stop debug capture on CPE device...'
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                # ----------------------------------------------- #
                # Remove SNMPv3 user that is used for verifying   #
                # SNMP connectivity after a Connection Lost event #
                # was received from an OVOC server.               #
                # ----------------------------------------------- #
                cli_script += 'configure system\n'
                cli_script += ' no snmp v3-users where username CaptureScript\n'
                cli_script += 'exit\n'
                cli_script += 'write\n'

                # -------------------------------- #
                # CLI script to stop debug capture #
                # -------------------------------- #
                if device['type'] == 'MSBR':
                    cli_script += 'debug capture data physical stop\n'
                else:
                    cli_script += 'debug capture voip physical stop\n'

                stop_capture_task = send_cli_script(logger, log_id, cli_script, target_device, device['username'], device['password'])

                # ---------------------- #
                # Store task information #
                # ---------------------- #
                stop_capture_task['task'] = 'Stop capture'
                task_timestamp = datetime.now()
                stop_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                device['tasks'].append(stop_capture_task.copy())

                device_status = stop_capture_task['status']
                last_description = stop_capture_task['description']

                # --------------- #
                # Display results #
                # --------------- #
                event = stop_capture_task['description']
                if device_status.lower() == 'success':
                    submitted = True
                    logger.info('{} - {}'.format(log_id, event))
                    print('    - INFO: {}'.format(event))
                else:
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))

                attempt += 1

            stopped = False
            if submitted:
                attempt = 1
                while attempt <= max_retries and not stopped:
                    # --------------------------------- #
                    # Attempt to verify capture stopped #
                    # --------------------------------- #
                    event = 'Verifying debug capture stopped...'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + {}'.format(event))

                    if device['type'] == 'MSBR':
                        cli_script = 'debug capture data physical show\n'
                    else:
                        cli_script = 'debug capture voip physical show\n'

                    verify_stopped_task = send_cli_script(logger, log_id, cli_script, target_device, device['username'], device['password'])

                    # --------------- #
                    # Display results #
                    # --------------- #
                    if re.search('Debug capture physical is not active', verify_stopped_task['output']):
                        stopped = True
                        event = verify_stopped_task['description']
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

                        event = 'Debug capture is not active.'
                        verify_stopped_task['description'] = event
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))
                    elif re.search('Debug capture physical is active', verify_stopped_task['output']):
                        stopped = False
                        event = verify_stopped_task['description']
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

                        event = 'Failed to stop debug capture on device!'
                        verify_stopped_task['description'] = event
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))
                    else:
                        event = verify_stopped_task['description']
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))

                    # ---------------------- #
                    # Store task information #
                    # ---------------------- #
                    verify_stopped_task['task'] = 'Verify stopped'
                    task_timestamp = datetime.now()
                    verify_stopped_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                    device['tasks'].append(verify_stopped_task.copy())

                    device_status = verify_stopped_task['status']
                    last_description = verify_stopped_task['description']

                attempt += 1

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            device['status'] = device_status
            device['description'] = last_description

            if stopped:
                device['cpeCapture'] = 'not active'
                device['severity'] = 'NORMAL'
            else:
                device['cpeCapture'] = 'active'
                device['severity'] = 'MAJOR'

        device_index += 1

    if not device_found:
        device['status'] = 'Failure'
        device['severity'] = 'CRITICAL'
        event = 'Device not found in monitored devices list!'
        logger.error('{} - {}'.format(log_id, event))
        print('  + ERROR: {}'.format(event))

    return

# --------------------------------------------------------------------------- #
# FUNCTION: retrieve_captures                                                 #
#                                                                             #
# Retrieve the debug capture file on any device that is currently in a        #
# triggered alarm event state with stopped captures.                          #
#                                                                             #
# Send a 'STOP' request message to each devices associated OVOC server. When  #
# the OVOC capture script receives the 'STOP' request it attempts to stop the #
# currently running 'tcpdump' on the OVOC server for the device submitting    #
# the request. Possible response values from the OVOC capture script:         #
#                                                                             #
#     '200 OK'                  - Successfully started 'tcpdump'              #
#     '404 Not Found'           - Device not registered with OVOC script      #
#     '503 Service Unavailable' - Failed to start 'tcpdump'                   #
#                                                                             #
# When a response is received, then the 'devices_info' will be updated to let #
# this script know about the OVOC status for the 'tcpdump' capture for that   #
# device.                                                                     #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     max_retries   - Max retry attempts allowed                              #
#     server_socket - Network socket to use for sending request               #
#     devices_info  - Dictionary of targeted devices                          #
#                                                                             #
# Return:                                                                     #
#     devices_info - Modified dictionary containing records for each device   #
#                    that contain all the tasks executed against each device. #
#                    (Mutable dictionary passed by reference)                 #
# --------------------------------------------------------------------------- #
def retrieve_captures(logger, log_id, max_retries, server_socket, devices_info):
    """Stop CPE captures for each device that has its last request set to 'VERIFY'."""

    for device in devices_info['devices']:

        if device['registration'] == 'active':

            event = 'Checking for devices that need their captures retrieved'
            logger.debug('{} - {}'.format(log_id, event))

            if device['cpeCapture'] == 'not active' and device['cpeEvent'] == 'active' and not device['completed']:

                # ------------------------------------- #
                # Retrieve capture file from CPE device #
                # ------------------------------------- #
                retrieve_capture(logger, log_id, max_retries, device['device'], devices_info)

                if device['status'] == 'Success':

                    device['cpeEvent'] = 'not active'

                    # ------------------------------------------------------ #
                    # Send STOP command to OVOC capture app script to        #
                    # trigger it to stop a 'tcpdump' capture on this device. #
                    # ------------------------------------------------------ #
                    this_request = 'STOP {} {}'.format(device['device'], device['lastCapture'])
                    event = 'Sending message to stop capture on OVOC server: [{}]'.format(this_request)
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + {}'.format(event))
                    if send_request(logger, log_id, server_socket, this_request, device['ovoc']):
                        event = 'Sent request to stop capture on OVOC server.'
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

                        # ------------------------------------------------------ #
                        # Save this command request in 'devices_info' dictionary #
                        # ------------------------------------------------------ #
                        device['lastRequest'] = 'STOP'
                        device['awaitingResponse'] = True
                        #time.sleep(3)

                else:
                    event = 'Failed to retrieve capture file from device!'
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))
                    device['lastRequest'] = ''

    return

# --------------------------------------------------------------------------- #
# FUNCTION: retrieve_capture                                                  #
#                                                                             #
# Use the paramiko library to get the PCAP file stored locally on the device  #
# using the SFTP protocol.                                                    #
#                                                                             #
# Parameters:                                                                 #
#     logger        - File handler for storing logged actions                 #
#     log_id        - Unique identifier for this devices log entries          #
#     max_retries   - Max retry attempts allowed                              #
#     target_device - CPE device to start network traffic capture on          #
#     devices_info  - Dictionary of targeted devices                          #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def retrieve_capture(logger, log_id, max_retries, target_device, devices_info):
    """Retrieve the locally stored PCAP file on the device."""

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

            retrieved = False

            if device['cpeCapture'].lower() == 'not active':

                event = 'Retrieving network traffic capture from CPE device #{}: [{}]'.format(device_index + 1, target_device)
                logger.info('{} - {}'.format(log_id, event))
                print('{}'.format(event))

                # ------------------------------------------------- #
                # Retrieve debug capture file stored on this device #
                # ------------------------------------------------- #
                attempt = 1
                while attempt <= max_retries and not retrieved:

                    # -------------------------------------------------- #
                    # Attempt to retrieve debug capture file from device #
                    # -------------------------------------------------- #
                    event = 'Attempting to retrieve debug capture file from CPE device...'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + {}'.format(event))

                    retrieve_capture_task = {}
                    retrieve_capture_task['task'] = 'Retrieve capture'
                    retrieve_capture_task['status'] = 'Failure'
                    retrieve_capture_task['description'] = 'Failed to retrieve capture from device!'
                    task_timestamp = datetime.now()
                    retrieve_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                    retrieve_capture_task['filename'] = ''

                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    #ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
                    try:
                        ssh.connect(target_device, username=device['username'], password=device['password'])
                        event = 'Connected to device'
                        logger.info('{} - {}'.format(log_id, event))
                        sftp = ssh.open_sftp()
                        event = 'Successfully started SFTP session'
                        logger.info('{} - {}'.format(log_id, event))
                    except Exception as err:
                        event = '{}'.format(err)
                        logger.error('{} - {}'.format(log_id, event))
                        print('  - ERROR: {}'.format(event))

                    else:
                        # -------------------------------- #
                        # Create filename to store pcap as #
                        # -------------------------------- #
                        file_timestamp = datetime.now()
                        file_timestamp = file_timestamp.strftime('%Y-%m-%dT%H.%M.%S.%f%z')
                        filename = 'device_{}_{}.pcap'.format(target_device, file_timestamp)
                        filename = re.sub(':', '.', filename)
                        filename = 'CPE_' + filename
                        retrieve_capture_task['filename'] = filename

                        remote_file = '/debug-capture/debug-capture-data.pcap'
                        local_file = './captures/' + filename

                        try:
                            sftp.get(remote_file, local_file, prefetch=False)
                        except Exception as err:
                            event = '{}'.format(err)
                            logger.error('{} - {}'.format(log_id, event))
                            retrieve_capture_task['status'] = 'Failure'
                            retrieve_capture_task['description'] = event
                            print('  - ERROR: {}'.format(event))
                        else:
                            retrieve_capture_task['status'] = 'Success'
                            event = 'Stored capture from device as file: [{}]'.format(filename)
                            retrieve_capture_task['description'] = event
                            retrieved = True

                    # ---------------------- #
                    # Store task information #
                    # ---------------------- #
                    device['tasks'].append(retrieve_capture_task.copy())
                    device_status = retrieve_capture_task['status']
                    logger.debug('{} - {}'.format(log_id, device_status))
                    last_description = retrieve_capture_task['description']

                    attempt += 1

                    # --------------- #
                    # Display results #
                    # --------------- #
                    event = retrieve_capture_task['description']
                    if device_status.lower() == 'success':
                        submitted = True
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))
                    else:
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))

            else:
                device_status = 'Failure'
                last_description = 'Debug capture is still active on CPE device!'

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            device['status'] = device_status
            device['description'] = last_description
            device['lastCapture'] = filename

            if retrieved:
                device['severity'] = 'NORMAL'
            else:
                device['severity'] = 'CRITICAL'

        device_index += 1

    if not device_found:
        device['status'] = 'Failure'
        device['severity'] = 'CRITICAL'
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

    # ------------------------------------------------- #
    # Match any response beginning with a response code #
    # followed by response text.                        #
    # ------------------------------------------------- #
    elif re.search('^\d+\s+\w+', message):

        # ------------ #
        # Set defaults #
        # ------------ #
        msg_info['type'] = 'response'
        msg_info['response'] = ''
        msg_info['device'] = ''
        msg_info['request'] = ''

        event = 'Matched OVOC capture script response'
        logger.debug('{} - {}'.format(log_id, event))

        #match = re.search('(\d+\s+[\w\s]+)\s+(.*)$', message)
        match = re.search('(\d+\s+[\w\s]+)\s+([0-9a-fA-F:.]+)\s+(.*)$', message)
        if match:
            msg_info['response'] = match.group(1).strip()
            msg_info['device'] = match.group(2).strip()
            msg_info['request'] = match.group(3).strip()

            event = 'Parsed request [{}] response [{}] for device: [{}]'.format(msg_info['request'], msg_info['response'], msg_info['device'])
            logger.debug('{} - {}'.format(log_id, event))

    event = 'Parsed message elements:\n{}'.format(json.dumps(msg_info, indent=4))
    logger.debug('{} - {}'.format(log_id, event))

    return msg_info

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
    print('===============================================================================')
    print(' Version: {:10s}            CPE CAPTURE APP'.format(version))
    print('===============================================================================')

    # ----------------------------- #
    # Prepare captures subdirectory #
    # ----------------------------- #
    pathlib.Path('./captures').mkdir(parents=True, exist_ok=True)

    # ------------------------------------------- #
    # Check if rotation of log files is necessary #
    # ------------------------------------------- #
    if rotate_logs(logger, log_id, config.app_log_file, config.app_max_log_file_size, config.app_archived_files):
        event = 'Rotation of log files completed'
        logger.info('{} - {}'.format(log_id, event))

    # ------------------------------------ #
    # Get parameters via interactive input #
    # ------------------------------------ #
    try:
        max_reg_attempts = get_max_reg_attempts(logger, log_id)
        devices_info = get_cpe_devices(logger, log_id)
        listen_port = get_listen_port(logger, log_id)
        max_retries = get_max_retries(logger, log_id)
        max_events_per_device = get_max_events_per_device(logger, log_id)

    except KeyboardInterrupt:
        print('')
        print('=================')
        print('>>>> Aborted <<<<')
        print('=================')
        exit(1)

    begin_time = time.time()
    begin_timestamp = datetime.now()
    print('')
    print('===============================================================================')
    print('                         CPE NETWORK TRAFFIC CAPTURES')
    #print(' Version: {:10s}     CPE NETWORK TRAFFIC CAPTURES'.format(version))
    print('===============================================================================')
    print('Start Time:'.format(begin_timestamp))
    print('-------------------------------------------------------------------------------')

    # --------------------------------------------- #
    # Prepare UDP socket to listen for OVOC alarms  #
    # and to send and receive command requests and  #
    # responses to complimentary OVOC capture app   #
    # scripts that manage the CPE's being captured. #
    # --------------------------------------------- #
    buffer_size = 16384

    # -------------------------------------- #
    # Create a UDP datagram socket to listen #
    # on any IPv4 interface on this host.    #
    # -------------------------------------- #
    try:
        server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
        server_socket.bind(('0.0.0.0', listen_port))

        # ------------------------------ #
        # Set UDP socket as non-blocking #
        # ------------------------------ #
        server_socket.setblocking(0)

    except Exception as err:
        event = '{}'.format(err)
        logger.error('{} - {}'.format(log_id, event))
        print('  - ERROR: {}'.format(event))

    else:

        # ---------------------------------------------------------- #
        # Send REGISTER requests for each device to their associated #
        # OVOC capture app scripts and give ample time for responses #
        # to come back before reading the messaging socket.          #
        # ---------------------------------------------------------- #
        register_devices(logger, log_id, server_socket, max_reg_attempts, devices_info)
        time.sleep(2)

        # ------------------------------------------------ #
        # For debugging - Output 'devices_info' dictionary #
        # ------------------------------------------------ #
        event = 'Devices Info:\n{}'.format(secure_json_dump(logger, log_id, devices_info, ['password']))
        logger.debug('{} - {}'.format(log_id, event))

        # ------------------------------------------------------------- #
        # Start listening for OVOC alarms or command responses if there #
        # are any devices that have not completed their registration    #
        # or have not completed their traffic captures.                 #
        # ------------------------------------------------------------- #
        devices_not_registered = False
        devices_not_completed = False
        for device in devices_info['devices']:
            if device['registration'].lower() == 'not active':
                devices_not_registered = True
            if device['completed'] == False:
                devices_not_completed = True

        event = 'Listening for OVOC alarms and script messaging on UDP port: [{}]'.format(listen_port)
        logger.info('{} - {}'.format(log_id, event))
        print('{}'.format(event))

        while (devices_not_registered or devices_not_completed):

            more_messages = True
            while more_messages:

                try:
                    bytes_address_pair = server_socket.recvfrom(buffer_size)
                except socket.error:
                    more_messages = False
                else:

                    # --------------------------- #
                    # Get message from UDP socket #
                    # --------------------------- #
                    message = bytes_address_pair[0]
                    event = 'UDP message: [{}]'.format(message)
                    logger.debug('{} - {}'.format(log_id, event))

                    ovoc_address = bytes_address_pair[1]
                    event = 'UDP message from: [{}]'.format(ovoc_address)
                    logger.info('{} - {}'.format(log_id, event))

                    # ---------------------- #
                    # Parse received message #
                    # ---------------------- #
                    msg_info = {}
                    msg_info['type'] = 'unknown'
                    try:
                        decoded_message = message.decode('utf-8')
                        msg_info = parse_message(logger, log_id, decoded_message)
                    except Exception as err:
                        event = 'Error decoding UDP message: {}'.format(err)
                        logger.error('{} - {}'.format(log_id, event))
                    else:

                        # ------------------- #
                        # Process OVOC alarms #
                        # ------------------- #
                        if msg_info['type'] == 'alarm':

                            # ------------------------------------------- #
                            # Trigger retrieval of CPE network capture on #
                            # 'Connection Lost' OVOC alarm.               #
                            # ------------------------------------------- #
                            if msg_info['alarmType'].lower() == 'connection alarm' and \
                               msg_info['alarm'].lower() == 'connection lost':

                                device_with_alarm = msg_info['ipAddress']

                                event = 'Received [{}] alarm from OVOC associated with device: [{}]'.format(msg_info['alarm'], device_with_alarm)
                                logger.info('{} - {}'.format(log_id, event))
                                print('{}'.format(event))

                                for device in devices_info['devices']:
                                    if device['device'] == device_with_alarm:

                                        # ------------------------ #
                                        # Increment events counter #
                                        # ------------------------ #
                                        device['events'] += 1
                                        event = 'Incrementing events counter to: [{}]'.format(device['events'])
                                        logger.info('{} - {}'.format(log_id, event))

                                        device['cpeEvent'] = 'active'

                                        break

                            else:

                                # ------------------------------------------------- #
                                # Just log any other OVOC alarms that don't trigger #
                                # the stop and retrieval of network captures.       #
                                # ------------------------------------------------- #
                                device_with_alarm = msg_info['ipAddress']
                                event = 'Received [{}] alarm from OVOC associated with device: [{}]'.format(msg_info['alarm'], device_with_alarm)
                                logger.info('{} - {}'.format(log_id, event))
                                print('  + {}'.format(event))

                        # ------------------------------------------------- #
                        # Process OVOC capture app script command responses #
                        # ------------------------------------------------- #
                        elif msg_info['type'] == 'response':

                            # ------------------------------------------------------------- #
                            # Update the state accordingly in the 'devices_info' dictionary #
                            # ------------------------------------------------------------- #
                            this_response = msg_info['response']
                            target_device = msg_info['device']
                            for_request = msg_info['request']

                            for device in devices_info['devices']:
                                if device['device'] == target_device:

                                    event = 'Received request [{}] response [{}] from OVOC associated with device: [{}]'.format(for_request, this_response, target_device)
                                    logger.info('{} - {}'.format(log_id, event))
                                    print('  + {}'.format(event))

                                    # ------------------------------------------------------- #
                                    # Save this command response in 'devices_info' dictionary #
                                    # ------------------------------------------------------- #
                                    device['lastResponse'] = this_response

                                    if this_response != '100 Trying':
                                        device['awaitingResponse'] = False

                                    # -------------------------------------------------- #
                                    # If a '200 OK' response to a 'REGISTER' request has #
                                    # been received, then OVOC successfully setup the    #
                                    # device and is ready to start captures.             #
                                    # -------------------------------------------------- #
                                    if this_response == '200 OK' and for_request == 'REGISTER':
                                        device['registration'] = 'active'

                                    # ------------------------------------------------- #
                                    # If a '200 OK' response to a 'CAPTURE' request has #
                                    # been received, then OVOC successfully started the #
                                    # 'tcpdump' for the device.                         #
                                    # ------------------------------------------------- #
                                    if this_response == '200 OK' and for_request == 'CAPTURE':
                                        device['ovocCapture'] = 'active'

                                    # ---------------------------------------------- #
                                    # If a '200 OK' response to a 'STOP' request has #
                                    # been received, then OVOC successfully stopped  #
                                    # the 'tcpdump' for the device.                  #
                                    # ---------------------------------------------- #
                                    if this_response == '200 OK' and for_request == 'STOP':

                                        # --------------------------------- #
                                        # Update OVOC tcpdump capture state #
                                        # --------------------------------- #
                                        device['ovocCapture'] = 'not active'

                                        if device['events'] == max_events_per_device:
                                            device['completed'] = True

                                    break

                        else:
                            event = 'Received unknown message to process! Check logs for details.'
                            logger.warning('{} - {}'.format(log_id, event))
                            print('  + WARNING: {}'.format(event))

                        # ------------------------------------------------ #
                        # For debugging - Output 'devices_info' dictionary #
                        # ------------------------------------------------ #
                        #event = 'Devices Info:\n{}'.format(secure_json_dump(logger, log_id, devices_info, ['password']))
                        #logger.debug('{} - {}'.format(log_id, event))

            event = 'Processed all buffered messages'
            logger.debug('{} - {}'.format(log_id, event))

            # ---------------------------------------------------------- #
            # Check if any devices need to have their REGISTER requests  #
            # sent to their associated OVOC capture app scripts.         #
            # ---------------------------------------------------------- #
            register_devices(logger, log_id, server_socket, max_reg_attempts, devices_info)

            # ------------------------------------------------------------------- #
            # Check if any registered devices need to have their captures started #
            # ------------------------------------------------------------------- #
            start_captures(logger, log_id, max_retries, server_socket, devices_info)

            # --------------------------------------------------------------- #
            # Check if any registered devices are in an triggered event state #
            # and should have generated network traffic sent to them.         #
            # --------------------------------------------------------------- #
            verify_connectivity(logger, log_id, max_retries, server_socket, devices_info)

            # ------------------------------------------------------------------- #
            # Check if any registered devices need to have their captures stopped #
            # ------------------------------------------------------------------- #
            stop_captures(logger, log_id, max_retries, server_socket, devices_info)

            # ------------------------------------------------------------ #
            # Check if any registered devices that are stopped should have #
            # their locally stored debug capture files retrieved.          #
            # ------------------------------------------------------------ #
            retrieve_captures(logger, log_id, max_retries, server_socket, devices_info)

            # ---------------------------------------------------------- #
            # Continue listening for OVOC alarms or script messaging if  #
            # there are any devices that have not completed their        #
            # registration or have not completed their traffic captures. #
            # ---------------------------------------------------------- #
            not_registered_cnt = 0
            not_completed_cnt = 0
            devices_not_registered = False
            devices_not_completed = False
            awaiting_response_cnt = 0
            for device in devices_info['devices']:
                if device['registration'].lower() == 'not active':
                    devices_not_registered = True
                    not_registered_cnt += 1
                if device['completed'] == False:
                    devices_not_completed = True
                    not_completed_cnt += 1
                if device['awaitingResponse'] == True:
                    awaiting_response_cnt += 1

            #sleep_time = 5
            #if not_registered_cnt == 0 and not_completed_cnt > 0:
            #    sleep_time = 30
            #if awaiting_response_cnt > 0 and not_completed_cnt > 0:
            if awaiting_response_cnt > 0:
                sleep_time = 3
            else:
                sleep_time = 30

            # ------------------------------------------- #
            # Check if rotation of log files is necessary #
            # ------------------------------------------- #
            if rotate_logs(logger, log_id, config.app_log_file, config.app_max_log_file_size, config.app_archived_files):
                event = 'Rotation of log files completed'
                logger.info('{} - {}'.format(log_id, event))

            # ---------------------------------------------- #
            # Sleep before next loop to receive UDP messages #
            # ---------------------------------------------- #
            time.sleep(sleep_time)

        event = 'All devices have completed'
        logger.info('{} - {}'.format(log_id, event))
        print('  - INFO: {}'.format(event))

    event = 'Finished'
    logger.info('{} - {}'.format(log_id, event))
    print('{}'.format(event))

    # ------------------------------------------------ #
    # For debugging - Output 'devices_info' dictionary #
    # ------------------------------------------------ #
    event = 'Devices Info:\n{}'.format(secure_json_dump(logger, log_id, devices_info, ['password']))
    logger.debug('{} - {}'.format(log_id, event))

    # ---------------------- #
    # Create CSV output file #
    # ---------------------- #
    #csv_records = create_csv_file(logger, log_id, output_csv, begin_timestamp, devices_info)

    end_time = time.time()
    end_timestamp = datetime.now()
    print('')
    print('===============================================================================')
    print('                              PROCESSING SUMMARY')
    print('===============================================================================')
    print('Completed:'.format(end_timestamp))
    print('Total Duration: {0:.3f} seconds'.format(end_time - begin_time))
    print('')

if __name__ == "__main__":
   main(sys.argv[1:])


