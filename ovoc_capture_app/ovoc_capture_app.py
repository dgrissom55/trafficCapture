"""OVOC APP: Syncrhonize network captures between OVOC server and CPE device."""

"""
-------------------------------------------------------------------------------
Script: ovoc_capture_app.py

Description:

This script starts a UDP listener server on an OVOC server and waits for
command messages from a 'cpe_capture_app.py' script. The commands received
tell this script to trigger a 'tcpdump' application filtering on a specific
CPE device.

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
and stopped using UDP signalled commands from the 'cpe_capture_app.py'
script. Commands are sent to this script to the 'listen_port' defined for in
this scripts 'config.py' file.

On the OVOC servers, the network captures are performed by issuing system
calls to the 'tcpdump' app. To start a capture on an OVOC server, this script
receives a 'CAPTURE' command sent from the CPE controller app to inform this
OVOC server of which CPE traffic should be filtered and captured using
'tcpdump'. This OVOC capture app script responds with a 'TRYING' when setting
up the tcpdump, and an 'OK' when the tcpdump process is running. The response
will be 'FAIL' if the capture fails to be started. The captures
are stopped on this OVOC server after the CPE controller app script
'cpe_capture_app.py' receives the 'Connection Lost' SNMP alarm. That CPE app
script will send a 'STOP' command to the appropriate OVOC server app that 
will trigger this script to kill the tcpdump process for that CPE device.
The following messages are exchanged:


  CPE script                                 This script
       |                                           |
       |-------- CAPTURE <device address> -------->|
       |                                           |
       |<-------- TRYING <device address> ---------|
       |                                           |
       |<------- OK | FAIL <device address> -------|
       |                                           |
       |---- STOP <device address> <filename> ---->|
       |                                           |
       |<-------- TRYING <device address> ---------|
       |                                           |
       |<------- OK | FAIL <device address> -------|
       |                                           |

This script tracks capture states, all tasks, and other information for each
targeted CPE device. The 'devices_info' dictionary is created to track each
devices information. The following is an example of what is tracked:

 {
     "devices": [
         {
             "device": "<device ip address>",
             "status": "Success|Failure",
             "state": "active|not active",
             "description": "<some description>",
             "lastCapture": "<last stopped capture filename>",
             "lastRequest": "<some command request>",
             "lastResponse": "<some command response>",
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
    print('Log directory [{}] can not be created!'.format(config.storage_dir))
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
# FUNCTION: send_cmd_response                                                 #
#                                                                             #
# Send a command response to a CPE capture app script.                        #
#                                                                             #
# Parameters:                                                                 #
#     logger     - File handler for storing logged actions                    #
#     log_id     - Unique identifier for this devices log entries             #
#     udp_socket - UDP socket object currenly bound to                        #
#     response   - Command message response sent to CPE capture app script    #
#     address    - Address of CPE capture app to send response to             #
#                                                                             #
# Return:                                                                     #
#    status - Boolean: 'True' for success, 'False' for failure                #
# --------------------------------------------------------------------------- #
def send_cmd_response(logger, log_id, udp_socket, response, address):
    """Send a command response to a CPE capture app script."""

    status = False

    # -------------------------------------------------- #
    # Send a command response on the UDP datagram socket #
    # -------------------------------------------------- #
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
# FUNCTION: update_listen_port                                                #
#                                                                             #
# Update the value stored in the 'config.py' file if necessary that defines   #
# the UDP port this script will listen on CPE capture app command requests.   #
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
# Get UDP port to listen on when waiting for CPE capture app command requests. #
#                                                                              #
# Parameters:                                                                  #
#     logger - File handler for storing logged actions                         #
#     log_id - Unique identifier for this devices log entries                  #
#                                                                              #
# Return:                                                                      #
#    listen_port - Integer value in the range (1025 - 65535)                   #
# ---------------------------------------------------------------------------- #
def get_listen_port(logger, log_id):
    """Get UPD port number to listen on for CPE capture app command requests."""

    listen_port = 1025

    stored_listen_port = config.listen_port

    event = 'Retrieved stored UDP listen port: [{}]'.format(stored_listen_port)
    logger.info('{} - {}'.format(log_id, event))

    # -------------------------------------------- #
    # Allow modification of stored UDP listen port #
    # -------------------------------------------- #
    print('')
    print(':============================================================:')
    print(': UDP port to listen on for incoming CPE capture app command :')
    print(': requests.                                                  :')
    print(':                                                            :')
    print(': NOTE: Entered port should be in the range (1025 - 65535)   :')
    print(':============================================================:')
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
# run indefinitely waiting for CPE commands.                                   #
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
    print(':============================================================:')
    print(': Setting to control whether or not shut down this script    :')
    print(': after all active captures have completed. Setting this     :')
    print(': to "y" prevents the script from shutting down and allows   :')
    print(': it to run indefinitely waiting for CPE capture commands.   :')
    print(':============================================================:')
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
    print(':============================================================:')
    print(': Network interface name to use for CPE traffic captures.    :')
    print(':============================================================:')
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
# FUNCTION: start_capture                                                     #
#                                                                             #
# Start network traffic capture on a specifc CPE device. The capture is       #
# started by sending the appropriate shell script command spawn the 'tcpdump' #
# application.                                                                #
#                                                                             #
# Parameters:                                                                 #
#     logger         - File handler for storing logged actions                #
#     log_id         - Unique identifier for this devices log entries         #
#     target_device  - CPE device to start network traffic capture filter on  #
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
    for this_device in devices_info['devices']:
        if this_device['device'] == target_device:

            device_found = True
            event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
            logger.debug('{} - {}'.format(log_id, event))

            this_device_address = this_device['device']

            # ------------------------------------------------------- #
            # Track information to summarize each devices info record #
            # ------------------------------------------------------- #
            device_status = ''
            device_severity = ''
            last_description = ''
            filename = ''

            started = False

            if this_device['state'].lower() == 'not active':

                print('Starting network traffic capture for CPE device #{}: [{}]'.format(device_index + 1, this_device_address))

                # -------------------------------- #
                # Create filename to store pcap as #
                # -------------------------------- #
                file_timestamp = datetime.now()
                file_timestamp = file_timestamp.strftime('%Y-%m-%dT%H.%M.%S.%f%z')
                filename = 'tmp_device_{}_{}.pcap'.format(this_device_address, file_timestamp)
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
                #           STOP command is received from the CPE capture app.          #
                #   -W 3  : Number of files to save before overwriting older files      #
                #   -C 10 : Max file size in MB before creating a new file              #
                #   host  : Target CPE device to filter on                              #
                #                                                                       #
                # Send normal output to /dev/null and echo out the PID number to save   #
                # --------------------------------------------------------------------- #
                capture_cmd = "nohup tcpdump -i {} -w ./captures/{} -W 3 -C 10 host {} > /dev/null 2>&1 & echo $!".format(interface_name, filename, this_device_address)

                pid = os.popen(capture_cmd).read().strip()

                # ------------------------------------------------------------ #
                # Save PID in 'devices_info' dictionary record for this device #
                # ------------------------------------------------------------ #
                devices_info['devices'][device_index]['pid'] = pid

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
                devices_info['devices'][device_index]['tasks'].append(start_capture_task.copy())
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
            devices_info['devices'][device_index]['status'] = device_status
            devices_info['devices'][device_index]['description'] = last_description
            devices_info['devices'][device_index]['tempCapture'] = filename

            if started:
                devices_info['devices'][device_index]['state'] = 'active'
                devices_info['devices'][device_index]['severity'] = 'NORMAL'
            else:
                devices_info['devices'][device_index]['state'] = 'not active'
                devices_info['devices'][device_index]['severity'] = 'CRITICAL'

            break

        device_index += 1

    if not device_found:
        event = 'Device not found in monitored devices list!'
        logger.error('{} - {}'.format(log_id, event))
        print('  + ERROR: {}'.format(event))

    return devices_info

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
#     target_device  - CPE device to stop network traffic capture filter on   #
#     filename       - Capture filename used for the CPE capture app script   #
#     devices_info   - Dictionary of targeted devices                         #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def stop_capture(logger, log_id, target_device, filename, devices_info):
    """Stop network traffic capture on specific device in the 'devices_info' dictionary."""

    device_found = False
    device_index = 0
    for this_device in devices_info['devices']:
        if this_device['device'] == target_device:

            device_found = True
            event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
            logger.debug('{} - {}'.format(log_id, event))

            this_device_address = this_device['device']

            # ------------------------------------------------------- #
            # Track information to summarize each devices info record #
            # ------------------------------------------------------- #
            device_status = ''
            device_severity = ''
            last_description = ''

            stopped = False

            if this_device['state'].lower() == 'active':

                print('Stopping network traffic capture for CPE device #{}: [{}]'.format(device_index + 1, this_device_address))

                # ------------------------------------------ #
                # Attempt to stop tcpdump capture for device #
                # ------------------------------------------ #
                event = 'Attempting to stop tcpdump capture on CPE device...'
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                stop_capture_task = {}
                stop_capture_task['task'] = 'Stop capture'
                stop_capture_task['description'] = 'Failed to stop tcpdump capture for device!'
                task_timestamp = datetime.now()
                stop_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                stop_capture_task['filename'] = filename

                # ----------------------------------------------------------- #
                # Get PID in 'devices_info' dictionary record for this device #
                # ----------------------------------------------------------- #
                pid = devices_info['devices'][device_index]['pid']

                try:
                    os.kill(int(pid), 15)
                except OSError:
                    event = '{}'.format(err)
                    logger.error('{} - {}'.format(log_id, event))
                    stop_capture_task['status'] = 'Failure'
                    stop_capture_task['description'] = event
                    print('  - ERROR: {}'.format(event))
                else:
                    stop_capture_task['status'] = 'Success'
                    event = 'Stopped capture on device as file: [{}]'.format(filename)
                    stop_capture_task['description'] = event
                    stopped = True

                # ---------------------- #
                # Store task information #
                # ---------------------- #
                devices_info['devices'][device_index]['tasks'].append(stop_capture_task.copy())
                device_status = stop_capture_task['status']
                logger.debug('{} - {}'.format(log_id, device_status))
                last_description = stop_capture_task['description']

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

                    rename_capture_task = {}
                    rename_capture_task['status'] = 'Success'
                    rename_capture_task['task'] = 'Rename capture files'
                    rename_capture_task['description'] = 'Successfully renamed capture files to match CPE capture script.'
                    task_timestamp = datetime.now()
                    rename_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                    rename_capture_task['filename'] = filename

                    # -------------------------------------------------------------- #
                    # Get temporary filename used when starting the tcpdump captures #
                    # -------------------------------------------------------------- #
                    path = './captures/'
                    temp_filename = devices_info['devices'][device_index]['tempCapture']

                    # -------------------------------------------------- #
                    # Rename up to 3 pcap files. The '-W 3' parameter on #
                    # the tcdump command in 'start_captures' sets the    #
                    # number of pcap files that are created per device.  #
                    # -------------------------------------------------- #
                    for index in range(0, 2, 1):

                        if os.path.exists(path + temp_filename + str(index)):

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
                            base_name = filename.rstrip('.pcap')
                            local_file = path + base_name + '-' + str(index) + '.pcap'

                            # ------------------------------------------- #
                            # Rename to match CPE capture script filename #
                            # ------------------------------------------- #
                            try:
                                os.rename(path + temp_filename + str(index), local_file)
                            except Exception as err:
                                event = 'Capture file renaming error: {}'.format(err)
                                logger.error('{} - {}'.format(log_id, event))
                                print('    - ERROR: {}'.format(event))
                                rename_capture_task['status'] = 'Failure'
                                rename_capture_task['description'] = event
                                renamed = False
                        else:
                            event = 'Capture file may not exist: [{}]'.format(path + temp_filename + str(index))
                            logger.info('{} - {}'.format(log_id, event))

                    # ---------------------- #
                    # Store task information #
                    # ---------------------- #
                    devices_info['devices'][device_index]['tasks'].append(rename_capture_task.copy())
                    device_status = rename_capture_task['status']
                    logger.debug('{} - {}'.format(log_id, device_status))
                    last_description = rename_capture_task['description']

                    # --------------- #
                    # Display results #
                    # --------------- #
                    event = rename_capture_task['description']
                    if device_status.lower() == 'success':
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))
                    else:
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))

            else:
                device_status = 'Failure'
                last_description = 'Traffic capture is not active for CPE device!'

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            devices_info['devices'][device_index]['status'] = device_status
            devices_info['devices'][device_index]['description'] = last_description
            devices_info['devices'][device_index]['lastCapture'] = filename

            if stopped:
                devices_info['devices'][device_index]['state'] = 'not active'
                if renamed:
                    devices_info['devices'][device_index]['severity'] = 'NORMAL'
                else:
                    devices_info['devices'][device_index]['severity'] = 'MINOR'
                    devices_info['devices'][device_index]['lastCapture'] = devices_info['devices'][device_index]['tempCapture']
            else:
                devices_info['devices'][device_index]['state'] = 'active'
                devices_info['devices'][device_index]['severity'] = 'MAJOR'

            break

        device_index += 1

    if not device_found:
        event = 'Device not found in monitored devices list!'
        logger.error('{} - {}'.format(log_id, event))
        print('  + ERROR: {}'.format(event))

    return devices_info

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

    if re.search('New Alarm -', message):

        # ------------ #
        # Set defaults #
        # ------------ #
        msg_info['type'] = 'alarm'
        msg_info['timestamp'] = ''
        msg_info['alarmType'] = ''
        msg_info['alarmMessage'] = ''
        msg_info['alarmSource'] = ''
        msg_info['alarm'] = ''
        msg_info['deviceName'] = ''
        msg_info['tenant'] = ''
        msg_info['region'] = ''
        msg_info['ipAddress'] = ''
        msg_info['deviceType'] = ''
        msg_info['deviceSerial'] = ''
        msg_info['deviceDescription'] = ''

        event = 'Matched OVOC alarm'
        logger.debug('{} - {}'.format(log_id, event))

        match = re.search('<\d+>(.*?)\s*:\s*New Alarm\s*-\s*(.*?),\s*(.*)\s*Source:(.*?),\s*Description:(.*?),\s*Device Name:(.*?),\s*Tenant:(.*?),\s*Region:(.*?),\s*IP Address:(.*?),\s*Device Type:(.*?),\s*Device Serial:(.*?),\s*Device Description:(.*$)', message)
        if match:
            msg_info['timestamp'] = match.group(1).strip()
            msg_info['alarmType'] = match.group(2).strip()
            msg_info['alarmMessage'] = match.group(3).strip()
            msg_info['alarmSource'] = match.group(4).strip()
            msg_info['alarm'] = match.group(5).strip()
            msg_info['deviceName'] = match.group(6).strip()
            msg_info['tenant'] = match.group(7).strip()
            msg_info['region'] = match.group(8).strip()
            msg_info['ipAddress'] = match.group(9).strip()
            msg_info['deviceType'] = match.group(10).strip()
            msg_info['deviceSerial'] = match.group(11).strip()
            msg_info['deviceDescription'] = match.group(12).strip()

    elif re.search('^CAPTURE', message):

        event = 'Matched CPE capture script request'
        logger.debug('{} - {}'.format(log_id, event))

        # ------------ #
        # Set defaults #
        # ------------ #
        msg_info['type'] = 'request'
        msg_info['request'] = 'CAPTURE'
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
        msg_info['request'] = 'CAPTURE'
        msg_info['device'] = ''
        msg_info['filename'] = ''

        event = 'Matched CPE capture script request'
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
    version = '1.0'

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
            print('Capture directory [./captures] created successfully.')
    except OSError as error:
        print('Capture directory [./captures] can not be created!')
        exit(1)

    # ------------------------------------------------------------------- #
    # When the CPE capture app script sucessfully started a traffic       #
    # capture for a CPE device, it then sends a command request 'CAPTURE' #
    # to this script to start a capture on an OVOC server at the same     #
    # time. A dictionary record is also created to track information on   #
    # the CPE that is being monitored. The following dictionary elements  #
    # are used to track the activity of the CPE devices:                  #
    # {                                                                   #
    #     "devices": [                                                    #
    #         {                                                           #
    #             "device": "<device address>",                           #
    #             "status": "Success|Failure",                            #
    #             "state": "not active",                                  #
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
        # -------------------------------------------------------- #
        # Disabled interactively setting 'listen_port'.            #
        # To enable, switch the comments on the following 2 lines. #
        # -------------------------------------------------------- #
        listen_port = get_listen_port(logger, log_id)
        #listen_port = config.listen_port
        prevent_shutdown = get_prevent_shutdown(logger, log_id)
        interface_name = get_interface_name(logger, log_id)

    except KeyboardInterrupt:
        print('')
        print('=================')
        print('>>>> Aborted <<<<')
        print('=================')
        exit(1)

    begin_time = time.time()
    #begin_timestamp = datetime.now()
    begin_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f%z')
    print('')
    print('===============================================================================')
    print('                         OVOC NETWORK TRAFFIC CAPTURES')
    print('===============================================================================')
    print('Start Time : {}'.format(begin_timestamp))
    print('-------------------------------------------------------------------------------')

    # ------------------------------------------------- #
    # Prepare UDP socket to receive command requests    #
    # and send command responses to complimentary       #
    # CPE capture app scripts that control the triggers #
    # for preforming network traffic captures.          #
    # ------------------------------------------------- #
    buffer_size = 1024

    # -------------------------------------- #
    # Create a UDP datagram socket to listen #
    # on any IPv4 interface on this host.    #
    # -------------------------------------- #
    try:
        udp_server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        udp_server_socket.bind(('0.0.0.0', listen_port))
    except Exception as err:
        event = '{}'.format(err)
        logger.error('{} - {}'.format(log_id, event))
        print('  - ERROR: {}'.format(event))

    else:

        event = 'Listening for command messages on UDP port: [{}]'.format(listen_port)
        logger.info('{} - {}'.format(log_id, event))
        print('{}'.format(event))

        active_captures = 0

        while (len(devices_info['devices']) == 0 or active_captures > 0):

            bytes_address_pair = udp_server_socket.recvfrom(buffer_size)
            message = bytes_address_pair[0]
            from_address = bytes_address_pair[1]

            event = 'UDP message from: [{}]'.format(from_address)
            logger.info('{} - {}'.format(log_id, event))

            # ---------------------- #
            # Parse received message #
            # ---------------------- #
            msg_info = parse_message(logger, log_id, message.decode('utf-8'))

            # ----------------------------------------------- #
            # Process CPE capture app script command requests #
            # ----------------------------------------------- #
            if msg_info['type'] == 'request':

                target_device = msg_info['device']
                event = 'Received [{}] request from CPE script controlling device: [{}]'.format(msg_info['request'], target_device)
                logger.info('{} - {}'.format(log_id, event))
                print('  + {}'.format(event))

                # ---------------------------------------------- #
                # Search for device in 'devices_info' dictionary #
                # ---------------------------------------------- #
                device_found = False
                device_index = -1
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
                    devices_info['devices'][device_index]['tasks'] = []

                    # ----------------------------------------------------- #
                    # Default the state to 'not active' to indicate the     #
                    # device is currently not performing a network capture. #
                    # ---------------------------------------------------- #
                    devices_info['devices'][device_index]['state'] = 'not active'

                    event = 'Created new CPE record for device: [{}]'.format(target_device)
                    logger.info('{} - {}'.format(log_id, event))

                    event = 'Create new device in devices information dictionary at index: [{}]'.format(device_index)
                    logger.debug('{} - {}'.format(log_id, event))

                # ---------------------------------------------------- #
                # If a 'CAPTURE' request has been received, then start #
                # 'tcpdump' capturing for this specific device.        #
                # ---------------------------------------------------- #
                if msg_info['request'] == 'CAPTURE':

                    # ------------------------------------------------------ #
                    # Save this command request in 'devices_info' dictionary #
                    # ------------------------------------------------------ #
                    devices_info['devices'][device_index]['lastRequest'] = 'CAPTURE'

                    # ----------------------------------------------- #
                    # Send TRYING response to CPE capture app script. #
                    # ----------------------------------------------- #
                    this_response = 'TRYING {}'.format(target_device)
                    response_type = 'TRYING'
                    event = 'Sending [TRYING] response for starting capture for device: [{}]'.format(target_device)
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + {}'.format(event))
                    if send_cmd_response(logger, log_id, udp_server_socket, this_response, from_address):
                        event = 'Successfully sent response for starting capture on OVOC server.'
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

                        # ------------------------------------------------------- #
                        # Save this command response in 'devices_info' dictionary #
                        # ------------------------------------------------------- #
                        devices_info['devices'][device_index]['lastResponse'] = response_type

                    else:
                        event = 'Failed to send response for starting capture on OVOC server!'
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))
                        devices_info['devices'][device_index]['lastResponse'] = ''

                    # --------------------------------- #
                    # Start capture for this CPE device #
                    # --------------------------------- #
                    devices_info = start_capture(logger, log_id, target_device, interface_name, devices_info)

                    if devices_info['devices'][device_index]['state'].lower() == 'active':
                        # ------------------------------------------- #
                        # Send OK response to CPE capture app script. #
                        # ------------------------------------------- #
                        this_response = 'OK {}'.format(target_device)
                        response_type = 'OK'
                    else:
                        this_response = 'FAIL {}'.format(target_device)
                        response_type = 'FAIL'

                    event = 'Sending response for starting capture on OVOC server: [{}]'.format(this_response)
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + {}'.format(event))
                    if send_cmd_response(logger, log_id, udp_server_socket, this_response, from_address):
                        event = 'Successfully sent response for starting capture on OVOC server.'
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

                        # ------------------------------------------------------- #
                        # Save this command response in 'devices_info' dictionary #
                        # ------------------------------------------------------- #
                        devices_info['devices'][device_index]['lastResponse'] = response_type

                    else:
                        event = 'Failed to send response for starting capture on OVOC server!'
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))
                        devices_info['devices'][device_index]['lastResponse'] = ''

                # ------------------------------------------------ #
                # If a 'STOP' request has been received, then stop #
                # 'tcpdump' capturing for this specific device.    #
                # ------------------------------------------------ #
                if msg_info['request'] == 'STOP':

                    # ------------------------------------------------------ #
                    # Save this command request in 'devices_info' dictionary #
                    # ------------------------------------------------------ #
                    devices_info['devices'][device_index]['lastRequest'] = 'STOP'

                    # ----------------------------------------------- #
                    # Send TRYING response to CPE capture app script. #
                    # ----------------------------------------------- #
                    this_response = 'TRYING {}'.format(target_device)
                    response_type = 'TRYING'
                    event = 'Sending [TRYING] response for stopping capture for device: [{}]'.format(target_device)
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + {}'.format(event))
                    if send_cmd_response(logger, log_id, udp_server_socket, this_response, from_address):
                        event = 'Successfully sent response for stopping capture on OVOC server.'
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

                        # ------------------------------------------------------- #
                        # Save this command response in 'devices_info' dictionary #
                        # ------------------------------------------------------- #
                        devices_info['devices'][device_index]['lastResponse'] = response_type

                    else:
                        event = 'Failed to send response for stopping capture on OVOC server!'
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))
                        devices_info['devices'][device_index]['lastResponse'] = ''

                    # -------------------------------- #
                    # Stop capture for this CPE device #
                    # -------------------------------- #
                    devices_info = stop_capture(logger, log_id, target_device, msg_info['filename'], devices_info)

                    if devices_info['devices'][device_index]['state'].lower() == 'not active':
                        # ------------------------------------------- #
                        # Send OK response to CPE capture app script. #
                        # ------------------------------------------- #
                        this_response = 'OK {}'.format(target_device)
                        response_type = 'OK'
                    else:
                        this_response = 'FAIL {}'.format(target_device)
                        response_type = 'FAIL'

                    event = 'Sending response for stopping capture on OVOC server: [{}]'.format(this_response)
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + {}'.format(event))
                    if send_cmd_response(logger, log_id, udp_server_socket, this_response, from_address):
                        event = 'Successfully sent response for stopping capture on OVOC server.'
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

                        # ------------------------------------------------------- #
                        # Save this command response in 'devices_info' dictionary #
                        # ------------------------------------------------------- #
                        devices_info['devices'][device_index]['lastResponse'] = response_type

                    else:
                        event = 'Failed to send response for stopping capture on OVOC server!'
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - ERROR: {}'.format(event))
                        devices_info['devices'][device_index]['lastResponse'] = ''

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
                    if device['state'].lower() == 'active':
                        active_captures += 1

            # ------------------------------------------------ #
            # For debugging - Output 'devices_info' dictionary #
            # ------------------------------------------------ #
            event = 'Devices Info:\n{}'.format(json.dumps(devices_info, indent=4))
            logger.debug('{} - {}'.format(log_id, event))

            event = 'Listening for command messages on UDP port: [{}]'.format(listen_port)
            logger.info('{} - {}'.format(log_id, event))
            print('{}'.format(event))

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
    print('===============================================================================')
    print('                              PROCESSING SUMMARY')
    print('===============================================================================')
    print('Completed: '.format(end_timestamp))
    print('Total Duration: {0:.3f} seconds'.format(end_time - begin_time))
    print('')

if __name__ == "__main__":
   main(sys.argv[1:])


