"""Syncrhonize network captures on OVOC server and CPE device."""

"""
-------------------------------------------------------------------------------
Script: capture.py

Description:

This script starts network traffic captures on both an OVOC server and a
targeted audiocodes CPE device and terminates the captures after receiving an
SNMP alarm. The SNMP alarm is the trigger to stop the captures.

The goal is the attempt catch an event where SNMP traffic is not being seen
on the CPE device and it loses management connectivity with the OVOC server.

The IP address and login credentials of the target CPE device is entered as
interactive input to this script. The commands to start/stop the debug capture
on the audiocodes CPE is sent via REST API to the device. The network capture
on the OVOC server is performed by issuing system calls to the 'tcpdump' app.
-------------------------------------------------------------------------------
"""

import io
import os
import sys
import re
import csv
import json
import logging
import requests
import base64
import getopt
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
from zipfile import ZipFile

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
    """Verify that the address entered is either a valide IPv4, IPv6, or FQDN."""

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
# Update the list of CPE devices stored in the config.py file if necessary.   #
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
    """Update list of CPE devices in config.py file."""

    status = False
    do_update = False

    # --------------------------------------------------------- #
    # Read in current configuration file contents. The contents #
    # will be modified by REGEX substitutions and written back  #
    # the the config.py file if differences exist.              #
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
            # the list of CPE devices stored in the config.py file.                #
            # The results of the 'compares iterations below will be > 0 if lists   #
            # of dictionaries are different.                                       #
            #                                                                      #
            # 'cpe_devices' is list of dictionaries from interactive entries.      #
            # 'config.cpe_devices' is list of dictionaries from config.py file.    #
            # -------------------------------------------------------------------- #
            compare_entered_to_stored = [i for i in cpe_devices if i not in config.cpe_devices]
            compare_stored_to_entered = [i for i in config.cpe_devices if i not in cpe_devices]
            if len(compare_entered_to_stored) != 0 or len(compare_stored_to_entered) != 0:
                result = re.sub("(?s)cpe_devices = (\[.*?\])", "cpe_devices = " + json.dumps(cpe_devices, indent=4), config_file_contents, 1)

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
# username and password. Any stored CPE devices in the config.py file will be #
# presented first and allowed to be modified if necessary.                    #
#                                                                             #
# Parameters:                                                                 #
#     logger - File handler for storing logged actions                        #
#     log_id - Unique identifier for this devices log entries                 #
#                                                                             #
# Return:                                                                     #
#    cpe_devices - List of dictionaries containing the CPE devices to target. #
# --------------------------------------------------------------------------- #
def get_cpe_devices(logger, log_id):
    """Build list of CPE devices to target for network captures."""
    
    cpe_devices = []

    # ---------------------------------------------------------- #
    # This list holds the contents of the created list of CPE    #
    # devices ('cpe_devices') without the 'password' field being #
    # present. This list will be stored in the config.py file    #
    # for future executions of this script.                      #
    # ---------------------------------------------------------- #
    config_cpe_devices = []

    print('')
    print(':=============================================================:')
    print(': Create a set of CPE devices to target for network traffic   :')
    print(': captures. Enter the required information to use when        :')
    print(': connecting to each device.                                  :')
    print(':                                                             :')
    print(': NOTE: Previously entered CPE devices are recalled and can   :')
    print(': be modified if desired.                                     :')
    print(':                                                             :')
    print(': To remove a previously stored device, type "delete" for the :')
    print(': CPE device address.                                         :')
    print(':=============================================================:')
    if len(config.cpe_devices) == 0:
        event = 'No stored CPE devices were found.'
        logger.info('{} - {}'.format(log_id, event))
        print('  - INFO: {}'.format(event))

    stored_device_index = 0
    used_device_index = 0
    while len(cpe_devices) == 0:

        # ------------------------------------------------------------ #
        # Get existing CPE devices previously stored in config.py file #
        # ------------------------------------------------------------ #
        while stored_device_index < len(config.cpe_devices):

            stored_device_address = config.cpe_devices[stored_device_index]['address']
            stored_device_user = config.cpe_devices[stored_device_index]['username']

            event = 'Retrieved stored CPE device address: [{}]'.format(stored_device_address)
            logger.info('{} - {}'.format(log_id, event))
            event = 'Retrieved stored CPE device username: [{}]'.format(stored_device_user)
            logger.info('{} - {}'.format(log_id, event))

            # ------------------------------------------- #
            # Allow modification of stored device address #
            # ------------------------------------------- #
            skip_device = False
            got_address = False
            while not got_address:
                this_device_address = str(input('CPE device #{} IP address or FQDN: (delete) [{}] '.format(used_device_index + 1, stored_device_address))).strip()
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
                    print('  - INFO: {}'.format(event))

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
                        event = 'Must enter an valid IPv4/IPv6 address or FQDN to be use for accessing the CPE device.'
                        logger.error('{} - {}'.format(log_id, event))
                        print('  - ERROR: {}'.format(event))

            if not skip_device:
                # -------------------------------------------- #
                # Allow modification of stored device username #
                # -------------------------------------------- #
                this_device_user = str(input('CPE device #{} username: [{}] '.format(used_device_index + 1, stored_device_user))).strip()
                event = 'Entered CPE device username: [{}]'.format(this_device_user)
                logger.info('{} - {}'.format(log_id, event))
                if this_device_user == '':
                    this_device_user = stored_device_user
                    event = 'Using existing CPE device username: [{}]'.format(this_device_user)
                    logger.info('{} - {}'.format(log_id, event))
                else:
                    event = 'Modifying CPE device username to: [{}]'.format(this_device_user)
                    logger.info('{} - {}'.format(log_id, event))

                # ------------------------------ #
                # Get password for stored device #
                # ------------------------------ #
                this_device_pass = ''
                while this_device_pass == '':
                    this_device_pass = getpass(prompt='CPE device #{} password: '.format(used_device_index + 1))
                    this_device_pass_verify = getpass(prompt='Retype password: ')
                    if this_device_pass != this_device_pass_verify:
                        event = 'Entered passwords do NOT match.'
                        logger.error('{} - {}'.format(log_id, event))
                        print('  - ERROR: {} Try again.'.format(event))
                        this_device_pass = ''
                    else:
                        if this_device_pass == '':
                            event = 'Passwords can not be empty!'
                            logger.error('{} - {}'.format(log_id, event))
                            print('  - ERROR: {} Try again.'.format(event))
                        else:
                            event = 'Entered passwords match!'
                            logger.info('{} - {}'.format(log_id, event))
                            print('  - INFO: {}'.format(event))

                used_device_index += 1

                # ------------------------ #
                # Create CPE device record #
                # ------------------------ #
                cpe_devices.append({})
                device_index = len(cpe_devices) - 1
                cpe_devices[device_index]['address'] = this_device_address
                cpe_devices[device_index]['username'] = this_device_user
                cpe_devices[device_index]['password'] = this_device_pass

                # ----------------------------------------------------- #
                # Create OVOC server record to store in config.py file. #
                # Do not store the OVOC password since it would be      #
                # stored in plain text.                                 #
                # ----------------------------------------------------- #
                config_cpe_devices.append({})
                device_index = len(cpe_devices) - 1
                config_cpe_devices[device_index]['address'] = this_device_address
                config_cpe_devices[device_index]['username'] = this_device_user

            stored_device_index += 1

        # ------------------------------ #
        # Option to add more CPE devices #
        # ------------------------------ #
        if len(cpe_devices) != 0:
            print('')
            reply = str(input('Add another targeted CPE device: (y/n) [n] ')).lower().strip()
            if reply == '':
                reply = 'n'
        else:
            reply = 'y'

        while reply[0] == 'y':

            this_device_address = ''
            while this_device_address == '':
                this_device_address = str(input('CPE device #{} IP address or FQDN: '.format(used_device_index + 1))).strip()
                event = 'Entered CPE device: [{}]'.format(this_device_address)
                logger.info('{} - {}'.format(log_id, event))
                # ------------------------------------------------------ #
                # Validate entered address is either IPv4, IPv6, or FQDN #
                # ------------------------------------------------------ #
                valid_address = validate_address(this_device_address)
                if not valid_address:
                    event = 'Must enter an valid IPv4/IPv6 address or FQDN to be use for accessing the CPE device.'
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))
                    this_device_address = ''

            event = 'Set new CPE device address to: [{}]'.format(this_device_address)
            logger.info('{} - {}'.format(log_id, event))

            this_device_user = ''
            while this_device_user == '':
                this_device_user = str(input('CPE device #{} username: '.format(used_device_index + 1))).strip()
                event = 'Entered CPE device username: [{}]'.format(this_device_address)
                logger.info('{} - {}'.format(log_id, event))
                if this_device_user == '':
                    event = 'Must enter a username to be used for accessing an account on the CPE device.'
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {}'.format(event))

            event = 'Set new CPE device username to: [{}]'.format(this_device_user)
            logger.info('{} - {}'.format(log_id, event))

            this_device_pass = ''
            while this_device_pass == '':
                this_device_pass = getpass(prompt='CPE device #{} password: '.format(used_device_index + 1))
                this_device_pass_verify = getpass(prompt='Retype password: ')
                if this_device_pass != this_device_pass_verify:
                    event = 'Entered passwords to NOT match.'
                    logger.error('{} - {}'.format(log_id, event))
                    print('  - ERROR: {} Try again.'.format(event))
                    this_device_pass = ''
                else:
                    if this_device_pass == '':
                        event = 'Passwords can not be empty!'
                        logger.error('{} - {}'.format(log_id, event))
                        print('  - ERROR: {} Try again.'.format(event))
                    else:
                        event = 'Entered passwords match!'
                        logger.info('{} - {}'.format(log_id, event))
                        print('  - INFO: {}'.format(event))

            event = 'Set CPE device password.'
            logger.info('{} - {}'.format(log_id, event))

            # ------------------------ #
            # Create CPE device record #
            # ------------------------ #
            cpe_devices.append({})
            device_index = len(cpe_devices) - 1
            cpe_devices[device_index]['address'] = this_device_address
            cpe_devices[device_index]['username'] = this_device_user
            cpe_devices[device_index]['password'] = this_device_pass

            # ---------------------------------------------------- #
            # Create OVOC server record to store in config.py file #
            # ---------------------------------------------------- #
            config_cpe_devices.append({})
            device_index = len(cpe_devices) - 1
            config_cpe_devices[device_index]['address'] = this_device_address
            config_cpe_devices[device_index]['username'] = this_device_user

            used_device_index += 1

            print('')
            reply = str(input('Add another targeted CPE device: (y/n) [n] ')).lower().strip()

        if len(cpe_devices) == 0:
            event = 'Must enter at least one CPE device to target for the network traffic capture.'
            logger.error('{} - {}'.format(log_id, event))
            print('  - ERROR: {} Try again.'.format(event))

    event = 'Set targeted CPE devices:\n{}'.format(json.dumps(config_cpe_devices, indent=4))
    logger.debug('{} - {}'.format(log_id, event))

    # ------------------------------------------------ #
    # Check if updates are necessary to config.py file #
    # ------------------------------------------------ #
    if not update_cpe_devices(logger, log_id, config_cpe_devices):
        event = 'Failed to update CPE devices in "config.py" file!'
        logger.warning('{} - {}'.format(log_id, event))
        print('  - WARNING: {} You can continue without saving the values entered.'.format(event))

    return cpe_devices

# --------------------------------------------------------------------------- #
# FUNCTION: update_listen_port                                                #
#                                                                             #
# Update the value stored in the config.py file if necessary that defines the #
# UDP port this script will listen on for forwarded SYSLOG format alarms.     #
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
    """Update UDP port to listen on that is stored in config.py file."""

    status = False
    do_update = False

    # --------------------------------------------------------- #
    # Read in current configuration file contents. The contents #
    # will be modified by REGEX substitutions and written back  #
    # the the config.py file if differences exist.              #
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
    """Get UPD port number to listen on for forwarded alarms from and OVOC server."""

    listen_port = 1025

    stored_listen_port = config.listen_port

    event = 'Retrieved stored UDP listen port: [{}]'.format(stored_listen_port)
    logger.info('{} - {}'.format(log_id, event))

    # -------------------------------------------- #
    # Allow modification of stored UDP listen port #
    # -------------------------------------------- #
    print('')
    print(':============================================================:')
    print(': UDP port to listen on for incoming alarms forwarded by an  :')
    print(': OVOC server. Alarms are expected to be in SYSLOG format.   :')
    print(':                                                            :')
    print(': NOTE: Entered port should be in the range (1025 - 65535)   :')
    print(':============================================================:')
    got_listen_port = False
    while not got_listen_port:

        this_listen_port = input('Enter UPD port to listen on: (1025-65535) [{}] '.format(stored_listen_port))
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

    # ------------------------------------------------ #
    # Check if updates are necessary to config.py file #
    # ------------------------------------------------ #
    if not update_listen_port(logger, log_id, listen_port):
        event = 'Failed to update "config.py" file!'
        logger.warning('{} - {}'.format(log_id, event))
        print('  - WARNING: {} You can continue without saving the value entered.'.format(event))

    return listen_port

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
# FUNCTION: start_captures                                                    #
#                                                                             #
# Start network traffic captures on all CPE devices. The captures are started #
# by sending the "debug capture" CLI script commands to the devices using a   #
# REST API request.                                                           #
#                                                                             #
# Parameters:                                                                 #
#     logger   - File handler for storing logged actions                      #
#     log_id   - Unique identifier for this devices log entries               #
#     devices  - List of entered CPE devices to start traffic captures on     #
#                                                                             #
# Return:                                                                     #
#    devices_info - Dictionary containing a record for each device that       #
#                   contains all the tasks executed against that device.      #
# --------------------------------------------------------------------------- #
def start_captures(logger, log_id, devices):
    """Start network traffic captures on all devices in the 'devices' list."""

    print('')
    print('Starting network traffic captures on {} devices...'.format(len(devices)))

    # -------------------------------------------- #
    # Create a list that will contain dictionaries #
    # to hold the relevant information associated  #
    # with each devices attempted tasks.           #
    # -------------------------------------------- #
    devices_info = {}
    devices_info['devices'] = []

    index = 0
    while index < len(devices):

        this_device_address = ''
        this_device_username = ''
        this_device_password = ''

        for key in devices[index]:
            if key == 'address':
                this_device_address = devices[index][key]
            if key == 'username':
                this_device_username = devices[index][key]
            if key == 'password':
                this_device_password = devices[index][key]

        if this_device_address != '' and this_device_username != '' and this_device_password != '':

            # ------------------------------------------------------- #
            # Track information to summarize each devices info record #
            # ------------------------------------------------------- #
            device_status = ''
            device_severity = ''
            last_description = ''

            # ------------------------------------------------ #
            # Add device record for each device being targeted #
            # ------------------------------------------------ #
            devices_info['devices'].append({})
            device_index = len(devices_info['devices']) - 1
            devices_info['devices'][device_index]['device'] = this_device_address
            devices_info['devices'][device_index]['tasks'] = []

            # ----------------------------------------------------- #
            # Default the state to 'not active' to indicate the     #
            # device is currently not performing a network capture. #
            # ---------------------------------------------------- #
            devices_info['devices'][device_index]['state'] = 'not active'

            # ------------------------------------------------ #
            # Default the number of alarm events seen for this #
            # device to 0. Each device will restart the        #
            # capture after receiving an alarm from OVOC.      #
            # ------------------------------------------------ #
            devices_info['devices'][device_index]['events'] = 0

            # ---------------------------------- #
            # Start debug capture on this device #
            # ---------------------------------- #
            submitted = False
            attempt = 1
            while attempt <= config.max_retries and not submitted:

                # ---------------------------------------- #
                # Attempt to start debug capture on device #
                # ---------------------------------------- #
                event = 'Attempting to start debug capture on CPE device #{}: [{}]'.format(index + 1, this_device_address)
                logger.info('{} - {}'.format(log_id, event))
                print('  + INFO: {}'.format(event))

                cli_script = """
debug capture data physical stop
debug capture data physical eth-wan
debug capture data physical start
                """
                start_capture_task = send_cli_script(logger, log_id, cli_script, this_device_address, this_device_username, this_device_password)

                # ---------------------- #
                # Store task information #
                # ---------------------- #
                start_capture_task['task'] = 'Start capture'
                task_timestamp = datetime.now()
                start_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                devices_info['devices'][device_index]['tasks'].append(start_capture_task.copy())

                device_status = start_capture_task['status']
                last_description = start_capture_task['description']

                # --------------- #
                # Display results #
                # --------------- #
                event = start_capture_task['description']
                if device_status.lower() == 'success':
                    submitted = True
                    logger.info('{} - {}'.format(log_id, event))
                    print('    - INFO: {}'.format(event))
                else:
                    logger.error('{} - {}'.format(log_id, event))
                    print('    - ERROR: {}'.format(event))

                attempt += 1

            started = False
            if submitted:
                attempt = 1
                while attempt <= config.max_retries and not started:
                    # --------------------------------- #
                    # Attempt to verify capture started #
                    # --------------------------------- #
                    event = 'Verifying debug capture started...'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + INFO: {}'.format(event))

                    cli_script = """
debug capture data physical show
                    """
                    verify_started_task = send_cli_script(logger, log_id, cli_script, this_device_address, this_device_username, this_device_password)

                    # --------------- #
                    # Display results #
                    # --------------- #
                    if re.search('Debug capture physical is active', verify_started_task['output']):
                        started = True
                        event = verify_started_task['description']
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

                        event = 'Debug capture is active.'
                        verify_started_task['description'] = event
                        logger.info('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))
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
                    devices_info['devices'][device_index]['tasks'].append(verify_started_task.copy())

                    device_status = verify_started_task['status']
                    last_description = verify_started_task['description']

                    attempt += 1

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            devices_info['devices'][device_index]['status'] = device_status
            devices_info['devices'][device_index]['description'] = last_description

            if not started:
                devices_info['devices'][device_index]['severity'] = 'CRITICAL'
            else:
                devices_info['devices'][device_index]['state'] = 'active'
                devices_info['devices'][device_index]['severity'] = 'NORMAL'

        index += 1

    return devices_info

# --------------------------------------------------------------------------- #
# FUNCTION: stop_capture                                                      #
#                                                                             #
# Stop network traffic captures on a specifc CPE device. The captures are     #
# stopped by sending the appropriate CLI script command to the devices using  #
# a REST API request.                                                         #
#                                                                             #
# Parameters:                                                                 #
#     logger   - File handler for storing logged actions                      #
#     log_id   - Unique identifier for this devices log entries               #
#     device   - CPE device to stop network traffic capture on                #
#     devices  - List of target CPE devices                                   #
#     devices_info - Dictionary of tasks attempted by devices                 #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def stop_capture(logger, log_id, device, devices, devices_info):
    """Stop network traffic capture on specific device in the 'devices' list."""

    device_found = False
    index = 0
    for this_device in devices:
        if this_device['address'] == device:

            device_found = True
            this_device_address = this_device['address']
            this_device_username = this_device['username']
            this_device_password = this_device['password']

            print('Stopping network traffic capture on CPE device #{}: [{}]'.format(index + 1, this_device_address))

            # ------------------------------------------------------- #
            # Track information to summarize each devices info record #
            # ------------------------------------------------------- #
            device_status = ''
            device_severity = ''
            last_description = ''

            # ---------------------------------------------------- #
            # Get index in 'devices_info' of device being targeted #
            # ---------------------------------------------------- #
            got_device_index = False
            device_index = 0
            while device_index < len(devices_info['devices']) and not got_device_index:
                if devices_info['devices'][device_index]['device'] == device:
                    event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
                    logger.debug('{} - {}'.format(log_id, event))
                    got_device_index = True

            # --------------------------------- #
            # Stop debug capture on this device #
            # --------------------------------- #
            submitted = False
            attempt = 1
            while attempt <= config.max_retries and not submitted:

                # --------------------------------------- #
                # Attempt to stop debug capture on device #
                # --------------------------------------- #
                event = 'Attempting to stop debug capture on CPE device...'
                logger.info('{} - {}'.format(log_id, event))
                print('  + INFO: {}'.format(event))

                cli_script = """
debug capture data physical stop
                """
                stop_capture_task = send_cli_script(logger, log_id, cli_script, this_device_address, this_device_username, this_device_password)

                # ---------------------- #
                # Store task information #
                # ---------------------- #
                stop_capture_task['task'] = 'Stop capture'
                task_timestamp = datetime.now()
                stop_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                if got_device_index:
                    devices_info['devices'][device_index]['tasks'].append(stop_capture_task.copy())

                    device_status = stop_capture_task['status']
                    last_description = stop_capture_task['description']
                else:
                    event = 'Did not find device in previously tracked devices!'
                    logger.warning('{} - {}'.format(log_id, event))

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
                while attempt <= config.max_retries and not stopped:
                    # --------------------------------- #
                    # Attempt to verify capture stopped #
                    # --------------------------------- #
                    event = 'Verifying debug capture stopped...'
                    logger.info('{} - {}'.format(log_id, event))
                    print('  + INFO: {}'.format(event))

                    cli_script = """
debug capture data physical show
                    """
                    verify_stopped_task = send_cli_script(logger, log_id, cli_script, this_device_address, this_device_username, this_device_password)

                    # --------------- #
                    # Display results #
                    # --------------- #
                    if re.search('Debug capture physical is not active', verify_stopped_task['output']):
                        stopped = True
                        event = verify_stopped_task['description']
                        logger.error('{} - {}'.format(log_id, event))
                        print('    - INFO: {}'.format(event))

                        event = 'Debug capture is not active.'
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
                    if got_device_index:
                        devices_info['devices'][device_index]['tasks'].append(verify_stopped_task.copy())

                        device_status = verify_stopped_task['status']
                        last_description = verify_stopped_task['description']
                    else:
                        event = 'Did not find device in previously tracked devices!'
                        logger.warning('{} - {}'.format(log_id, event))

                    attempt += 1

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            if got_device_index:
                devices_info['devices'][device_index]['status'] = device_status
                devices_info['devices'][device_index]['description'] = last_description

                if not stopped:
                    devices_info['devices'][device_index]['severity'] = 'MAJOR'
                else:
                    devices_info['devices'][device_index]['state'] = 'not active'
                    devices_info['devices'][device_index]['severity'] = 'NORMAL'
            else:
                event = 'Did not find device in previously tracked devices!'
                logger.warning('{} - {}'.format(log_id, event))

        index += 1

    if not device_found:
        event = 'Device not found in monitored devices list!'
        logger.error('{} - {}'.format(log_id, event))
        print('  + ERROR: {}'.format(event))

    return devices_info

# --------------------------------------------------------------------------- #
# FUNCTION: retrieve_capture                                                  #
#                                                                             #
# Use the paramiko library to get the PCAP file stored locally on the device  #
# using the SFTP protocol.                                                    #
#                                                                             #
# Parameters:                                                                 #
#     logger   - File handler for storing logged actions                      #
#     log_id   - Unique identifier for this devices log entries               #
#     device   - CPE device to stop network traffic capture on                #
#     devices  - List of target CPE devices                                   #
#     devices_info - Dictionary of tasks attempted by devices                 #
#                                                                             #
# Return:                                                                     #
#    devices_info - Modified dictionary containing a record for each device   #
#                   that contains all the tasks executed against that device. #
# --------------------------------------------------------------------------- #
def retrieve_capture(logger, log_id, device, devices, devices_info):
    """Retrieve the locally stored PCAP file on the device."""

    device_found = False
    index = 0
    for this_device in devices:
        if this_device['address'] == device:

            device_found = True
            this_device_address = this_device['address']
            this_device_username = this_device['username']
            this_device_password = this_device['password']

            print('Retrieving network traffic capture from CPE device #{}: [{}]'.format(index + 1, this_device_address))

            # ------------------------------------------------------- #
            # Track information to summarize each devices info record #
            # ------------------------------------------------------- #
            device_status = ''
            device_severity = ''
            last_description = ''

            # ---------------------------------------------------- #
            # Get index in 'devices_info' of device being targeted #
            # ---------------------------------------------------- #
            got_device_index = False
            device_index = 0
            while device_index < len(devices_info['devices']) and not got_device_index:
                if devices_info['devices'][device_index]['device'] == device:
                    event = 'Found device in devices information dictionary at index: [{}]'.format(device_index)
                    logger.debug('{} - {}'.format(log_id, event))
                    got_device_index = True

            # ------------------------------------------------- #
            # Retrieve debug capture file stored on this device #
            # ------------------------------------------------- #
            retrieved = False
            attempt = 1
            while attempt <= config.max_retries and not retrieved:

                # -------------------------------------------------- #
                # Attempt to retrieve debug capture file from device #
                # -------------------------------------------------- #
                event = 'Attempting to retrieve debug capture file from CPE device...'
                logger.info('{} - {}'.format(log_id, event))
                print('  + INFO: {}'.format(event))

                retrieve_capture_task = {}
                retrieve_capture_task['task'] = 'Retrieve capture'
                task_timestamp = datetime.now()
                retrieve_capture_task['timestamp'] = task_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

                ssh = paramiko.SSHClient()
                #ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
                try:
                    ssh.connect(this_device_address, username=this_device_username, password=this_device_password)
                    event = 'Connected to device'
                    logger.info('{} - {}'.format(log_id, event))
                    sftp = ssh.open_sftp()
                    event = 'Successfully started SFTP session'
                    logger.info('{} - {}'.format(log_id, event))
                except Exception as err:
                    event = '{}'.format(err)
                    logger.error('{} - {}'.format(log_id, event))
                    print("  - Error: {}".format(event))

                else:
                    # -------------------------------- #
                    # Create filename to store pcap as #
                    # -------------------------------- #
                    file_timestamp = datetime.now()
                    file_timestamp = file_timestamp.strftime('%Y-%m-%dT%H.%M.%S.%f%z')
                    filename = 'device_{}_{}.pcap'.format(this_device_address, file_timestamp)
                    filename = re.sub(':', '.', filename)

                    remote_file = '/debug-capture/debug-capture-data.pcap'
                    local_file = './captures/' + filename

                    try:
                        sftp.get(remote_file, local_file, prefetch=False)
                    except Exception as err:
                        event = '{}'.format(err)
                        logger.error('{} - {}'.format(log_id, event))
                        retrieve_capture_task['status'] = 'Failure'
                        #retrieve_capture_task['description'] = 'Failed to retrieve capture from device!'
                        retrieve_capture_task['description'] = event
                        print("  - Error: {}".format(event))
                    else:
                        retrieve_capture_task['status'] = 'Success'
                        retrieve_capture_task['description'] = 'Stored capture from device as file: [{}]'.format(filename)
                        retrieved = True

                    # ---------------------- #
                    # Store task information #
                    # ---------------------- #
                    devices_info['devices'][device_index]['tasks'].append(retrieve_capture_task.copy())
                    if got_device_index:
                        device_status = retrieve_capture_task['status']
                        last_description = retrieve_capture_task['description']
                    else:
                        event = 'Did not find device in previously tracked devices!'
                        logger.warning('{} - {}'.format(log_id, event))

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

            # -------------------------------------- #
            # Store task information at device level #
            # -------------------------------------- #
            if got_device_index:
                devices_info['devices'][device_index]['status'] = device_status
                devices_info['devices'][device_index]['description'] = last_description

                if not retrieved:
                    devices_info['devices'][device_index]['severity'] = 'CRITICAL'
                else:
                    devices_info['devices'][device_index]['severity'] = 'NORMAL'
            else:
                event = 'Did not find device in previously tracked devices!'
                logger.warning('{} - {}'.format(log_id, event))

        index += 1

    if not device_found:
        event = 'Device not found in monitored devices list!'
        logger.error('{} - {}'.format(log_id, event))
        print('  + ERROR: {}'.format(event))

    return devices_info

# --------------------------------------------------------------------------- #
# FUNCTION: process_message                                                   #
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
def process_message(logger, log_id, message):
    """Parse the elements of a message and add to a dictionary."""

    event = 'Received Message:\n{}'.format(message)
    logger.debug('{} - {}'.format(log_id, event))

    msg_info = {}

    if re.search('New Alarm -', message):
        msg_info['type'] = 'alarm'

        event = 'Matched OVOC alarm'
        logger.debug('{} - {}'.format(log_id, event))

        #msg_items = message.split(',')
        #if len(msg_items) > 0:
        #    msg_info['timestamp'] = msg_items[0]
        #    msg_info['alarm'] = msg_items[1].split(' - ')[1]

        #match = re.search('<\d+>(.*?)\s*:\s*(New Alarm)\s*-\s*(.*?),\s*(.*)\s*(Source):(.*?),\s*(Description):(.*?),\s*(Device Name):(.*?),\s*(Tenant):(.*?),\s*(Region):(.*?),\s*(IP Address):(.*?),\s*(Device Type):(.*?),\s*(Device Serial):(.*?),\s*(Device Description):(.*)\\x\d+', message)

        match = re.search('<\d+>(.*?)\s*:\s*New Alarm\s*-\s*(.*?),\s*(.*)\s*Source:(.*?),\s*Description:(.*?),\s*Device Name:(.*?),\s*Tenant:(.*?),\s*Region:(.*?),\s*IP Address:(.*?),\s*Device Type:(.*?),\s*Device Serial:(.*?),\s*Device Description:(.*)\x00', message)

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
    print("{}".format(event))

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
            print("  - Error: {}".format(event))

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

    # ----------------------------- #
    # Prepare captures subdirectory #
    # ----------------------------- #
    pathlib.Path('./captures').mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Initialize devices information dictionary. The dictionary be built #
    # with the following structure:                                      #
    # {                                                                  #
    #     "devices": [                                                   #
    #         {                                                          #
    #             "device": "<device ip address>",                       #
    #             "status": "Success|Failure",                           #
    #             "description": "<some description>",                   #
    #             "severity": "NORMAL|MINOR|MAJOR|CRITICAL",             #
    #             "tasks": [                                             #
    #                 {                                                  #
    #                     "task": "<task name>"                          #
    #                     "timestamp": "%Y-%m-%dT%H:%M:%S:%f%z",         #
    #                     "status": "Success|Failure",                   #
    #                     "statusCode": <http response status code>,     #
    #                     "output": "<CLI script execution>",            #
    #                     "description": "<CLI script load status>",     #
    #                 },                                                 #
    #                 ...                                                #
    #                 <Next Task>                                        #
    #             ]                                                      #
    #         },                                                         #
    #         ...                                                        #
    #         <Next Device>                                              #
    #     ]                                                              #
    # }                                                                  #
    # ------------------------------------------------------------------ #
    devices_info = {}

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
        cpe_devices = get_cpe_devices(logger, log_id)
        listen_port = get_listen_port(logger, log_id)
        max_retries = config.max_retries
        max_events_per_device = config.max_events_per_device

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
    print('===============================================================================')
    print('Start Time :', begin_timestamp)
    print('-------------------------------------------------------------------------------')

    # ----------------------------------------- #
    # Start captures on all defined CPE devices #
    # ----------------------------------------- #
    devices_info = start_captures(logger, log_id, cpe_devices)

    # ------------------------------------------ #
    # For debugging - Output returned 'job_info' #
    # dictionary containing all tasks in job.    #
    # ------------------------------------------ #
    event = 'Devices Info:\n{}'.format(json.dumps(devices_info, indent=4))
    logger.debug('{} - {}'.format(log_id, event))

    # ------------------------------------------ #
    # Start UDP server to listen for OVOC alarms #
    # and other inter-process messages. Messages #
    # can be sent back and forth from other      #
    # scripts to exchange status updates and     #
    # health checks.                             #
    # ------------------------------------------ #
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
        print("  - Error: {}".format(event))

    else:

        success_cnt = 0
        active_devices = 0
        events_remaining = 0
        for device in devices_info['devices']:
            if device['state'].lower() == 'active':
                active_devices += 1
            if device['status'].lower() == 'success':
                success_cnt += 1

        if active_devices > 0:
            event = 'Listening for OVOC alarms and other messages on UDP port: [{}]'.format(listen_port)
            logger.info('{} - {}'.format(log_id, event))
            print('{}'.format(event))

        while (active_devices > 0):

            bytes_address_pair = udp_server_socket.recvfrom(buffer_size)
            message = bytes_address_pair[0]
            address = bytes_address_pair[1]

            # ------------------------ #
            # Process received message #
            # ------------------------ #
            msg_info = process_message(logger, log_id, message.decode('utf-8'))

            clientMsg = "Message from Client: {}".format(message)
            clientIP  = "Client IP Address: {}".format(address[0])

            print(clientMsg)
            print(clientIP)

            #device_with_alarm = '192.168.200.218'

            # -------------------------- #
            # Stop capture on CPE device #
            # -------------------------- #
            #devices_info = stop_capture(logger, log_id, device_with_alarm, cpe_devices, devices_info)

            # ------------------------------------- #
            # Retrieve capture file from CPE device #
            # ------------------------------------- #
            #devices_info = retrieve_capture(logger, log_id, device_with_alarm, cpe_devices, devices_info)

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
    end_timestamp = datetime.now()
    print('')
    print('===============================================================================')
    print('                              PROCESSING SUMMARY')
    print('===============================================================================')
    print('Completed:', end_timestamp)
    print('Total Duration: {0:.3f} seconds'.format(end_time - begin_time))
    print('')

if __name__ == "__main__":
   main(sys.argv[1:])


