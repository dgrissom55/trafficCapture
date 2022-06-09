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
    if config.app_log_level == 'DEBUG':
        print('  - DEBUG: {}'.format(event))
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
        if config.app_log_level == 'DEBUG':
            print('  - DEBUG: {}'.format(event))

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
            reply = str(input('Add another targeted CPE device: (y/n) ')).lower().strip()
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
            reply = str(input('Add another targeted CPE device: (y/n) ')).lower().strip()

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
    if config.app_log_level == 'DEBUG':
        print('  - DEBUG: {}'.format(event))
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
        if config.app_log_level == 'DEBUG':
            print('  - DEBUG: {}'.format(event))

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
def get_report_level(logger, log_id):
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
# FUNCTION: get_file_id                                                       #
#                                                                             #
# Submit a REST API query to get the ID of a file stored on the OVOC server   #
# acting as a file repository.                                                #
#                                                                             #
# Parameters:                                                                 #
#     logger   - File handler for storing logged actions                      #
#     log_id   - Unique identifier for this devices log entries               #
#     filename - Normalized configuration filename stored on OVOC server      #
#     server   - Address of OVOC server used as file repository               #
#     username - Username for REST API account on OVOC server                 #
#     password - Password for REST API account on OVOC server                 #
#                                                                             #
# Return:                                                                     #
#    task_info - Dictionary containing the following items:                   #
#        status      - String: 'Success' or 'Fail'                            #
#        statusCode  - Integer: REST response status code. (Ex: 200)          #
#        fileId      - Integer: -1 for not found, >= 0 for ID of stored file  #
#        description - String: Description of the task action                 #
# --------------------------------------------------------------------------- #
def get_file_id(logger, log_id, filename, server, username, password):
    """Get file ID of file stored on OVOC file repository."""

    # ------------------------------------------- #
    # Create a dictionary to hold the relevant    #
    # information to return for the current task. #
    # ------------------------------------------- #
    task_info = {}
    task_info['task'] = 'Check for File'
    task_info['status'] = 'Fail'
    task_info['statusCode'] = -1
    task_info['fileId'] = -1
    task_info['description'] = ''

    # ---------------- #
    # Set REST API URL #
    # ---------------- #
    url = "https://" + server + "/ovoc/v1/swManager/files?detail=1&filter=(name='" + filename + "')"

    event = 'Method [GET]" - Request URL: {}'.format(url)
    logger.info('{} - {}'.format(log_id, event))

    # -------------------------------- #
    # Send REST request to OVOC server #
    # -------------------------------- #
    rest_response = send_rest('GET', url, username, password)
    rest_response_data = ''
    if type(rest_response) is str:
        rest_response_data = rest_response
        event = 'REST Request Error: {}'.format(rest_response_data)
        logger.error('{} - {}'.format(log_id, event))

        # ------------- #
        # Set task info #
        # ------------- #
        task_info['description'] = event

        event = 'REST request failed. Could not verify if configuration file is on OVOC server.'
        logger.warning('{} - {}'.format(log_id, event))
    else:
        if 'Content-Type' in rest_response.headers:
            if re.match('application/json', rest_response.headers['Content-Type']):
                rest_response_data = {}
                if len(rest_response.text) > 0:
                    rest_response_data = json.loads(rest_response.text)
                event = 'REST Response application/json Content-Type:\n{}'.format(json.dumps(rest_response_data, indent=4))
                logger.debug('{} - {}'.format(log_id, event))
            else:
                rest_response_data = rest_response.text
                event = 'REST Response non-application/json Content-Type:\n{}'.format(rest_response_data)
                logger.debug('{} - {}'.format(log_id, event))
        else:
            rest_response_data = rest_response.text
            event = 'REST Response no Content-Type:\n{}'.format(rest_response_data)
            logger.debug('{} - {}'.format(log_id, event))

        if rest_response.status_code == 200:
            # ------------------------------------------------------------- #
            # Status Code 200 - File already exists and needs to be removed #
            # ------------------------------------------------------------- #
            if 'files' in rest_response_data:

                # ------------------------- #
                # Get the file id from OVOC #
                # ------------------------- #
                event = 'Configuration file exists on this OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

                # ------------- #
                # Set task info #
                # ------------- #
                task_info['status'] = 'Success'
                task_info['statusCode'] = rest_response.status_code
                task_info['fileId'] = rest_response_data['files'][0]['id']
                task_info['description'] = event

            else:
                event = 'Could not get file ID for configuration file from OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

                # ------------- #
                # Set task info #
                # ------------- #
                task_info['description'] = event
        else:
            # --------------------------------------------- #
            # Get ID of file from server was not successful #
            # --------------------------------------------- #
            if 'description' in rest_response_data:
                event = '{}'.format(rest_response_data['description'])
                logger.warning('{} - {}'.format(log_id, event))
            else:
                event = 'Failed to get file ID from OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

            # ------------- #
            # Set task info #
            # ------------- #
            task_info['statusCode'] = rest_response.status_code
            task_info['description'] = event

    return task_info

# --------------------------------------------------------------------------- #
# FUNCTION: delete_file                                                       #
#                                                                             #
# Submit a REST API query to delete a file that is stored on the OVOC server  #
# acting as a file repository.                                                #
#                                                                             #
# Parameters:                                                                 #
#     logger   - File handler for storing logged actions                      #
#     log_id   - Unique identifier for this devices log entries               #
#     file_id  - Normalized configuration filename stored on OVOC server      #
#     server   - Address of OVOC server used as file repository               #
#     username - Username for REST API account on OVOC server                 #
#     password - Password for REST API account on OVOC server                 #
#                                                                             #
# Return:                                                                     #
#    task_info - Dictionary containing the following items:                   #
#        status      - String: 'Success' or 'Fail'                            #
#        statusCode  - Integer: REST response status code. (Ex: 200)          #
#        description - String: Description of the task action                 #
# --------------------------------------------------------------------------- #
def delete_file(logger, log_id, file_id, server, username, password):
    """Delete file stored on OVOC file repository."""

    # ------------------------------------------- #
    # Create a dictionary to hold the relevant    #
    # information to return for the current task. #
    # ------------------------------------------- #
    task_info = {}
    task_info['task'] = 'Delete File'
    task_info['status'] = 'Fail'
    task_info['statusCode'] = -1
    task_info['description'] = ''

    # ---------------- #
    # Set REST API URL #
    # ---------------- #
    url = "https://" + server + "/ovoc/v1/swManager/files/" + str(file_id)

    event = 'Method [DELETE] - Request URL: {}'.format(url)
    logger.debug('{} - {}'.format(log_id, event))

    # -------------------------------- #
    # Send REST request to OVOC server #
    # -------------------------------- #
    rest_response = send_rest('DELETE', url, username, password)
    rest_response_data = ''
    if type(rest_response) is str:
        rest_response_data = rest_response
        event = 'REST Request Error: {}'.format(rest_response_data)
        logger.debug('{} - {}'.format(log_id, event))

        # ------------- #
        # Set task info #
        # ------------- #
        task_info['description'] = event

        event = 'REST request failed. Could not remove configuration file from OVOC server.'
        logger.warning('{} - {}'.format(log_id, event))
    else:
        if 'Content-Type' in rest_response.headers:
            if re.match('application/json', rest_response.headers['Content-Type']):
                rest_response_data = {}
                if len(rest_response.text) > 0:
                    rest_response_data = json.loads(rest_response.text)
                event = 'REST Response application/json Content-Type:\n{}'.format(json.dumps(rest_response_data, indent=4))
                logger.debug('{} - {}'.format(log_id, event))
            else:
                rest_response_data = rest_response.text
                event = 'REST Response non-application/json Content-Type:\n{}'.format(rest_response_data)
                logger.debug('{} - {}'.format(log_id, event))
        else:
            rest_response_data = rest_response.text
            event = 'REST Response no Content-Type:\n{}'.format(rest_response_data)
            logger.debug('{} - {}'.format(log_id, event))

        if rest_response.status_code == 200:
            # ------------------------------------------- #
            # Status Code 200 - Successfully removed file #
            # ------------------------------------------- #
            event = 'Successfully removed configuration file from OVOC server'
            logger.info('{} - {}'.format(log_id, event))

            # ------------- #
            # Set task info #
            # ------------- #
            task_info['status'] = 'Success'
            task_info['statusCode'] = rest_response.status_code
            task_info['description'] = event

        else:
            # ------------------------------------------------ #
            # File removal from this server was not successful #
            # ------------------------------------------------ #
            if 'description' in rest_response_data:
                event = '{}'.format(rest_response_data['description'])
                logger.warning('{} - {}'.format(log_id, event))
            else:
                event = 'Failed to remove configuration file from OVOC server'
                logger.warning('{} - {}'.format(log_id, event))

            # ------------- #
            # Set task info #
            # ------------- #
            task_info['statusCode'] = rest_response.status_code
            task_info['description'] = event

    return task_info

# --------------------------------------------------------------------------- #
# FUNCTION: put_cli_script                                                    #
#                                                                             #
# Submit a REST API request to a device to execute the desired CLI script.    #
#                                                                             #
# Parameters:                                                                 #
#     logger   - File handler for storing logged actions                      #
#     log_id   - Unique identifier for this devices log entries               #
#     filename - Confiuration filename to create on OVOC server               #
#     script   - Confiuration CLI script in TEXT format                       #
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
def put_cli_script(logger, log_id, filename, script, device, username, password):
    """Submit REST API PUT request to execute CLI script on device."""

    # ------------------------------------------- #
    # Create a dictionary to hold the relevant    #
    # information to return for the current task. #
    # ------------------------------------------- #
    task_info = {}
    task_info['status'] = 'failure'
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
    logger.debug('{} - {}'.format(log_id, event))

    # -------------------------------- #
    # Send REST request to OVOC server #
    # -------------------------------- #
    rest_response = send_rest('PUT', url, username, password, file_contents, 'files')
    rest_response_data = ''
    if type(rest_response) is str:
        rest_response_data = rest_response
        event = 'REST Request Error: {}'.format(rest_response_data)
        logger.debug('{} - {}'.format(log_id, event))

        # ------------- #
        # Set task info #
        # ------------- #
        task_info['description'] = event

        event = 'REST request failed. Could not send CLI script to device.'
        logger.warning('{} - {}'.format(log_id, event))
    else:
        if 'Content-Type' in rest_response.headers:
            if re.match('application/json', rest_response.headers['Content-Type']):
                rest_response_data = {}
                if len(rest_response.text) > 0:
                    rest_response_data = json.loads(rest_response.text)
                event = 'REST Response application/json Content-Type:\n{}'.format(json.dumps(rest_response_data, indent=4))
                logger.debug('{} - {}'.format(log_id, event))
            else:
                rest_response_data = rest_response.text
                event = 'REST Response non-application/json Content-Type:\n{}'.format(rest_response_data)
                logger.debug('{} - {}'.format(log_id, event))
        else:
            rest_response_data = rest_response.text
            event = 'REST Response no Content-Type:\n{}'.format(rest_response_data)
            logger.debug('{} - {}'.format(log_id, event))

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
# FUNCTION: store_config_file                                                 #
#                                                                             #
# Store the configuration file on the list of OVOC servers used as file       #
# repositories using REST API.                                                #
#                                                                             #
# Parameters:                                                                 #
#     logger   - File handler for storing logged actions                      #
#     log_id   - Unique identifier for this devices log entries               #
#     filename - Normalized configuration filename to create on OVOC servers  #
#     contents - Configuration file contents                                  #
#     servers  - List of OVOC servers used as file repositories               #
#                                                                             #
# Return:                                                                     #
#    task_info - Dictionary containing the following sub-dictionary items:    #
#        'getFileId'  returned dictionary (See 'get_file_id' function call)   #
#        'deleteFile' returned dictionary (See 'delete_file' function call)   #
#        'putFile'    returned dictionary (See 'put_file' function call)      #
# --------------------------------------------------------------------------- #
def store_config_file(logger, log_id, filename, contents, servers):
    """Store configuration file on list of OVOC servers used as file repositories."""

    # --------------------------------------------- #
    # Create a list that will contain  dictionaries #
    # to hold the relevant information associated   #
    # with the current task.                        #
    # --------------------------------------------- #
    task_info = []

    index = 0
    while index < len(servers):

        this_ovoc_address = ''
        this_ovoc_username = ''
        this_ovoc_password = ''

        for key in servers[index]:
            if key == 'address':
                this_ovoc_address = servers[index][key]
            if key == 'username':
                this_ovoc_username = servers[index][key]
            if key == 'password':
                this_ovoc_password = servers[index][key]

        if this_ovoc_address != '' and this_ovoc_username != '' and this_ovoc_password != '':

            # -------------------------------------------------------- #
            # Track status of description of tasks to add to task info #
            # -------------------------------------------------------- #
            server_status = ''
            server_severity = ''
            last_description = ''

            # ------------------------------------------ #
            # Add task record for each server being used #
            # ------------------------------------------ #
            task_info.append({})
            server_index = len(task_info) - 1
            task_info[server_index]['server'] = this_ovoc_address
            task_info[server_index]['tasks'] = []

            do_file_upload = False

            # --------------------------------------------------------------- #
            # Check for preexisting configuration file on current OVOC server #
            # --------------------------------------------------------------- #
            event = 'Checking for preexisting configuration file [{}] on OVOC server [{}]'.format(filename, this_ovoc_address)
            logger.info('{} - {}'.format(log_id, event))

            # ----------------------------------------------------------------------- #
            # Call to 'get_file_id' returns dictionary that includes:                 #
            #    status      - String: 'Success' or 'Fail'                            #
            #    statusCode  - Integer: REST response status code. (Ex: 200)          #
            #    fileId      - Integer: -1 for not found, >= 0 for ID of stored file  #
            #    description - String: Description of the task action                 #
            # ----------------------------------------------------------------------- #
            get_file_id_task = get_file_id(logger, log_id, filename, this_ovoc_address, this_ovoc_username, this_ovoc_password)

            # ---------------------- #
            # Store task information #
            # ---------------------- #
            server_status = get_file_id_task['status']
            last_description = get_file_id_task['description']
            preexisting_file_id = get_file_id_task['fileId']
            task_info[server_index]['tasks'].append(get_file_id_task.copy())

            # --------------------------------------------------------------- #
            # Status Code: 204 - REST response received but no file was found #
            # --------------------------------------------------------------- #
            if get_file_id_task['statusCode'] == 204:
                do_file_upload = True

            if preexisting_file_id >= 0:
                # ----------------------------------------------------------------- #
                # Remove preexisting configuration file using 'preexisting_file_id' #
                # ----------------------------------------------------------------- #
                event = 'Removing preexisting file with same name from OVOC server'
                logger.info('{} - {}'.format(log_id, event))

                # ----------------------------------------------------------------------- #
                # Call to 'get_file_id' returns dictionary that includes:                 #
                #    status      - String: 'Success' or 'Fail'                            #
                #    statusCode  - Integer: REST response status code. (Ex: 200)          #
                #    description - String: Description of the task action                 #
                # ----------------------------------------------------------------------- #
                delete_file_task = delete_file(logger, log_id, preexisting_file_id, this_ovoc_address, this_ovoc_username, this_ovoc_password)

                # ---------------------- #
                # Store task information #
                # ---------------------- #
                server_status = delete_file_task['status']
                last_description = delete_file_task['description']
                task_info[server_index]['tasks'].append(delete_file_task.copy())

                # -------------------------------------------------------------- #
                # Status Code: 200 - REST response received and file was deleted #
                # -------------------------------------------------------------- #
                if delete_file_task['statusCode'] == 200:
                    do_file_upload = True

            else:
                event = 'No preexisting file with same name on OVOC server'
                logger.info('{} - {}'.format(log_id, event))

            if do_file_upload:
                # ---------------------------------------------------------- #
                # Attempt to store configuration file on current OVOC server #
                # ---------------------------------------------------------- #
                event = 'Attempting to store configuration file [{}] on OVOC server [{}]'.format(filename, this_ovoc_address)
                logger.info('{} - {}'.format(log_id, event))
                put_file_task = put_file(logger, log_id, filename, contents, this_ovoc_address, this_ovoc_username, this_ovoc_password)

                # ---------------------- #
                # Store task information #
                # ---------------------- #
                #task_info[server_index]['putFile'] = put_file_task.copy()
                server_status = put_file_task['status']
                last_description = put_file_task['description']
                task_info[server_index]['tasks'].append(put_file_task.copy())

            # -------------------------------------- #
            # Store task information at server level #
            # -------------------------------------- #
            task_info[server_index]['status'] = server_status
            task_info[server_index]['description'] = last_description

            if not do_file_upload:
                task_info[server_index]['severity'] = 'CRITICAL'
            else:
                task_info[server_index]['severity'] = 'NORMAL'

        index += 1

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
#     devices  - List of CPE devices to start network traffic captures on     #
#                                                                             #
# Return:                                                                     #
#    job_info - Dictionary with list of CPE devices script status             #
# --------------------------------------------------------------------------- #
def start_captures(logger, log_id, devices):
    """Start network traffic captures on all devices in the 'devices' list."""

    print('')
    print('Starting network traffic captures on {} devices...'.format(len(devices)))

    # ----------------------------------------- #
    # Create dictionary to store records of     #
    # each task taken on a device for this job. #
    # ----------------------------------------- #
    job_info = {}
    job_info['devices'] = []

    index = 0
    while index < len(cpe_devices):
        for key in cpe_devices[index]:
            if key == 'address':
                this_device_address = cpe_devices[index][key]
            if key == 'username':
                this_device_address = cpe_devices[index][key]
            if key == 'password':
                this_device_address = cpe_devices[index][key]

        if this_device_address != '' and \
           this_device_username != '' and \
           this_device_password != '':

            event = 'Sending debug capture command to CPE device #{}: [{}]'.format(index + 1, this_device_address)
            logger.info('{} - {}'.format(log_id, event))
            print('  + {}'.format(event))

            cli_script = 

        index += 1

            event = 'Processing zipped file: [{}]'.format(zip_filename)
            logger.info('{} - {}'.format(log_id, event))

            # ------------------------------------- #
            # Normalize base filename to lower case #
            # ------------------------------------- #
            base_filename = os.path.basename(zip_filename).lower()

            # ------------------------------------------ #
            # Remove any ':' or '-' separators if needed #
            # ------------------------------------------ #
            base_filename = re.sub('[:-]', '', base_filename)

            event = 'Normalized base filename to lowercase and removed any ":" or "-" separators'
            logger.info('{} - {}'.format(log_id, event))
            event = 'Base filename: [{}]'.format(base_filename)
            logger.info('{} - {}'.format(log_id, event))

            # ---------------------------------------------------------- #
            # Create end of run report information record for this file. #
            # The information in 'job_info' will be used to create the   #
            # records of the CSV output file.                            #
            # ---------------------------------------------------------- #
            if base_filename != '':
                job_info['files'].append({})
                task_index = len(job_info['files']) - 1
                job_info['files'][task_index]['baseFilename'] = base_filename
                job_info['files'][task_index]['zipFilename'] = zip_filename
                event = 'Created record in "job_info" dictionary for file'
                logger.debug('{} - {}'.format(log_id, event))

            # ----------------------------------------------------- #
            # Explanation of re.match REGEX to match MAC address:   #
            #                                                       #
            #   [0-9a-f] means an hexadecimal digit                 #
            #   {2} means that we want two of them                  #
            #   [-:]? means either a dash or a colon but optional.  #
            #       Note that the dash as first char doesn't mean   #
            #       a range but only means itself. This             #
            #       subexpression is enclosed in parenthesis so it  #
            #       can be reused later as a back reference.        #
            #   [0-9a-f]{2} is another pair of hexadecimal digits   #
            #   \\1 this means that we want to match the same       #
            #       expression that we matched before as separator. #
            #       This is what guarantees uniformity. Note that   #
            #       the regexp syntax is \1 but I'm using a regular #
            #       string so backslash must be escaped by doubling #
            #       it.                                             #
            #   [0-9a-f]{2} another pair of hex digits              #
            #   {4} the previous parenthesized block must be        #
            #       repeated exactly 4 times, giving a total of 6   #
            #       pairs of digits:                                #
            #       <pair> [<sep>] <pair> ( <same-sep> <pair> ) * 4 #
            #   .cli$ The string must end right after this          #
            #                                                       #
            # REGEX accepts 12 hex digits with either : or - or     #
            # nothing as separators between pairs (but the          #
            # separator must be uniform... either all separators    #
            # are : or are all - or there is no separator).         #
            # ----------------------------------------------------- #
            if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}.cli$", base_filename):
                event = 'Base filename matches expected configuration file format'
                logger.info('{} - {}'.format(log_id, event))

                files_to_store.append(zip_filename)

                # -------------------- #
                # Add file to job info #
                # -------------------- #
                job_info['files'][task_index]['status'] = ''
                job_info['files'][task_index]['severity'] = 'NORMAL'
                job_info['files'][task_index]['description'] = ''

            else:
                event = 'Skipped unexpected file: [{}]'.format(base_filename)
                logger.warning('{} - {}'.format(log_id, event))

                if base_filename != '':
                    # -------------------- #
                    # Add file to job info #
                    # -------------------- #
                    job_info['files'][task_index]['status'] = ''
                    job_info['files'][task_index]['severity'] = 'MINOR'
                    job_info['files'][task_index]['description'] = event
                    print('    - {}: {}'.format(job_info['files'][task_index]['severity'], job_info['files'][task_index]['description']))

        # ---------------------------------------- #
        # Add information to 'job_info' dictionary #
        # ---------------------------------------- #
        job_info['totalFiles'] = len(job_info['files'])
        job_info['filesNoSuccess'] = 0
        job_info['filesAllSuccess'] = 0
        job_info['filesPartialSuccess'] = 0

        files_to_store_cnt = len(files_to_store)
        event = 'Files to store: [{}]'.format(files_to_store_cnt)
        logger.info('{} - {}'.format(log_id, event))
        job_info['filesToStore'] = files_to_store_cnt

        total_servers = len(servers)
        event = 'Total servers to use as file repositories: [{}]'.format(total_servers)
        logger.info('{} - {}'.format(log_id, event))
        job_info['totalServers'] = total_servers

        total_cnt = files_to_store_cnt * total_servers
        event = 'Total file storage actions to attempt: [{}]'.format(total_cnt)
        logger.info('{} - {}'.format(log_id, event))
        job_info['totalStorageAttempts'] = total_cnt

        print('  + {} files match expected configuration file format'.format(files_to_store_cnt))
        if total_servers == 1:
            print('  + Storing configuration files on {} server'.format(total_servers))
        else:
            print('  + Storing configuration files on {} servers'.format(total_servers))

        # ------------------------------------------------------------ #
        # Start of progress indication bar.                            #
        # The percentage of completion of a job is shown with '#' tick #
        # marks. Total of 50 tick marks. Each tick mark represents 2%  #
        # completion.                                                  #
        #                                                              #
        # Example:                                                     #
        #  [##################################################] 100%   #
        #                                                              #
        # ------------------------------------------------------------ #
        print('    0% [{}] 100%'.format('-' * 50))
        #print('        ', end='', flush=True)

        ticks = 0
        files_cnt = 0
        success_cnt = 0
        critical_cnt = 0
        major_cnt = 0
        minor_cnt = 0
        normal_cnt = 0

        for zip_filename in files_to_store:

            # ----------------------------------------------------------- #
            # Get the index of file record in the 'job_index' dictionary. #
            # This is referenced below as the 'task_index'. Any tasks     #
            # associated with the file will be addded to the correct      #
            # record.                                                     #
            # ----------------------------------------------------------- #
            task_index = -1
            this_index = 0
            event = 'Searching for file record in "job_info" dictionary...'
            logger.debug('{} - {}'.format(log_id, event))

            for this_file in job_info['files']:
                if this_file['zipFilename'] == zip_filename:
                    task_index = this_index
                    event = 'Located record for file in "job_info" dictionary'
                    logger.debug('{} - {}'.format(log_id, event))
                    break
                this_index += 1

            if task_index >= 0:

                # ---------------------------------------------------- #
                # Increment the number of attempts to store each file. #
                # Each file should be incremented by the total number  #
                # of repositories it will try to be stored on.         #
                # ---------------------------------------------------- #
                files_cnt += total_servers

                # ---------------------------------------------- #
                # Read configuration file contents from ZIP file #
                # ---------------------------------------------- #
                try:
                    fp = io.TextIOWrapper(zipObj.open(zip_filename, 'r'), encoding="utf-8")
                    config_file_contents = fp.read()

                except Exception as err:
                    event = 'Unable to read zipped configuration file: [{}] - Error: {}'.format(zip_filename, err)
                    logger.error('{} - {}'.format(log_id, event))

                    # --------------------- #
                    # Add event to job info #
                    # --------------------- #
                    job_info['files'][task_index]['status'] = 'Fail'
                    job_info['files'][task_index]['severity'] = 'CRITICAL'
                    job_info['files'][task_index]['description'] = event

                else:
                    event = 'Successfully extracted and read in zipped configuration file contents'
                    logger.info('{} - {}'.format(log_id, event))

                    # -------------------------------------------- #
                    # Default the overall task of storing the file #
                    # to the servers as 'failed'. This will be     #
                    # updated below if the file was succesfully    #
                    # stored on a server.                          #
                    # -------------------------------------------- #
                    job_info['files'][task_index]['status'] = 'Fail'

                    # ---------------------------------------- #
                    # Store configuration file on OVOC servers #
                    # ---------------------------------------- #
                    base_filename = job_info['files'][task_index]['baseFilename']
                    task_info = store_config_file(logger, log_id, base_filename, config_file_contents, servers)

                    # -------------------------------------------------------- #
                    # Add event to job info. The 'task_info' variable returned #
                    # above is a list of dictionaries for each server that the #
                    # file was attempted to be stored on.                      #
                    # -------------------------------------------------------- #
                    job_info['files'][task_index]['servers'] = task_info.copy()

                    # ------------------------------------------------- #
                    # Set overall job status. If any one of the servers #
                    # was successful in storing the configuration file, #
                    # then the overall job status is set to 'Success'.  #
                    # ------------------------------------------------- #
                    task_success_cnt = 0
                    for server in job_info['files'][task_index]['servers']:
                        if server['status'] == 'Success':
                            job_info['files'][task_index]['status'] = 'Success'
                            task_success_cnt += 1
                            # ---------------------------- #
                            # Add to overall success count #
                            # ---------------------------- #
                            success_cnt += 1

                    # -------------------------------------------------------- #
                    # Set overall job severity. The serverity level is         #
                    # calculated based on a percentage of successful uploads   #
                    # of a file to a set of OVOC servers repositories.         #
                    #                                                          #
                    #   success_pct = 
                    # The following levels can be set:                         #
                    #     - CRITICAL: 0%   (file upload failed to all servers) #
                    #     - MAJOR   : >0% - <50%                               #
                    #     - MINOR   : 50% - <100%                              #
                    #     - NORMAL  : 0% (file uploaded to all servers)        #
                    # -------------------------------------------------------- #
                    task_total_servers = len(job_info['files'][task_index]['servers'])
                    task_success_pct = (task_success_cnt / task_total_servers) * 100
                    event = 'Task success percentage: [{}]'.format(task_success_pct)
                    logger.debug('{} - {}'.format(log_id, event))
                    if task_success_pct == 0:
                        job_info['files'][task_index]['severity'] = 'CRITICAL'
                        job_info['files'][task_index]['description'] = 'File [{}] failed to be uploaded to any server!'.format(base_filename)
                        critical_cnt += 1
                        job_info['filesNoSuccess'] += 1
                        event = 'File upload CRITICAL severity incremented to: [{}]'.format(critical_cnt)
                        logger.debug('{} - {}'.format(log_id, event))
                    elif task_success_pct > 0 and task_success_pct <= 50:
                        job_info['files'][task_index]['severity'] = 'MAJOR'
                        job_info['files'][task_index]['description'] = 'File [{}] only uploaded to {} of {} servers!'.format(base_filename, task_success_cnt, task_total_servers)
                        major_cnt += 1
                        job_info['filesPartialSuccess'] += 1
                        event = 'File upload MAJOR severity incremented to: [{}]'.format(major_cnt)
                        logger.debug('{} - {}'.format(log_id, event))
                    elif task_success_pct > 50 and task_success_pct < 100:
                        job_info['files'][task_index]['severity'] = 'MINOR'
                        job_info['files'][task_index]['description'] = 'File [{}] uploaded to {} of {} servers.'.format(base_filename, task_success_cnt, task_total_servers)
                        minor_cnt += 1
                        job_info['filesPartialSuccess'] += 1
                        event = 'File upload MINOR severity incremented to: [{}]'.format(minor_cnt)
                        logger.debug('{} - {}'.format(log_id, event))
                    else:
                        job_info['files'][task_index]['severity'] = 'NORMAL'
                        job_info['files'][task_index]['description'] = 'File [{}] uploaded successfully to all servers.'.format(base_filename)
                        normal_cnt += 1
                        job_info['filesAllSuccess'] += 1
                        event = 'File upload NORMAL severity incremented to: [{}]'.format(normal_cnt)
                        logger.debug('{} - {}'.format(log_id, event))

                    event = 'Task Info:\n{}'.format(json.dumps(job_info['files'][task_index], indent=4))
                    logger.debug('{} - {}'.format(log_id, event))

                finally:
                    # -------- #
                    # Clean up #
                    # -------- #
                    fp.close()

            else:
                event = 'File record was not located in "job_info" dictionary!'
                logger.error('{} - {}'.format(log_id, event))

            # ----------------------- #
            # Update the progress bar #
            # ----------------------- #
            if ticks < 50:
                new_ticks = int((files_cnt / total_cnt) * 50)
                i = 0
                while i < new_ticks - ticks:
                    if ticks < 50:
                        #print('#', end='', flush=True)
                        pass
                    i += 1
                ticks = new_ticks

        # ------------------------- #
        # Complete the progress bar #
        # ------------------------- #
        if ticks < 50:
            #new_ticks = int((files_cnt / total_cnt) * 50)
            new_ticks = 50
            i = 0
            while i < new_ticks - ticks:
                if ticks < 50:
                    #print('#', end='', flush=True)
                    pass
                i += 1
            ticks = new_ticks
        #print('\n', end='', flush=True)

        # --------------- #
        # Output job info #
        # --------------- #
        for job_item in job_info['files']:
            if job_item['status'] != '':
                if 'severity' in job_item:
                    if job_item['severity'] == 'CRITICAL' or \
                       job_item['severity'] == 'MAJOR' or \
                       job_item['severity'] == 'MINOR':
                        print('    - {}: {}'.format(job_item['severity'], job_item['description']))

        # ------------------- #
        # Print Success Ratio #
        # ------------------- #
        #print('  + Successful Upload Attempts: {0:5.1f}% '.format((success_cnt / total_cnt) * 100), flush=True)
        print('  + Successful Upload Attempts: {0:5.1f}% '.format((success_cnt / total_cnt) * 100))

    finally:
        # -------- #
        # Clean up #
        # -------- #
        zipObj.close()

        print('  + Finished')

    return job_info

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
#     job_info - Dictionary containing all files and tasks processed          #
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

    # ------------------------------------- #
    # Initialize job information dictionary #
    # ------------------------------------- #
    job_info = {}

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

    except KeyboardInterrupt:
        print('')
        print('=================')
        print('>>>> Aborted <<<<')
        print('=================')
        exit(1)

    exit(1)

    begin_time = time.time()
    begin_timestamp = datetime.now()
    print('')
    print('===============================================================================')
    print('                        START NETWORK TRAFFIC CAPTURES')
    print('===============================================================================')
    print('Start Time :', begin_timestamp)
    print('')
    index = 0
    while index < len(cpe_devices):
        for key in cpe_devices[index]:
            if key == 'address':
                this_device_address = cpe_devices[index][key]
            if key == 'username':
                this_device_address = cpe_devices[index][key]
            if key == 'password':
                this_device_address = cpe_devices[index][key]

        if this_device_address != '' and \
           this_device_username != '' and \
           this_device_password != '':
            print('Starting capture on CPE device #{}: {}'.format(index + 1, cpe_devices[index][key]))

        index += 1
    print('-------------------------------------------------------------------------------')

    # -------------------------------------------------------- #
    # Process ZIP file containing ALU DMP configuration files. #
    # Store each configuration file extracted on the list of   #
    # defined OVOC servers.                                    # 
    # -------------------------------------------------------- #
    job_info = process_zip_file(logger, log_id, filename, ovoc_servers)

    # ------------------------------------------ #
    # For debugging - Output returned 'job_info' #
    # dictionary containing all tasks in job.    #
    # ------------------------------------------ #
    event = 'Job Info:\n{}'.format(json.dumps(job_info, indent=4))
    logger.debug('{} - {}'.format(log_id, event))

    # ---------------------- #
    # Create CSV output file #
    # ---------------------- #
    csv_records = create_csv_file(logger, log_id, output_csv, begin_timestamp, job_info)

    end_time = time.time()
    end_timestamp = datetime.now()
    print('')
    print('===============================================================================')
    print('                              PROCESSING SUMMARY')
    print('===============================================================================')
    print('Completed:', end_timestamp)
    print('Total Duration: {0:.3f} seconds'.format(end_time - begin_time))
    print('')
    print('Total files processed in ZIP file: {}'.format(job_info['totalFiles']))
    print('Total files matching expected configuration file format: {}'.format(job_info['filesToStore']))
    print('')
    print('Servers to use as file repositories: {}'.format(job_info['totalServers']))
    print('         File upload attempts taken: {}'.format(job_info['totalStorageAttempts']))
    print('')
    print('Files that uploaded to ALL servers SUCCESSFULLY: {}'.format(job_info['filesAllSuccess']))
    print('Files that FAILED to be uploaded to ALL servers: {}'.format(job_info['filesNoSuccess']))
    print('Files with PARTIAL SUCCESS (Failed upload to at least 1 server): {}'.format(job_info['filesPartialSuccess']))
    print('')
    print('===============================================================================')

    if report_level > 0:
        print('                       ACTIONS DETAIL FOR FILES TO UPLOAD')
        print('===============================================================================')
        report_desc = ''
        if report_level == 1:
            report_desc = 'Only file upload action issues are reported.'
        if report_level == 2:
            report_desc = 'Both issues and successful file upload actions are reported.'
        print('Report Level: \'{}\' - {}'.format(report_level, report_desc))
        print('-------------------------------------------------------------------------------')

        if report_level == 1 or report_level == 2:
            if job_info['filesToStore'] == 0:
                print('')
                print('No file upload actions to report.')
            else:
                for csv_record in csv_records:

                    # ------------------------------------ #
                    # Report on any successful file upload #
                    # ------------------------------------ #
                    if report_level == 2:
                        if csv_record['serverStatus'] == 'Success' and csv_record['task'] == 'Store File':
                            print('\nCSV Row {}: ({}) - Severity: [{}] Server: [{}]'.format(csv_record['row'], csv_record['serverStatus'], csv_record['serverSeverity'], csv_record['server']))
                            print('    [{}]: {}'.format(csv_record['filename'], csv_record['serverDescription']))

                    # -------------------------------- #
                    # Report on any failed file upload #
                    # -------------------------------- #
                    if report_level == 1 or report_level == 2:
                        if csv_record['serverSeverity'].upper() != '' and csv_record['serverSeverity'].upper() != 'NORMAL':
                            print('\nCSV Row {}: ({}) - Severity: [{}] Server: [{}]'.format(csv_record['row'], csv_record['serverStatus'], csv_record['serverSeverity'], csv_record['server']))
                            print('   x[{}]: {}'.format(csv_record['filename'], csv_record['serverDescription']))

            print('')
            print('===============================================================================')

    print('')

if __name__ == "__main__":
   main(sys.argv[1:])


