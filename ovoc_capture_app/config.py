# =========================================================================== #
#                               GENERAL SETTINGS                              #
# =========================================================================== #

# -------------- #
# Script version #
# -------------- #
version = '1.0.5'

# ----------------------------------- #
# Directory to store application logs #
# ----------------------------------- #
storage_dir = './logs'

# ---------------------------------------------------------- #
# Log Files used by this application. The 'app_log_file' is  #
# written to based on the actions of this application.       #
#                                                            #
# Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL          #
# ---------------------------------------------------------- #
app_log_level = 'DEBUG'
app_log_file = 'ovoc_capture_app.log'

# ---------------------------------------------------------------------- #
# Log files over 'app_max_log_file_size' (in megabytes) are rotated. The #
# total number of archived files for the application is set using the    #
# parameter 'app_archived_files'.                                        #
# ---------------------------------------------------------------------- #
app_max_log_file_size = 100
app_archived_files = 10

# ---------------------------------------------------------------------- #
# Flag to prevent the script from shutting down when there are no active #
# captures to manage. Setting this to 'y' prevents this script from      #
# shutting down and it will run indefinitely waiting for CPE commands.   #
# NOTE: This value can be set via interactive entry from this script.    #
# ---------------------------------------------------------------------- #
prevent_shutdown = 'y'

# ------------------------------------------------------------------- #
# UDP port to listen on for OVOC alarm forwarding and other messages. #
# It is expected that OVOC will forward the selected alarms in SYSLOG #
# format.                                                             #
# NOTE: This value can be set via interactive entry from this script. #
# ------------------------------------------------------------------- #
listen_port = 20001

# ------------------------------------------------------------------- #
# Network interface name to use for CPE traffic captures.             #
# NOTE: This value can be set via interactive entry from this script. #
# ------------------------------------------------------------------- #
interface_name = 'ens192'

# ------------------------------------------------------------------- #
# OVOC user account for performing REST API commands to create SNMP   #
# alarm forwarding rules. Only the username is stored in this config  #
# file. The password must be entered interactively at the time the    #
# script is run.                                                      #
# NOTE: This value can be set via interactive entry from this script. #
# ------------------------------------------------------------------- #
ovoc_username = ''
