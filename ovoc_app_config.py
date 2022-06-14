# =========================================================================== #
#                               GENERAL SETTINGS                              #
# =========================================================================== #

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

# ------------------------------------------------------------------- #
# UDP port to listen on for OVOC alarm forwarding and other messages. #
# It is expected that OVOC will forward the selected alarms in SYSLOG #
# format.                                                             #
# ------------------------------------------------------------------- #
listen_port = 20001

# ------------------------------------------------------------------- #
# UDP port that the complementary traffic capture Python script on    #
# the CPE controlling server is listening on. Command responses are   #
# sent to the CPE app when starting and stopping 'tcpdump' traffic    #
# captures for the targeted CPE devices.                              #
# ------------------------------------------------------------------- #
cpe_listen_port = 20001

# ------------------------------------------------------------------- #
# Max retries for failed attempts to spawn 'tcpdump' captures.        #
# NOTE: This value can be set via interactive entry from this script. #
# ------------------------------------------------------------------- #
max_retries = 2

