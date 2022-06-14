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
app_log_file = 'cpe_capture_app.log'

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
# the OVOC server is listening on. Commands are sent to the OVOC app  #
# to start and stop traffic captures for the targeted CPE devices.    #
# ------------------------------------------------------------------- #
ovoc_listen_port = 20001

# ------------------------------------------------------------------- #
# Max retries for failed REST API requests.                           #
# NOTE: This value can be set via interactive entry from this script. #
# ------------------------------------------------------------------- #
max_retries = 10

# ------------------------------------------------------------------- #
# Max events per device. After the max events have been triggered on  #
# all of the devices, the application will exit.                      #
# NOTE: This value can be set via interactive entry from this script. #
# ------------------------------------------------------------------- #
max_events_per_device = 1

# ------------------------------------------------------------------- #
# List of targeted CPE devices.                                       #
# NOTE: This value can be set via interactive entry from this script. #
# ------------------------------------------------------------------- #
cpe_devices = [
    {
        "device": "192.168.200.218",
        "username": "Admin",
        "ovoc": "192.168.200.252"
    }
]

