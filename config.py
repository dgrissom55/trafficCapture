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
app_log_file = 'capture.log'

# ---------------------------------------------------------------------- #
# Log files over 'app_max_log_file_size' (in megabytes) are rotated. The #
# total number of archived files for the application is set using the    #
# parameter 'app_archived_files'.                                        #
# ---------------------------------------------------------------------- #
app_max_log_file_size = 100
app_archived_files = 10

# --------------------------------------------------------------- #
# UDP port to listen on for OVOC alarm forwarding. It is expected #
# that OVOC will forward the selected alarms in SYSLOG format.    #
# --------------------------------------------------------------- #
listen_port = 20001

# ---------------------------------------- #
# Max retries for failed REST API requests #
# ---------------------------------------- #
max_retries = 5

# --------------------------------------------------------------- #
# Max events per device. After the max events have been triggered #
# on all of the devices, the application will exit.               #
# --------------------------------------------------------------- #
max_events_per_device = 5

# ---------------------------- #
# List of targeted CPE devices #
# ---------------------------- #
cpe_devices = [
    {
        "address": "192.168.200.218",
        "username": "Admin"
    }
]

