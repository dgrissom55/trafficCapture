# trafficCapture

<div id="top"></div>

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]

![Last Commit][last-commit-shield]
![Repo Size][repo-size-shield]





<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/dgrissom55/trafficCapture">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">trafficCapture</h3>

  <p align="center">
    Synchronize network traffic captures on multiple CPE devices and their associated OVOC servers.
    <br />
    <br />
    <a href="https://github.com/dgrissom55/trafficCapture/issues">Report Bug</a>
    ·
    <a href="https://github.com/dgrissom55/trafficCapture/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
---
<details>
  <summary><h2>Table of Contents</h2></summary>
  <ol>
    <li><a href="#change-log">Change Log</a></li>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>


<!-- CHANGE LOG -->
---
<details>
  <summary><h2>Change Log</h2></summary>

## v1.0.5

### Added or Changed
- Bug fix to correct setting the status after connecting to the device to pull its debug capture file fails.

## v1.0.4

### Added or Changed
- Added the feature to send ICMP, SNMPv3 messaging, and TCP connection requests to devices that trigger a 'Connection Lost' event on an OVOC server.
     The generated traffic is sent from both the CPE capture script server and the OVOC server.
- Automatically added OVOC alarm forwarding rules are cleaned up from the OVOC capture script if the device in the dictionary has been idle for 2 hours.

## v1.0.3

### Added or Changed
- Bug fixes

## v1.0.2

### Added or Changed
- CPE capture script now registers all targeted CPE devices to their associated OVOC capture scripts.
     This allows for the CPE script to not start captures if the OVOC server script isn't running as well.
- The UDP socket is set for non-blocking to cycle through registration requests.
- OVOC capture script now automatically sets up SNMP alarm forwarding rules for registered CPE devices.

## v1.0.1

### Added or Changed
- Added this changelog. :)
- Modified CPE and OVOC prefix to filenames of stored capture files.
- Output the script version in the section displaying the execution events.
- Added support for managing debug captures on Gateway and SBC devices.
- Added logging of the CLI scripts to the log file.
- Passwords are masked in any logging output.
- When capturing on MSBR devices you can now select multiple WAN interfaces to simultaneously capture on.

## v1.0.0

### Added or Changed
- Only supports managing debug captures for MSBR devices.

</details>

<!-- ABOUT THE PROJECT -->
---
## About The Project

![Product Name Screen Shot][product-screenshot]

The goal of this project is to try and isolate with network traffic captures any anomalies that may be preventing certain traffic types from traversing a WAN. With the scripts in this project, the task of automating the synchronization of network captures on numerous audiocodes MSBR CPE devices with their associated OVOC servers, and collecting the captures is handled.

There are a mimimum of two scripts that will be required to be run. The following is a high level description of each scripts functions:

* `cpe_capture_app.py`

  This script should be run on a separate host server, as depicted in the diagram above, that will have separate network connectivity to access both the CPE devices and the OVOC servers and also the ability to have additional Python modules installed like 'requests', 'paramiko', etc. This script DOES NOT have to be run with 'root' privileges.
                         
  This script is responsible for initiating the `debug capture` commands using REST API calls to the MSBR devices and sending UDP command request messages to synchronize `tcpdump` traffic captures on OVOC servers associated with the targeted CPE devices.

* `ovoc_capture_app.py`

  This script should be run on each OVOC server, as depicted in the diagram above, that is associated with a CPE device being targeted for network traffic captures. This script MUST BE run with 'root' privileges since it will issue system calls to start the linux 'tcpdump' application.
  
  This script receives the UDP command request messages from the CPE capture app and initiates the `tcpdump` that filters captured traffic based on the targeted CPE devices IP address.

<b>Detailed Descriptions:</b>

Running the `cpe_capture_app.py` script on a separate server other than an OVOC server is required since the goal is to understand why an OVOC server may be losing connectivity with the CPE devices. The intent is that the separate server will not have any loss of connectivity to the CPE device and will be able to remain in communications with the CPE to issue REST API commands to control and retrieve debug captures without failure.

The goal is the attempt catch an event where SNMP traffic is not being seen on the CPE device and it loses management connectivity with the OVOC server.

A major part of the interactive input to this script is the creation of a list of CPE devices and their associated OVOC servers. The commands to start/stop the debug capture on the audiocodes CPE is sent via REST API to the devices defined from the interactive entries. The traffic captures on the CPE's associated OVOC servers are started and stopped using UDP signaling.  Commands are sent from this script to the `ovoc_listen_port` defined for the complementatry Python script (`ovoc_capture_app.py`) running on the appropriate OVOC servers.

On the CPE devices, the network captures are performed by sending REST API request to the targeted CPE. The REST API request contains the necessary CLI script to start the debug capture on the selected interfaces. Also, an SNMP v3 user is created to enable this script and the OVOC capture script to send SNMP traffic to the device after OVOC has placed the device(s) in a `Connection Lost` state. In addition to the SNMP traffic, ICMP pings and TCP connection requests are sent. This is to force network traffic to the device that will be captured by the CPE debug capture and the OVOC tcpdumps.

On the OVOC servers, the network captures are performed by issuing system calls to the `tcpdump` app. To start a capture on the OVOC server, this script first registers the target devices by sending a `REGISTER` message for each device. The OVOC capture script receives the devices registration and creates an SNMP forwarding alarm on the OVOC servers for each device in order to send `Connection Lost` events to this CPE capture script. The OVOC capture script sends a `200 OK` once the device setup is complete and the alarm forwarding rule is setup on the OVOC server. If the forwarding rule fails to be created or updated, the OVOC capture script sends a `503 Service Unavailable` response.

After the registration the CPE capture script sends a `CAPTURE` command to the OVOC capture script for each targeted device to inform it which CPE traffic should be captured. The OVOC capture script responds with a `100 TRYING` when setting up the tcpdump, and a `200 OK` when the tcpdump process is running. The response will be a `503 Service Unavailable` if the tcpdump fails to start on the server.

To generate ICMP, SNMPv3, and TCP connections to the target device that OVOC triggered the `Connection Lost` alarm on, a 'VERIFY' message is sent from the CPE capture script to the OVOC capture script. The `VERIFY` message is sent to the OVOC capture script so that both the server that is running the CPE capture script and the OVOC server can create traffic to send to the targeted CPE device. The debug capture running on the device and the tcpdump running on the OVOC server should capture this generated traffic. If there truly is a network connectivity issue, this generated traffic should help isolate any issues.

The captures are stopped on the OVOC server after this script receives the `Connection Lost` SNMP alarm. This script will send a `STOP` message to the OVOC capture script to trigger it to kill the tcpdump process for that CPE device.

<p>
  (<a href="#ovoc">See the OVOC server prerequisites below.</a>)
</p>

The alarm forwarded from the OVOC servers should be in `SYSLOG` format so that the `cpe_capture_app.py` script can properly parse the contents of the alarm. This SNMP alarm forwarding rule will be automatically created in the appropriate OVOC servers in future releases. Once the alarm has been processed, the CPE capture script will send a `STOP` message to the OVOC server to trigger it to kill the tcpdump process for that CPE device. The `STOP` message also contains the filename of the PCAP capture file retrieved from an SFTP transfer of a stopped CPE `debug capture`. The OVOC server renameds its `tcpdump` files to match the filename of the CPE device for easier correlation.

For a normal flow, the following messages are exchanged:

  ```sh
CPE capture script                         OVOC capture server
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

  ```

If this script receives a request and the device address is not found in the devices information dictionary, then a `404 Not Found` is returned.

If the capture fails to be started or fails to stop, then the response will be a `503 Service Unavailable`.

The CPE capture script `cpe_capture_app.py` tracks capture states, all tasks, and other information for each targeted CPE device. The `devices_info` dictionary is created to track each devices information. The following is an example of what is tracked:

  ```sh
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
              "ovocCapture": "active|not active",
              "registration": "active|not active|aborted",
              "registerAttempts": <some value>,
              "events": <some value>,
              "lastRequest": "REGISTER|CAPTURE|VERIFY|STOP",
              "lastResponse": "<some response>",
              "lastCapture": "<stored CPE capture filename>
          },

          <NEXT DEVICE>

      ]
  }
  ```

The OVOC capture script `ovoc_capture_app.py` tracks capture states, all tasks, and other information for each targeted CPE device. The `devices_info` dictionary is created to track each devices information. The following is an example of what is tracked:

  ```sh
  {
      "devices": [
          {
              "device": "<device address>",
              "status": "Success|Failure",
              "severity": "NORMAL|MINOR|MAJOR|CRITICAL",
              "description": "<some descriptive text>",
              "tasks": [
                  {
                      "task": "<some task name>",
                      "status": "Success|Fail",
                      "statusCode": <some HTTP response code>,
                      "description": "<some descriptive text>",
                      "timestamp": "2022-06-22T16:13:39.895358"

                      <OTHER TASK SPECIFIC ITEMS, For instance>
                      "deviceId": <some value>
                      "ruleId": <some value>
                  }, 
              ], 
              "registration": "active|not active",
              "regTime": seconds since epoch,
              "ovocCapture": "not active", 
              "cpeFilename": "<filename of stored CPE capture file on CPE script>
              "tempCapture": "<local tcpdump filename before renamed to match CPE filename>", 
              "pid": "<some PID of tcpdump process>", 
              "ovocCapture0": "<filename 1 from OVOC tcpdump capture that matches CPE filename>",
              "ovocCapture1": "<filename 2 from OVOC tcpdump capture that matches CPE filename>",
              "ovocCapture2": "<filename 3 from OVOC tcpdump capture that matches CPE filename>",
              "lastRequest": "REGISTER|CAPTURE|VERIFY|STOP",
              "lastResponse": "200 OK", 
          },

          <NEXT DEVICE>

      ]
  }
  ```

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started


### Prerequisites

This is a list of of requirements for the scripts, the additional modules needed, how to install them.

On the servers hosting the CPE capture script: `cpe_capture_app.py`
* Python 3.6+
* Module `requests` for sending REST API requests to the CPE devices.

  > **Note**
  > 
  > CPE devices will need to allow access to TCP port 443.
  ```sh
  pip3 install requests
  ```
* Module `urllib3` for underlying HTTP/S transport.
  ```sh
  pip3 install urllib3
  ```
* Module `pathlib` for managment of logs and capture directories.
  ```sh
  pip3 install pathlib
  ```
* Module `paramiko` for SFTP transfers of capture files from the CPE devices.

  > **Note**
  > 
  > CPE devices will need to allow access to TCP port 22.
  ```sh
  pip3 install paramiko
  ```
<br>

On the OVOC servers hosting the capture script: `ovoc_capture_app.py`
* No prerequisites
<br>

<div id="ovoc"></div>

OVOC Server:
* No prerequisties

<br>


### Installation

> **Note**
> 
> The `ovoc_capture_app.py` script should be running prior to starting the `cpe_capture_app.py` script(s).

<br>

On OVOC servers:
1. Upload the `ovoc_capture_app` directory to each OVOC server that is used for managing any of the targeted CPE devices.
2. Access each OVOC server using SSH and navigate to the uploaded `ovoc_capture_app` directory.
3. Run the following command:
      
        python ovoc_capture_app.py
<br>


On the servers hosting the CPE capture script:
1. Upload the `cpe_capture_app` directory to a different server in the network that has access to communicate to both the CPE devices and to each OVOC server used.
2. Access the server hosting the CPE capture script using SSH or command line and navigate to the uploaded `cpe_capture_app` directory.
3. Run the following command:
      
        python3 cpe_capture_app.py
<br>


<p align="right">(<a href="#top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

1. Run `ovoc_capture_app.py` on OVOC server managing a targeted CPE device and answer the following interactive input:


      > **Note**
      > 
      > Python 2.7.x is the version of Python shipped with the OVOC server. You must use the following method `python` to start the script using Python 2.7.x on the OVOC server.
      
      ```sh
      python ovoc_capture_app.py

      =================================================================================
       Version: 1.0.2                 OVOC CAPTURE APP
      =================================================================================
      ```
  
  
      The allowed values that can be entered are displayed in the parentheses `(allowed values)`.
      Stored values from previous runs of the script are displayed in square brackets `[previously entered value]`.
      
      To accept the previously entered value, simply hit the `enter` key.

      The entry for the UDP port that this OVOC capture script listens on for request commands from running CPE capture scripts. This port is used for receiving and sending the synchronization requests and responses between the CPE capture scripts and this associated OVOC capture script running on the OVOC server. For example, the port is used for receiving the `CAPTURE` request to an OVOC capture script and sending for `TRYING` after receipt of the request and sending an `OK or FAIL` response after the tcpdump process is spawned.

      ```sh
      :===============================================================================:
      : UDP port to listen on for incoming CPE capture app command requests.          :
      :                                                                               :
      : NOTE: Entered port should be in the range (1025 - 65535)                      :
      :===============================================================================:
      Enter UPD port to listen on: (1025-65535) [20001] 
        - INFO: Set UDP port to listen on to: [20001]
      ```
  
      ```sh
      :===============================================================================:
      : Setting to control whether or not shut down this script after all active      :
      : captures have completed. Setting this to "y" prevents the script from         :
      : shutting down and allows this script to run indefinitely waiting for CPE      :
      : capture commands.                                                             :
      :===============================================================================:
      Prevent script from shutting down: (y/n) [y] 
        - INFO: Set prevent script shutdown setting to: [y]
      ```
  
  
      The list of network interfaces is dynamically created by the script by reading in the interfaces on the OVOC system that the script is running on. This list of allowed values may change for different OVOC servers.
      
      ```sh
      :===============================================================================:
      : Name of the network interface to use for CPE traffic captures.                :
      :===============================================================================:
      Enter network interface name for capture: (ens192|lo) [ens192] 
        - INFO: Set network interface name for captures to: [ens192]
      ```

      In order to automatically create the SNMP alarm forwarding rules for each registering device, it's necessary to enter a valid `Operator` privilege user account on this OVOC server. The script will use REST API to automatically create and/or update any needed alarm forwarding rules on this OVOC server.

      ```sh
      :===============================================================================:
      : OVOC account username and password that can be used for performing REST API   :
      : requests. This script will use REST API to create the SNMP alarm forwarding   :
      : needed for the CPE capture scripts.                                           :
      :                                                                               :
      : NOTE: The account used must have at least "Operator" security level.          :
      :===============================================================================:
      Enter OVOC account username: [ovoc_user] 
        - INFO: Set OVOC account username to: [ovoc_user]
        - Password: 
          Confirm password: 
          - INFO: Entered passwords match!
        - INFO: Set OVOC account password
      ```

      After the the interactive input, the script waits for `request` commands from the CPE capture app. The following is an example of a full and successful capture session for a single CPE device.
  
      ```sh
      =================================================================================
                               OVOC NETWORK TRAFFIC CAPTURES
      =================================================================================
      Start Time: 2022-06-22 21:13:16.638520
      ---------------------------------------------------------------------------------
      Listening for script messaging on UDP port: [20001]
      Received [REGISTER] request from CPE script controlling device: [192.168.200.218]
        + Checking if OVOC is managing device: [192.168.200.218]
          - INFO: CPE device exists on OVOC server
        + Checking if device has existing SNMP alarm forwarding rule.
          - ERROR: Failed to get SNMP alarm forwarding rule ID from OVOC server
        + Creating SNMP alarm forwarding rule [Forward Connection Lost from 192.168.200.218] for device: [192.168.200.218]
          - INFO: Successfully created SNMP alarm forwarding rule on OVOC server
          - INFO: Registered device and setup alarm forwarding rule.
        + Sending response for registering device on OVOC server: [200 OK 192.168.200.218]
          - INFO: Sent response for registering device on OVOC server.
      Received [CAPTURE] request from CPE script controlling device: [192.168.200.218]
        + Sending [100 Trying] response for starting capture for device: [192.168.200.218]
          - INFO: Sent response for starting capture on OVOC server.
      Starting network traffic capture for CPE device #1: [192.168.200.218]
        + Attempting to start tcpdump capture on CPE device...
          - INFO: Started capture on device as file: [tmp_device_192.168.200.218_2022-06-22T21.13.44.269908.pcap]
        + Sending response for starting capture on OVOC server: [200 OK 192.168.200.218]
          - INFO: Sent response for starting capture on OVOC server.
      Received [STOP] request from CPE script controlling device: [192.168.200.218]
        + Sending [100 Trying] response for stopping capture for device: [192.168.200.218]
          - INFO: Sent response for stopping capture on OVOC server.
      Stopping network traffic capture for CPE device #1: [192.168.200.218]
        + Attempting to stop tcpdump capture on CPE device...
          - INFO: Stopped capture on device as file: [CPE_device_192.168.200.218_2022-06-22T16.16.07.565758.pcap]
          - INFO: Successfully renamed capture file: [tmp_device_192.168.200.218_2022-06-22T21.13.44.269908.pcap0]
        + Sending response for stopping capture on OVOC server: [200 OK 192.168.200.218]
          - INFO: Sent response for stopping capture on OVOC server.
      ```
<br>

2. Run `cpe_capture_app.py` on server that has access to both the CPE device and also the associated OVOC server.


      > **Note**
      > 
      > Python 3.6+ is required for running the CPE capture script on an external computer. You should not run this script on the OVOC server since the goal is to see if the communication between the OVOC server and the CPE device truly is having communication issues. You must use the following method `python3`, or a symbolic link to python3, to start the script using Python 3.6+ on the external computer. Please see the section <a href="#usage">Usage</a> for prerequisites.
      
      ```sh
      python3 cpe_capture_app.py

      =================================================================================
       Version: 1.0.2                 CPE CAPTURE APP
      =================================================================================

      ```
  
      > **Note**
      > 
      > Multiple CPE devices can be targeted for each run of this script. This CPE script coordinates and separates the captures for each CPE device.
      
      > **Note**
      > 
      > Error checking and validation is done on each input item. For IP address and FQDN entries, the entered value is validated before allowing you to enter other information. Also, you can not enter blank/empty passwords. A valid password is required. The entered passwords are not echoed to the screen and require confirmation. If the entered password and confirmed password do not match, you'll be prompted to try again.
      
      You can limit the number of registration attempts for each CPE device to its associated OVOC capture app script. If the maximum attempts have been made without success, the script will abort any traffic captures for this device on this session of the script execution. The registration will fail if the OVOC capture app isn't running or if the SNMP alarm forwarding rule fails to be created or updated for this device.

      ```sh
      :===============================================================================:
      : Maximum number of registration attempts allowed when sending connection       :
      : requests to an OVOC capture app script. If the registration is unsuccessful,  :
      : then no capture will be performed for the device that failed to register for  :
      : this session of the CPE capture script.                                       :
      :                                                                               :
      : NOTE: Entered value should be in the range (1 - 25)                           :
      :===============================================================================:
      Enter CPE registration attempts: (1-25) [2] 
        - INFO: Set CPE registration attempts to: [2]
      ```

      The following example is an entry of a targeted MSBR device when there are no previously stored devices. After the `type` value is entered as `MSBR`, there are options for which interfaces you would like to capture on. You can select multiple interfaces for a capture session. In the example below, the `eth-wan` and `cellular-wan` interfaces are selected for this capture session.
      
      ```sh
      :===============================================================================:
      : Create a set of CPE devices to target for network traffic captures. Enter the :
      : required information to use when connecting to each device.                   :
      :                                                                               :
      : NOTE: Previously entered CPE devices are recalled and can  be modified if     :
      :       desired.                                                                :
      :                                                                               :
      : NOTE: To remove a stored device, type "delete" for the CPE device address.    :
      :===============================================================================:
      CPE device #1:
        - IP address or FQDN: 192.168.200.218
        - Type: (msbr|gwsbc) msbr
        
        MSBR capture interface options:
        :-----------------------------------------------------------------------------:
        : Valid Options: "cellular-wan", "fiber-wan", "xdsl-wan", "shdsl-wan",        :
        :                "t1-e1-wan", "eth-wan", or "eth-lan"                         :
        :                                                                             :
        : NOTE: To remove a stored interface, type "delete" for the entry.            :
        :-----------------------------------------------------------------------------:
        - Capture interface #1: eth-wan
          Add another capture interface: (y/n) [n] y
        - Capture interface #2: cellular-wan
          Add another capture interface: (y/n) [n] n
        - Username: Admin
        - Password: 
          Confirm password: 
          - INFO: Entered passwords match!
        - Associated OVOC IP address or FQDN: 192.168.200.252
        
      Add another targeted CPE device: (y/n) [n] 
        - INFO: Updates for list of targeted CPE devices successfully prepared.
        - INFO: Successfully updated "config.py" file
      ```
  
      The following example is an entry of a targeted Gateway or SBC device when there are no previously stored devices. When the `type` is set to `GWSBC`, then there is no option for selecting the capture interface for this session. On those devices, there is only one type of interface `eth-lan` and it will be used for this devices capture session.
      
      ```sh
      ===============================================================================:
      : Create a set of CPE devices to target for network traffic captures. Enter the :
      : required information to use when connecting to each device.                   :
      :                                                                               :
      : NOTE: Previously entered CPE devices are recalled and can  be modified if     :
      :       desired.                                                                :
      :                                                                               :
      : NOTE: To remove a stored device, type "delete" for the CPE device address.    :
      :===============================================================================:
      CPE device #1:
        - IP address or FQDN: (delete) [192.168.200.218] delete
          - INFO: Removed CPE device [192.168.200.218] from list of targeted devices.
      CPE device #1:
        - IP address or FQDN: 192.168.200.210
        - Type: (msbr|gwsbc) gwsbc
        - Username: Admin
        - Password: 
          Confirm password: 
          - INFO: Entered passwords match!
        - Associated OVOC IP address or FQDN: 192.168.200.252
      
      Add another targeted CPE device: (y/n) [n] 
        - INFO: Updates for list of targeted CPE devices successfully prepared.
        - INFO: Successfully updated "config.py" file
      ```
  
      Stored values from previous runs of the script are displayed in square brackets `[previously entered value]`.
      
      To accept the previously entered value, simply hit the `enter` key.

      To remove a previously store CPE device from the targeted list, enter `delete` to remove it as shown below. If there was only one targeted CPE devices stored, then you'll get the following input prompt `CPE device #x` so that you can enter at least one device to capture traffic.
      
      The following example is an interactive entry session in which the Gateway/SBC device `is removed from the targeted list, but the MSBR device is targeted again. On the MSBR device, the `cellular-wan` interface is removed from the traffic capture.

      ```sh
      :===============================================================================:
      : Create a set of CPE devices to target for network traffic captures. Enter the :
      : required information to use when connecting to each device.                   :
      :                                                                               :
      : NOTE: Previously entered CPE devices are recalled and can  be modified if     :
      :       desired.                                                                :
      :                                                                               :
      : NOTE: To remove a stored device, type "delete" for the CPE device address.    :
      :===============================================================================:
      CPE device #1:
        - IP address or FQDN: (delete) [192.168.200.210] delete
          - INFO: Removed CPE device [192.168.200.210] from list of targeted devices.
      CPE device #1:
        - IP address or FQDN: (delete) [192.168.200.218] 
        - Type: (msbr|gwsbc) [MSBR] 
      
        MSBR capture interface options:
        :-----------------------------------------------------------------------------:
        : Valid Options: "cellular-wan", "fiber-wan", "xdsl-wan", "shdsl-wan",        :
        :                "t1-e1-wan", "eth-wan", or "eth-lan"                         :
        :                                                                             :
        : NOTE: To remove a stored interface, type "delete" for the entry.            :
        :-----------------------------------------------------------------------------:
        Stored interfaces: [eth-wan, cellular-wan]
        - Capture interface #1: (delete) [eth-wan] 
        - Capture interface #2: (delete) [cellular-wan] delete
          - INFO: Removed interface [cellular-wan] from list to capture.
          Add another capture interface: (y/n) [n] n
        - Username: [Admin] 
        - Password: 
          Confirm password: 
          - INFO: Entered passwords match!
        - Associated OVOC IP address or FQDN: [192.168.200.252] 
      
      Add another targeted CPE device: (y/n) [n] 
        - INFO: Updates for list of targeted CPE devices successfully prepared.
        - INFO: Successfully updated "config.py" file
      ```
  
      The following entry of for the UDP port that this CPE capture script will listen on for forward alarms from each devices targeted OVOC server. Each server should have SNMP alarm rules setup for the `Connection Alarm` event that is triggered when the OVOC server and the CPE device lose communication with each other. A rule should manually be setup in each OVOC server that is associated with the devices that are targeted for capture sessions.
      
      In addition to the SNMP forwarded alarms that will be processed by the CPE capture script, this same port is used for sending and receiving the synchronization requests and responses between this CPE capture script and the associated OVOC capture script running on the OVOC servers. For example, the port is used for sending the `CAPTURE` request to an OVOC capture script after the debug capture has started on the targeted CPE device and waiting for `TRYING` after the OVOC capture script received the request and then an `OK or FAIL` response after the OVOC capture script has started for failed to start the spawned tcpdump process.


      ```sh
      :===============================================================================:
      : UDP port to listen on for incoming alarms forwarded by an OVOC server. Alarms :
      : are expected to be in SYSLOG format.                                          :
      :                                                                               :
      : NOTE: Entered port should be in the range (1025 - 65535)                      :
      :===============================================================================:
      Enter UPD port to listen on: (1025-65535) [20001] 
        - INFO: Set UDP port to listen on to: [20001]
      ```
  
      When sending REST API commands to the CPE devices, this setting tries to ensure that REST API requests are successful by retrying the request. Sometimes it has been noticed that the CPE may not be online or have a temporary hiccup and not accept the first request. This will also ensure that any true network outages can attempt to be handled without losing the contents of the capture session.
      
      ```sh
      :===============================================================================:
      : Maximum number of REST API retry attempts allowed when  sending requests to   :
      : CPE devices.                                                                  :
      :                                                                               :
      : NOTE: Entered value should be in the range (1 - 100)                          :
      :===============================================================================:
      Enter REST API retry attempts: (1-100) [10] 
        - INFO: Set REST API retry attempts to: [10]
      ```
     
      This entry controls how many captures are performed for each targeted CPE device. If a `Connection Lost` SNMP alarm is received for a device, then this setting restarts a new capture session until this entry has been decremented to 0. The current capture sessions (`debug capture` on device and the `tcpdump` on the OVOC server) is terminated on each receipt of the `Connection Lost` SNMP alarm and those captures are stored with the same filenames. This setting restarts that process.
      
      ```sh
      :===============================================================================:
      : Maximum number of OVOC alarm events that can be received per device that      :
      : trigger the retrieval of the network capture from a CPE device.               :
      :                                                                               :
      : If the triggering events counter is less than the value, then the network     :
      : traffic capture is restarted on the CPE device.                               :
      :                                                                               :
      : NOTE: Currently triggering on "Connection Lost" alarm.                        :
      :                                                                               :
      : NOTE: Entered value should be in the range (1 - 50)                           :
      :===============================================================================:
      Enter OVOC alarm trigger events per device: (1-50) [1] 
        - INFO: Set OVOC alarm trigger events per device to: [1]
      ```     

      After the entries are complete, the CPE capture script starts the debug capture on each targeted CPE device and then sends the `CAPTURE` command to the appropriate OVOC capture script app. The following is an example of a full and successful capture session for a single CPE device.
      
      ```sh
      =================================================================================
                               CPE NETWORK TRAFFIC CAPTURES
      =================================================================================
      Start Time:
      ---------------------------------------------------------------------------------
      Registering CPE devices to their associated OVOC capture scripts.
        + Registering device [192.168.200.218] to OVOC capture script on server: [192.168.200.252]
        + Sending message to OVOC capture script: [REGISTER 192.168.200.218]
          - INFO: Sent registration request to OVOC capture script.
      Listening for OVOC alarms and script messaging on UDP port: [20001]
        + Received response [200 OK] from OVOC associated with device: [192.168.200.218]
      Starting debug capture on CPE device #1: [192.168.200.218]
        + Attempting to start debug capture...
        + Verifying debug capture started...
          - INFO: Debug capture is active.
        + Sending message to start capture on OVOC server: [CAPTURE 192.168.200.218]
        + Sending message to OVOC capture script: [CAPTURE 192.168.200.218]
          - INFO: Sent request to start capture on OVOC server.
        + Received response [100 Trying] from OVOC associated with device: [192.168.200.218]
        + Received response [200 OK] from OVOC associated with device: [192.168.200.218]
      Received [Connection Lost] alarm from OVOC associated with device: [192.168.200.218]
      Stopping network traffic capture on CPE device #1: [192.168.200.218]
        + Attempting to stop debug capture on CPE device...
          - INFO: Successfully executed CLI script on device.
        + Verifying debug capture stopped...
          - INFO: Successfully executed CLI script on device.
          - INFO: Debug capture is not active.
      Retrieving network traffic capture from CPE device #1: [192.168.200.218]
        + Attempting to retrieve debug capture file from CPE device...
          - INFO: Stored capture from device as file: [CPE_device_192.168.200.218_2022-06-22T16.16.07.565758.pcap]
        + Sending message to stop capture on OVOC server: [STOP 192.168.200.218 CPE_device_192.168.200.218_2022-06-22T16.16.07.565758.pcap]
        + Sending message to OVOC capture script: [STOP 192.168.200.218 CPE_device_192.168.200.218_2022-06-22T16.16.07.565758.pcap]
          - INFO: Sent request to stop capture on OVOC server.
        + Received [Connection established] alarm from OVOC associated with device: [192.168.200.218]
        + Received response [100 Trying] from OVOC associated with device: [192.168.200.218]
        + Received response [200 OK] from OVOC associated with device: [192.168.200.218]
        - INFO: All devices have completed
      Finished
      
      =================================================================================
                                    PROCESSING SUMMARY
      =================================================================================
      Completed:
      Total Duration: 188.114 seconds
      ```
  

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

- [ ] Add support for capturing traffic on Mediant Gateway and SBC devices.
- [ ] Add automate creation of SNMP forwarding rules to the `ovoc_capture_app.py` script.

     * When a `CAPTURE` request is received by the OVOC capture script, if a SNMP fowarding rule doesn't already exist for the CPE capture script that sent the request, then a new rule will be added.
- [ ] Create CSV file that has records for each device and details every event and task performed against it.


<p align="right">(<a href="#top">back to top</a>)</p>


<!-- CONTACT -->
## Contact

Doug Grissom - doug.grissom@audiocodes.com

Project Link: [https://github.com/dgrissom55/trafficCapture](https://github.com/dgrissom55/trafficCapture)

<p align="right">(<a href="#top">back to top</a>)</p>




<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/dgrissom55/trafficCapture?style=for-the-badge
[contributors-url]: https://github.com/dgrissom55/trafficCapture/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/dgrissom55/trafficCapture?style=for-the-badge
[forks-url]: https://github.com/dgrissom55/trafficCapture/network/members
[stars-shield]: https://img.shields.io/github/stars/dgrissom55/trafficCapture?style=for-the-badge
[stars-url]: https://github.com/dgrissom55/trafficCapture/stargazers
[issues-shield]: https://img.shields.io/github/issues/dgrissom55/trafficCapture?style=for-the-badge
[issues-url]: https://github.com/dgrissom55/trafficCapture/issues
[license-shield]: https://img.shields.io/github/license/dgrissom55/trafficCapture?style=for-the-badge
[license-url]: https://github.com/dgrissom55/trafficCapture/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/linkedin_username
[product-screenshot]: images/capturing_flow_v1.0.4.png
[select-devices-screenshot]: images/alarm_fwd_select_devices.png
[select-alarms-screenshot]: images/alarm_fwd_select_alarm.png
[select-destination-screenshot]: images/alarm_fwd_set_type_and_destination.png
[last-commit-shield]: https://img.shields.io/github/last-commit/dgrissom55/trafficCapture?style=for-the-badge
[repo-size-shield]: https://img.shields.io/github/repo-size/dgrissom55/trafficCapture?style=for-the-badge
