# SDNController
This SDN controller distributes TCP or UDP streams to Android devices connected to the Open-vSwitch.

## Usage
```
$ ryu-manager switch.py
```

## REST API
### POST /mac
#### Resource URL
http://&lt;Server_IP&gt;:8080/mac
#### Parameters
| Name        | Explanation                           |
| :---------: | :---------:                           |
| port_no     | The port number of a connected device |
| mac         | The MAC address of 'rndis0'           |
| datapath_id | The datapath id of the switch         |
