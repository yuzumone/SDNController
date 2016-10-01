# SDNController
## Usage
```
$ ryu-manager switch.py
```

## REST API
### PUT bandwidth/{dpid}
#### Resource URL
http://&lt;Server_IP&gt;:8080/bandwidth/{dpid}
#### Parameters
| Name | Explanation |
| :--: | :---------: |
| dpid | OpenFlow Switch ID |
| throughput <br> <b>required</b> | Current throughput value |

## LastUpdate
2016/10/01