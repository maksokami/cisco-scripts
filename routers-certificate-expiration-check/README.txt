USAGE
 ====================
python script.py <SSH_USER> <SSH_PWD> <ROUTER_IPs_LIST>

E.g. python script.py admin adm_pwd ip_list.txt

 ====================
Script structure:

 * Connect to each device by ssh, issue "sh crypto pki certificates" | search()
 * Get output and split it into parts for each certificate (Condition = line doesn't start from ' ' and contains 'Certificate') | split_text()
 * For each certificate get fields: "end date" and "Associated Trustpoints" | extract_cert_info()
 
Errors:
 CONNECTION_ERROR - ssh error, or command cannot be executed\not supported
 CERT_NOT_FOUND - no certificates to parse
 SCRIPT_ERROR - certificate parsing error
 
 ====================
Script output example - results.csv:
<Hostname>,<IP>,<Script status>,<Cert end date>,<Trustpoint name>
* Hostname is resolved locally by the script


router1.local.com,172.16.180.193,OK,16:09:27 GMT Jun 12 2020,TP-self-signed-33664684654
router1.local.com,172.16.180.193,OK,15:41:46 GMT Oct 21 2021,RootCA2
router2.local.com,172.16.68.65,CERT_NOT_FOUND,,
cisco-rt.local.com,172.16.92.193,CONNECTION_ERROR,,


