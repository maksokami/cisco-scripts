import sys, re, socket
import paramiko, time
# Input: List of IP addresses
# Output: result.csv
# Output format: hostname, IP , <script run status>, <trustpoint_name>, <cert_end_date>

# Tacacs credentials (for a local script run)
user = ''
pwd = ""

# -----------------
# Perform 'search' function for each line in IP list file
def r_file(v_path):
    with open("result.csv", 'w') as rr:

        with open(v_path, 'r') as f:
            for line in f:
                line = line.strip()
                res = search(line)
                for item in res:
                    rr.write(str(item)+"\n")


# Takes a list of strings and concat them into one string with '\n'
def concat_lines(v_list, v_start, v_end):
    tmp_str = ""
    for i in range(v_start, v_end):
        tmp_str = tmp_str + v_list[i] + "\n"
   # print tmp_str
    return tmp_str


# -----------------
# Split CLI text into a List. Each list item is a separate certificate CLI output
# Split condition: line that includes "Certificate" and doesn't start from ' ' - (config segment)
def split_text(v_str):
    v_last_found = 0
    v_prev_found = 0
    first_match = 0
    res = []
    lines = str(v_str).splitlines()
    if len(lines) > 0:
        lines = lines[1:]
    # No certificate information
    if len(lines) <= 2:
        return []

    for ind, l in enumerate(lines):
        k = l.find("Certificate")

        # Reached end of the list
        if ind == len(lines)-1:
            if ind > v_prev_found :
                res.append(concat_lines(lines, v_prev_found, ind))

        # If new certificate found
        if k >= 0 and l[0] != " ":
            #print l
            # First certificate
            if first_match== 0:
                first_match = 1
                v_prev_found = ind
            # Later certificates
            else:
                #if v_last_found > 1:
                res.append(concat_lines(lines, v_prev_found, ind-1))
                v_prev_found = ind

    return res


# -----------------
# Extracts "End Date, TrustPoint name from CLI output
# Returns [<cert_end>, <trustpoint_name>]
def extract_cert_info(v_str):
    #v_str = v_str.lower()
    res = []
    # Match 1 Group 2 for each regexp:
    v_regexp_start = r"(start\s+date:?\s+)(.*)"
    v_regexp_end = r"(end\s+date:?\s+)(.*)"
    v_regexp_trustp = r"(Trustpoints?:?\s+)(.*)"

    k1 = re.search(v_regexp_end, v_str)
    k1 = k1.group(2).strip()
    k2 = re.search(v_regexp_trustp, v_str)
    k2 = k2.group(2).strip()
    res.append(k1)
    res.append(k2)
    #print v_str
    return res


# -----------------
# Script logic here
def search(v_ip):
    global user, pwd

    # ----------- Reverse DNS lookup (tuples)
    try:
        hostname = socket.gethostbyaddr(v_ip)
        hostname = hostname[0]
        #print hostname
    except Exception:
        hostname = ""
    # ---------- SSH CONNECTION
    try:
        remote_conn_pre = paramiko.SSHClient()
        remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        remote_conn_pre.connect(v_ip, username=user, password=pwd, look_for_keys=False, allow_agent=False)
        remote_conn = remote_conn_pre.invoke_shell()
        remote_conn.send("\n")
        time.sleep(2)
        remote_conn.send("term len 0\n")
        time.sleep(4)
        output = remote_conn.recv(4000)
        remote_conn.send("sh crypto pki certificates\n")
        time.sleep(2)
        time.sleep(2)
    except Exception as e:
        return [hostname + "," + v_ip+",CONNECTION_ERROR"]
    # ---------- FIND CERTIFICATES
    try:
        remote_conn.send("\n")
        output = remote_conn.recv(8000)
        v_list = split_text(output)
        if len(v_list) == 0:
            return [hostname + "," + v_ip + ",CERT_NOT_FOUND,,"]
    except Exception as e:
        return [hostname + "," + v_ip + ",CERT_NOT_FOUND,,"]
    # ---------- PARSE CERTIFICATES
    try:
        v_res = []
        for v_item in v_list:
            v_info = extract_cert_info(v_item)
            v_res.append(hostname + "," + v_ip + ",OK,"+v_info[0] + ',' + v_info[1])
        return  v_res
    except Exception as e:
        return [hostname + "," + v_ip + ",SCRIPT_ERROR,,"]

# Local script run
#if __name__ == '__main__':
#    r_file("ip_list.txt")
if len(sys.argv) != 4:
    print "Please provide all arguments: <usr> <pwd> <ip list filepath>\n"
else:
    user = sys.argv[1]
    pwd = sys.argv[2]
    r_file(sys.argv[3])