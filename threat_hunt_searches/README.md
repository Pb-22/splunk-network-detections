
# **Threat Hunting Search for Raw Socket C2 (MITRE T1095)**

This page documents a Splunk threat hunting search to identify **raw TCP connections with no application-layer protocol ("service") to external IPs, characterized by many repeated low-data connections**. This technique is often associated with **malware Command and Control (C2) using MITRE ATT\&CK T1095: Non-Application Layer Protocol**.
To reduce noise, steps were taken to filter out benign behaviors such as scanning (by excluding rows with many destination ports) and ordinary high-data or protocol-identified traffic.

---

## **Why Focus on Raw Socket, Low-Payload Connections**

Detection of these behaviors is important because many advanced attackers use raw TCP or non-standard application-layer protocols to establish command and control channels. Such C2 channels are often not identified by simple firewall rules or IDS signatures, especially when well-known ports and protocols are avoided. By hunting for many repeated connections with little or no payload data, stealthy C2 infrastructure can be identified at the C2 phase of the cyber kill chain—specifically mapping to [MITRE ATT\&CK Technique T1095: Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/).
This approach also brings to light malicious activity that tries to "blend in" at the network layer, while minimizing noise from normal user and scanning traffic.

---

## **Detection SPL**

This hunting search uses Zeek/Corelight connection logs in Splunk to find repeated raw TCP connections to external IPs that lack application-layer protocol identification and have very little data transferred.
Line by line:

* Focuses on outbound TCP connections to non-internal IPs, where no application-layer protocol (“service”) is detected.
* Selects only sessions with minimal data and short histories—these are commonly seen in beaconing or backconnect shells.
* Groups connections by internal and external IP, summarizing how many times, on which ports, and how much data was transferred.
* Filters for repeat activity, and drops rows with many destination ports to avoid noisy scanning results.
* Assigns scores for odd ports, long durations, high counts, low average bytes, and multi-destination fan-out.
* Sums these scores into a risk score, then shows only the most suspicious connections, sorted for easy triage.

```spl
index=<your_index> sourcetype=<your_sourcetype> NOT dest_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16", "169.254.0.0/16", <!-- add more IPs or networks to ignore here -->) NOT service=* transport=tcp
| where (len(history) <=3 )
| where orig_bytes < 200 AND resp_bytes < 200
| stats count, values(dest_port) as dest_port values(history) as history sum(orig_bytes) as sum_orig_bytes sum(resp_bytes) as sum_resp_bytes sum(duration) as sum_duration by src_ip dest_ip
| where count >3 <!-- adjust as needed: raise this to reduce results -->
| eval dest_port_count=mvcount(dest_port)
| where dest_port_count < 5 <!-- adjust to reduce large rows taking up the page -->
| sort - count
| eval is_oddport=if(match(dest_port,"^(80|443|22|25|53|110|143)$"),"no","yes")
| eval is_longconn=if(sum_duration > 7200, "yes", "no") <!-- tune duration threshold -->
| eval is_high_count=if(count > 504, "yes", "no") <!-- tune count threshold -->
| eval bytes_per_count=round((sum_orig_bytes + sum_resp_bytes) / count, 1)
| eventstats dc(dest_ip) as unique_dests by src_ip
| eval is_multidest=if(unique_dests > 3, "yes", "no") <!-- tune dest IP count threshold -->
| eval oddport_score=case(match(dest_port,"^(80|443|22|25|53|110|143)$"),0, tonumber(dest_port) > 1024,2, true(),1)
| eval longconn_score=if(is_longconn="yes" AND is_high_count="no", 3, if(is_longconn="yes", 1, 0))
| eval highcount_score=if(is_high_count="yes", 2, 0)
| eval multidest_score=if(is_multidest="yes", 1, 0)
| eval lowbytes_score=if(bytes_per_count < 20 AND is_high_count="yes", 2, if(bytes_per_count < 20, 1, 0)) <!-- tune bytes per count threshold -->
| eval risk_score=oddport_score + longconn_score + highcount_score + multidest_score + lowbytes_score
| fields src_ip dest_ip dest_port count unique_dests sum_orig_bytes sum_resp_bytes sum_duration is_oddport is_longconn is_high_count is_multidest bytes_per_count risk_score
| search risk_score > 5 <!-- tune risk score threshold -->
| sort - risk_score - duration
```

---

## **Field Descriptions**

| Field             | Description                                                                                |
| ----------------- | ------------------------------------------------------------------------------------------ |
| src\_ip           | Source IP address (internal host)                                                          |
| dest\_ip          | Destination IP address (external host)                                                     |
| dest\_port        | List of destination ports used between the src\_ip and dest\_ip                            |
| count             | Number of raw TCP connections between the src\_ip and dest\_ip                             |
| unique\_dests     | Number of unique destination IPs the src\_ip has communicated with (for fan-out detection) |
| sum\_orig\_bytes  | Total bytes sent from src\_ip to dest\_ip across all connections                           |
| sum\_resp\_bytes  | Total bytes sent from dest\_ip to src\_ip across all connections                           |
| sum\_duration     | Total duration of all the sessions for this src\_ip/dest\_ip pair                          |
| is\_oddport       | "yes" if destination port(s) are not common (not HTTP, HTTPS, SSH, SMTP, DNS, POP3, IMAP)  |
| is\_longconn      | "yes" if total session duration exceeds threshold (default: 7200 seconds/2 hours)          |
| is\_high\_count   | "yes" if number of sessions exceeds threshold (default: 504)                               |
| bytes\_per\_count | Average (rounded) bytes transferred per session (orig + resp / count)                      |
| is\_multidest     | "yes" if src\_ip is talking to more than 3 unique dest IPs                                 |
| oddport\_score    | Score (0/1/2) based on whether destination port is common or high/random                   |
| longconn\_score   | Weighted score for long connection behavior                                                |
| highcount\_score  | Weighted score for high connection count                                                   |
| multidest\_score  | Weighted score for src\_ip talking to multiple dest IPs                                    |
| lowbytes\_score   | Weighted score for low average bytes per session                                           |
| risk\_score       | Total risk score for the row based on the sum of the above weighted fields                 |

---

## **Next Steps**

* **Investigate the internal host(s) (`src_ip`):**

  * Examine for malware, suspicious scheduled tasks, persistence, or unexpected network tools.
  * Determine when these connections began and how often they occur by reviewing historical logs for first and last seen times, as well as frequency and periodicity.
* **Validate the external destination(s) (`dest_ip`):**

  * Check threat intelligence sources (e.g. VirusTotal, Shodan) for known malicious infrastructure.
  * Consider passive DNS, historical Whois, and recent open ports.
* **Review session packet data:**

  * If available, inspect pcap or Zeek logs for traffic characteristics—look for hand-crafted protocols, encryption, or command patterns.
* **Correlate with other detections:**

  * Look for related alerts (proxy use, DNS tunneling, endpoint detections).
* **Hunt for lateral movement:**

  * Search for other internal hosts showing similar outbound patterns or connecting to the same destination.
* **Block or monitor as needed:**

  * If confirmed malicious, block the external IP at the firewall and continue monitoring for related activity.

---

## **Tuning Notes**

This threat hunting search is **likely to produce some noise** and should be tuned to fit each environment.
Below are the areas in the SPL where tuning may be required:

* **Network scoping:**
  `NOT dest_ip IN (...)` — This filter removes common internal networks from results. Additional external IPs or networks (such as trusted partners, known scanners, or specific public services) can also be added here if they should be ignored.

* **Minimum number of connections:**
  `| where count >3` — Adjust to control result volume.

* **Maximum number of destination ports:**
  `| where dest_port_count < 5` — Lower to eliminate scanning; raise to be more inclusive.

* **Long connection duration threshold:**
  `| eval is_longconn=if(sum_duration > 7200, "yes", "no")` — Set to reflect session patterns.

* **High connection count threshold:**
  `| eval is_high_count=if(count > 504, "yes", "no")` — Tune for expected or observed beaconing/C2 activity.

* **Multi-destination threshold:**
  `| eval is_multidest=if(unique_dests > 3, "yes", "no")` — Adjust based on what is considered abnormal for hosts in the environment.

* **Bytes per session threshold:**
  `| eval lowbytes_score=if(bytes_per_count < 20 AND is_high_count="yes", 2, if(bytes_per_count < 20, 1, 0))` — Modify as needed.

* **Risk score cutoff:**
  `| search risk_score > 5` — Lower for broader hunting, raise for higher-confidence results.

Regular review and refinement of these thresholds is recommended to minimize noise and maximize coverage of true threats.

