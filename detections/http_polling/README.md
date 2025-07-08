# **Suspicious Repeated Web Polling with `rnd=`**

This page documents a Splunk detection to identify repeated HTTP requests to file-based endpoints containing randomized `rnd=` query parameters — a pattern often associated with **command-and-control (C2) beaconing**.

While similar request patterns also appear in benign ad tracker and telemetry traffic, this detection includes logic to filter out likely tracker activity based on known filetypes, keyword patterns, and query parameter usage.

---

## **Why Focus on Repeated `rnd=` Requests to File-Based Endpoints**

This detection targets the **Command and Control** phase of the **cyber kill chain**, where compromised hosts repeatedly contact attacker-controlled infrastructure for tasking or updates. The use of randomized parameters like `rnd=` helps attackers evade caching, so the implanted client receives uncached instructions.

In the **MITRE ATT\&CK framework**, this activity aligns with:

* **T1071.001 – Application Layer Protocol: Web Protocols**
* **T1008 – Fallback Channels**
* **T1105 – Ingress Tool Transfer** (when payloads are staged behind these requests)

Filtering out known tracker activity (like mobile SDKs and ad beacons) improves signal quality and allows defenders to focus on high-confidence anomalies that may indicate real C2 behavior.

---

## **Detection SPL**

This search finds `rnd` parameters in URIs in summary logs, then passes the corresponding UIDs into the main HTTP search to retrieve full request details. It uses `rex` to extract the base URI path (`uri_endpoint`) and the value of the `rnd` parameter (`rnd_value`) from each request. A series of `eval` statements follow to count known tracker-related parameters, identify common filetypes used by trackers, and flag keyword patterns in URIs or referrers. Based on the parameter count, filetype, and keyword presence, a final `is_tracker_activity` flag is assigned to help distinguish benign tracker traffic from suspicious polling behavior. Mobile indicators in the user agent are evaluated separately to assign `is_mobile` values for additional triage context. Finally, this search looks for 4 or more connections to the same file endpoint with different `rnd` values within a 5-minute time period.

```spl
index=<YOUR_INDEX> sourcetype=<YOUR_SOURCETYPE> uri="*rnd=*"
| rex field=uri "^(?<uri_endpoint>/[^?]+)"
| rex field=uri "rnd=(?<rnd_value>[^&]+)"
| eval query_string=mvindex(split(uri, "?"), 1)

| eval tracker_param_hits=
    (if(like(query_string, "%cid=%"), 1, 0) +
     if(like(query_string, "%rnd=%"), 1, 0) +
     if(like(query_string, "%cb=%"), 1, 0) +
     if(like(query_string, "%uid=%"), 1, 0) +
     if(like(query_string, "%impid=%"), 1, 0) +
     if(like(query_string, "%trackid=%"), 1, 0))

| eval tracker_filetype=if(
    like(uri, "%.gif%") OR like(uri, "%.js%") OR like(uri, "%.png%"),
    "yes", "no"
)

| eval has_tracker_keyword=if(
    like(uri, "%track%") OR like(uri, "%pixel%") OR like(uri, "%log%") OR 
    like(uri, "%ads%") OR like(uri, "%metrics%") OR like(uri, "%wv%") OR 
    like(uri, "%cdn%") OR
    like(referrer, "%track%") OR like(referrer, "%pixel%") OR like(referrer, "%log%") OR 
    like(referrer, "%ads%") OR like(referrer, "%metrics%") OR like(referrer, "%wv%") OR 
    like(referrer, "%cdn%"),
    "yes", "no"
)

| eval is_mobile=if(
    like(user_agent, "%Android%") OR 
    like(user_agent, "%iPhone%") OR 
    like(user_agent, "%iPad%") OR 
    like(user_agent, "%Mobile%") OR 
    like(user_agent, "%wv%") OR 
    like(user_agent, "%SM-%"),
    "yes", "no"
)

| eval is_tracker_activity=if(
    (tracker_param_hits >= 2 AND tracker_filetype="yes")
    OR has_tracker_keyword="yes",
    "yes", "no"
)

| bucket _time span=5m
| stats count values(rnd_value) as rnd_values min(_time) as first_seen max(_time) as last_seen values(user_agent) as user_agent values(tracker_filetype) as tracker_filetype values(has_tracker_keyword) as has_tracker_keyword values(is_tracker_activity) as is_tracker_activity values(is_mobile) as is_mobile values(dest_host) as dest_host values(uid) as uids values(referrer) as referrer values(status_code) as status_code by src_ip dest_ip uri_endpoint _time
| where count >= 4
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| rename count as total_requests
| table first_seen last_seen src_ip dest_ip dest_host uri_endpoint total_requests status_code referrer user_agent tracker_filetype has_tracker_keyword is_tracker_activity is_mobile rnd_values uids
```

---

## **Field Descriptions**

These fields help to provide additional context and could also be used to automate alert triage to reduce noise.

| Field                 | Description                                                                 |
| --------------------- | --------------------------------------------------------------------------- |
| `uri_endpoint`        | Base URI path, excluding query string (e.g., `/track.php`, `/vbl.gif`)      |
| `query_string`        | The full URI after the `?`, containing all query parameters                 |
| `tracker_param_hits`  | Number of known tracking-related parameters found in the query string       |
| `tracker_filetype`    | Flags if the request was for a `.gif`, `.js`, or `.png` file                |
| `has_tracker_keyword` | Indicates whether the URI or referrer contains adtech/tracking keywords     |
| `is_tracker_activity` | Flags likely benign tracking-related traffic for suppression or triage      |
| `is_mobile`           | Flags requests coming from mobile devices or embedded WebView browsers      |
| `rnd_values`          | All unique `rnd=` values seen within the 5-minute window                    |
| `uids`                | Unique Zeek connection UIDs involved in this activity                       |
| `total_requests`      | Count of requests matching the detection within the time bucket (5 minutes) |

---

## **Next Steps**

* Review the `uri_endpoint`, query string parameters, `user_agent`, and `referrer` to determine if the activity matches known tracker behavior.
* Investigate any `is_tracker_activity = "no"` cases for signs of potential C2, especially if they include uncommon endpoints, non-browser user agents, or IP addresses used instead of domains.
* Correlate with DNS, SSL, and JA3 data to identify related infrastructure by creating a timeline of the client’s activity surrounding the event.
* Use inspect the PCAP to study behavior and possibly export the file as an HTTP object if using WireShark.

---


