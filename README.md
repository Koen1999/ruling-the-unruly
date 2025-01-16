# Ruling the Unruly

This repository shares the rules improved in the [Ruling the Unruly paper](https://doi.org/10.1145/3708821.3710823).
`original.rules` contains the original unmodified rules from ET OPEN, whereas `improved.rules` contains the improved versions thereof that were discussed in the paper.

## Improvement Explanations

### ET SCAN OpenVAS User-Agent Inbound (2012726)

This rule aims at detecting OpenVAS scans. We modify it to detect an RCE test string instead of an User-Agent such that the characteristic relates more closely to the malicious behavior.

Additionally, we add a threshold limit to prevent alert flooding.

### ET WEB_SERVER ColdFusion administrator access (2016184)

First, we modify the rule using a regular expression to also match other related CVEs which were previously not covered by this rule.

Secondly, we modify the rule to set a flowbit when such a request is detected but do not raise an alert.
An alert is instead raised when a HTTP 200 OK response is detected to the request for which a flowbit is set.
Hence we avoid raising alerts for unsuccessful attempts.

### ET USER_AGENTS Go HTTP Client User-Agent (2024897)

We modify this rule by including an exception for a common benign trigger caused by Tailscale using a negated content match.

### ET EXPLOIT D-Link DSL-2750B - OS Command Injection (2025756)

We modify this rule by splitting up the content match such that the position of the query parameter becomes irrelevant.
Hence we improve the generalizability of the rule.

### Various HTTP scanning rules

- ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) (92009358)
- ET WEB_SERVER Possible MySQL SQLi Attempt Information Schema Access (92017808)
- ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM (92006445)
- ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT (92006446)

These rules are changed such that a flowbit is set when request is detected but no alerts are raised.
An alert is instead raised when a HTTP 200 OK response is detected to the request for which a flowbit is set.
Hence we avoid raising alerts for unsuccessful attempts.

Additionally, we add a threshold limit to prevent alert flooding.

### ET SCAN Possible Nmap User-Agent Observed (92024364)

We modify this rule by adding a threshold limit to prevent alert flooding.

### Various TCP scanning and bruteforce rules

- ET SCAN Rapid POP3 Connections - Possible Brute Force Attack (92002992)
- ET SCAN Rapid POP3S Connections - Possible Brute Force Attack (92002993)
- ET SCAN Rapid IMAP Connections - Possible Brute Force Attack (92002994)
- ET SCAN Rapid IMAPS Connections - Possible Brute Force Attack (92002995)
- ET SCAN Suspicious inbound to Oracle SQL port 1521 (92010936)
- ET SCAN Suspicious inbound to mySQL port 3306 (92010937)
- ET SCAN Suspicious inbound to PostgreSQL port 5432 (92010939)
- ET SCAN Potential SSH Scan (92001219)
- ET SCAN Potential VNC Scan 5800-5820 (92002910)
- ET SCAN Potential VNC Scan 5900-5920 (92002911)

These rules required the most effort to improve, considering it is not using standard Suricata functionality to set an xbit after a number of identical observations have been made within a specific time window.
Suricata would normally set the xbit for every observation regardless whether the threshold is reacher or not.

Therefore, we devise a lua script to count the number of observations made within a rolling time window and set an xbit if the threshold is reached whilst not triggering any alerts.
An alert is raised when a SYN,ACK is detected in response to the SYN for which the xbit is set.
Hence we avoid raising alerts for unsuccessful attempts.

Additionally, we add a threshold limit to prevent alert flooding.

### ET SCAN NMAP OS Detection Probe (92018489)

This rule is changed such that a flowbit is set when probe is detected but alert is not raised.
An alert is instead raised when a packet in response to the probe for which a flowbit is set is detected.
Hence we avoid raising alerts for unsuccessful attempts.

### ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt (92009714)

This rule is changed such that a flowbit is set when request is detected but alert is not raised.
An alert is instead raised when a HTTP 200 OK response is detected to the request for which a flowbit is set.
Hence we avoid raising alerts for unsuccessful attempts.

Additionally, we add a threshold limit to prevent alert flooding.

## Remarks

Most time spent adjusting these rules went into the LUA scripts, and changing nitpicky details such as rule names and SIDs.

## Citations

If you use the rules, or otherwise draw from this work, please cite the following paper:

**Koen T. W. Teuwen, Tom Mulders, Emmanuele Zambon, and Luca Allodi. 2025. Ruling the Unruly: Designing Effective, Low-Noise Network Intrusion Detection Rules for Security Operations Centers. In ACM Asia Conference on Computer and Communications Security (ASIA CCS ’25), August 25–29, 2025, Hanoi, Vietnam. ACM, New York, NY, USA, 14 pages. [https://doi.org/10.1145/3708821.3710823](https://doi.org/10.1145/3708821.3710823)**
