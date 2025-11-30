
# AWS Network Firewall Rules

This directory contains AWS Network Firewall Suricata rules used in the [AWS Network Security Workshop](https://catalog.us-east-1.prod.workshops.aws/workshops/cbfa9f18-1175-4916-b7e7-e33dbbca9f9d).

## Important Note

**These firewall rules are specifically designed for Labs 1 and 2 of the workshop.** The rules provided here demonstrate general network security patterns and controls.

Labs 5 and 6 use different, more specialized firewall rules for very specific use cases:
- **Lab 5**: Focuses on allow-listing specific domains and applications
- **Lab 6**: Demonstrates TLS inspection capabilities with targeted rules

The rules in this directory are more general-purpose and serve as a foundation for understanding AWS Network Firewall capabilities.

## Rule Files

- **rule-set.txt**: Contains the raw Suricata rule syntax
- **README.md**: This file, providing detailed explanations of each rule

---

# Rule Explanations

## Allow TCP 3-way handshake
```pass tcp any any -> any any (flow:to_server,not_established; sid:10001;)```
- This rule allows the initial TCP handshake (SYN packets) from any source to any destination. The `flow:to_server,not_established` keyword ensures this only matches traffic that is going to the server and is not part of an established connection. This is necessary to allow new TCP connections to be initiated before applying more specific rules.

---


# Mark MySQL connection from DEV to PROD sanitized database as allowed
```alert tcp $DEV_CIDR any -> $SANITIZED_PROD_DB 3306 (msg:"Allow DEV to PROD sanitized DB"; flowbits:set,allow; flow:to_server; sid:10002;)```
- This rule identifies and marks MySQL traffic (port 3306) from the Development environment to the sanitized Production database as allowed. The `flowbits:set,allow` keyword sets a flag called "allow" on this connection, which will be checked by later rules. This rule uses `alert` action which means it will log the connection but still allow it to be evaluated by other rules.

---


# Mark TLS connection from DEV to PROD internal API as allowed
```alert tls $DEV_CIDR any -> $PROD_INTERNAL_API 443 (msg:"Allow DEV to PROD internal API over TLS"; flowbits:set,allow; flow:to_server; sid:10003;)```
- This rule identifies and marks HTTPS/TLS traffic (port 443) from the Development environment to the Production internal API as allowed. The `tls` protocol matcher specifically looks for TLS-encrypted traffic. Like the previous rule, it sets the "allow" flowbit to mark this connection as permitted.

---


# Mark HTTP connection from DEV to PROD internal API as allowed
```alert http $DEV_CIDR any -> $PROD_INTERNAL_API 80 (msg:"Allow DEV to PROD internal API over HTTP"; flowbits:set,allow; flow:to_server; sid:10004;)```
- This rule identifies and marks HTTP traffic (port 80) from the Development environment to the Production internal API as allowed. The `http` protocol matcher specifically looks for HTTP traffic. This allows both encrypted (TLS) and unencrypted (HTTP) access to the internal API.

---


# Reject any other TCP connections from DEV to PROD (Send a TCP reset so it's clear the connection was blocked by firewall and not a routing issue)
```reject tcp $DEV_CIDR any -> $PROD_CIDR any (msg:"UNAUTHORIZED DEV -> PROD TCP CONNECTION ATTEMPT"; flowbits:isnotset,allow; flow:to_server; sid:10005;)```
- This rule blocks any TCP traffic from Development to Production that hasn't been marked as allowed by previous rules. The `flowbits:isnotset,allow` keyword checks if the "allow" flag has NOT been set on this connection. The `reject` action sends a TCP reset packet back to the source, providing clear feedback that the connection was actively blocked.

---

# Drop any other IP connections from DEV to PROD (Catch all drop rule for non TCP based protocols)
```drop ip $DEV_CIDR any -> $PROD_CIDR any (msg:"UNAUTHORIZED DEV -> PROD NON-TCP CONNECTION ATTEMPT"; flowbits:isnotset,allow; flow:to_server; ip_proto: !TCP; sid:10006;)```
- This is a catch-all rule that blocks any non-TCP traffic (UDP, ICMP, etc.) from Development to Production. The `ip_proto: !TCP` specifically matches any IP protocol that is not TCP. The `drop` action silently discards the packets. This rule ensures complete isolation between environments except for the specifically allowed connections.

**Understanding flowbits:** The `flowbits` keyword allows rules to communicate with each other by setting and checking stateful flags on network flows. In this ruleset, flowbits implement an allow-list approach where specific connections are marked as permitted (`flowbits:set,allow`), and everything else is blocked (`flowbits:isnotset,allow`). For more information, see the [Suricata documentation](https://docs.suricata.io/en/latest/rules/flow-keywords.html).


# Block evasion of Route 53 Resolver (enforce the use of Route 53 Resolver DNS Firewall)
```drop dns $HOME_NET any -> !$HOME_NET any (msg:"Drop DNS protocol outbound on any port"; reference:url,https://attack.mitre.org/techniques/T1048/; sid:10000001;)```
- This Suricata rule drops (blocks) all DNS traffic that originates from $HOME_NET (home network) and is heading out to a destination that is not within the home network (!$HOME_NET), on any destination port. This is more comprehensive than just blocking port 53, as it prevents DNS traffic on non-standard ports as well. By enforcing that all DNS queries must go through Route 53 Resolver, you ensure that DNS Firewall protections are applied to all DNS traffic.
- The Suricata keyword of reference:url allows us to include a URL where one can get more information about the threat this rule is designed to mitigate. In this case, it references the MITRE ATT&CK technique T1048 for exfiltration over alternative protocols.


# Port 80 can only be used for HTTP traffic
```drop tcp $HOME_NET any -> any 80 (msg:"Egress Port TCP/80 but not HTTP"; app-layer-protocol:!http; flow:to_server; sid:10000002;)```
- This rule blocks any TCP traffic on port 80 that is not using the HTTP protocol. The `app-layer-protocol:!http` keyword specifically identifies traffic that doesn't match HTTP protocol patterns. This prevents attackers from using port 80 for non-HTTP traffic, such as command and control channels or data exfiltration using custom protocols.

---

# Outbound HTTP traffic must use port 80
```drop http $HOME_NET any -> any !80 (msg:"Egress HTTP but not port TCP/80"; flow:to_server; sid:10000003;) ```
- This rule blocks HTTP traffic that's not using the standard port 80. The `!80` in the destination port field matches any port except 80. This prevents applications from using non-standard ports for HTTP traffic, which is a common evasion technique to bypass security monitoring focused only on standard ports.

---

# Port 443 can only be used for TLS traffic
```drop tcp $HOME_NET any -> any 443 (msg:"Egress Port TCP/443 but not TLS"; app-layer-protocol:!tls; flow:to_server; sid:10000004;)```
- This rule blocks any TCP traffic on port 443 that is not using the TLS protocol. Similar to the port 80 rule, this prevents misuse of the HTTPS port for non-encrypted or custom protocol traffic, ensuring that only legitimate encrypted web traffic uses this port.

---


# Outbound TLS traffic must use port 443
```drop tls $HOME_NET any -> any !443 (msg:"Egress TLS but not port TCP/443"; flow:to_server; sid:10000005;)```
- This rule blocks TLS/encrypted traffic that's not using the standard port 443. This prevents applications from using TLS on non-standard ports to evade security controls, a technique often used to tunnel prohibited traffic through firewalls.

---


# Port 22 can only be used for SSH traffic
```drop tcp $HOME_NET any -> any 22 (msg:"Egress Port TCP/22 but not SSH"; app-layer-protocol:!ssh; flow:to_server; sid:10000006;)```
- This rule blocks any TCP traffic on port 22 that is not using the SSH protocol. This prevents misuse of the SSH port for other types of traffic, ensuring that only legitimate SSH connections are allowed on this port.

---


# Outbound SSH traffic must use port 22
```drop ssh $HOME_NET any -> any !22 (msg:"Egress SSH but not port TCP/22"; flow:to_server; sid:10000007;)```
- This rule blocks SSH traffic that's not using the standard port 22. This prevents SSH tunneling on non-standard ports, which is a common technique used to bypass network security controls.



# Block Traffic To/From ITAR Countries 
```drop ip any any -> any any (msg:"Geographic IP is from ITAR-Restricted Country"; geoip:any,AF,BY,MM,KH,CF,CN,CU,CY,CD,ER,ET,HT,HK,IR,IQ,KG,LB,LY,NI,KP,RU,SO,SS,SD,SY,VE,ZW; sid:10000008;)```
- This rule blocks all IP traffic to or from countries restricted by the International Traffic in Arms Regulations (ITAR). The `geoip:any` keyword matches traffic in either direction (source or destination), followed by a comma-separated list of two-letter country codes. This ensures compliance with ITAR requirements by preventing any network communication with these restricted countries, including Afghanistan (AF), Belarus (BY), Myanmar (MM), Cambodia (KH), Central African Republic (CF), China (CN), Cuba (CU), Cyprus (CY), Democratic Republic of the Congo (CD), Eritrea (ER), Ethiopia (ET), Haiti (HT), Hong Kong (HK), Iran (IR), Iraq (IQ), Kyrgyzstan (KG), Lebanon (LB), Libya (LY), Nicaragua (NI), North Korea (KP), Russia (RU), Somalia (SO), South Sudan (SS), Sudan (SD), Syria (SY), Venezuela (VE), and Zimbabwe (ZW).

---


# Block Traffic To/From Any Country Besides the US or Canada
```drop ip any any -> any any (geoip:any,!US,!CA; msg:"Drop traffic to countries other than US and Canada"; sid:10000009;)```
- This rule implements an allow-list approach by blocking all IP traffic except to or from the United States and Canada. The `!US,!CA` syntax uses negation to specify that only these two countries are permitted. This is a more restrictive security posture than blocking specific countries, as it denies all traffic by default except to explicitly approved geographic locations. This approach is particularly useful when your business operations are limited to specific regions and you want to minimize your attack surface by preventing connections to any other country.

