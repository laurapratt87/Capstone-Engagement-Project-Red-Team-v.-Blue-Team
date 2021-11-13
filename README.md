# Capstone-Engagement-Project-Red-Team-v.-Blue-Team
As the Red Team, attack a vulnerable VM within the environment, ultimately gaining root access to the machine. As Blue Team, use Kibana to review logs taken during Day 1 engagement of Red Team’s attack. Use the logs to extract hard data and visualizations for a detailed report of findings.

This document serves as an outline for the [Presentation]() of the Capstone Engagement Project.

# Network Topology

The following machines live on the network:

| **Name**     | **IP Address** |
|----------|------------|
| Kali    |  192.168.1.90  |
| Target    | 192.168.1.105   |
|ELK | 192.168.1.100   |
|Azure Hyper-V | 192.168.1.1   |

![alt text](https://github.com/laurapratt87/Capstone-Engagement-Project-Red-Team-v.-Blue-Team/blob/main/Resources/network%20topology1.PNG)

# Red Team

While the web server suffers from several vulnerabilities, here are three that were initially discovered:

| | **Vulnerability**     | **Description** | **Impact** |
|-|----------|------------|------------|
| 1 | Sensitive Data Exposure (A02:2021 OWASP Top 10) **_Critical_** | The secret_folder is publicly accessible, but contains sensitive data intended only for authorized personnel. | The exposure compromises credentials that attackers can use to break into the web server. |
| 2 | Brute Force Vulnerability  | An attack method where login information, passwords and encryption keys are attempted until there is a successful login. | This type of attack can have a significant impact because the attacker can cause loss of data, identity theft, and unauthorized access to confidential data. |
| 3 |Remote Code Execution via Command Injection (A03:2021 OWASP Top 10) **_Critical_** | Code injection, also called Remote Code Execution (RCE), occurs when an attacker exploits an input validation flaw in software to introduce and execute malicious code. | Malicious code can be injected to possibly gain access to sensitive data and compromise the confidentiality and integrity of the information. |

## Exploits

  - **Explotation: Sensitive Data Exposure**
    - Tools & Processes
      - `nmap` command to determine open ports and IP addresses accepting connections.
      - `dirb` command that is used to find existing and/or hidden web objects, which are the elements of a web page.
      - Explore different avenues of the web page. 

    - Achievements
      - The exploit revealed a `secret_folder` directory
      - Folder says for Asthon’s eyes only, leading the direction of the login efforts. 
      - This directory is password protected, but susceptible to **brute-force**.

    - Aftermath
      - The login prompt reveals that the user is `Ashton` 
      - This information is used to run a brute force attack and steal the data that is needed for the Remote Code Injection. 

  - **Explotation: Brute Force Vulnerability**
    - Tools & Processes
      - `gunzip` rockyou.gz file to unzip the file to be used later in the password cracking step.
      - Run `hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder`. Running this command with hydra (built into         the Kali Linux OS) with the username Ashton, against the rockyou.txt is the process for obtaining Ashton's password. **Hydra** is a common login cracker.

    - Achievements
      - Brute force attack gaining access to log into the browser to gain access to Ryan’s hashed password, which later leads to access to the webdav browser.

     - Aftermath
       - Crack hash and proceed with brute force attack, logging into the web browser, then receiving further instruction on how to connect to the webdav server, which is used           in the remote code injection.

 - **Explotation: Remote Code Injection**
    - Tools & Processes
      - Use Meterpreter to connect to uploaded web shell
      - Use shell to explore and compromise target.
 
    - Achievements
      - Deploying the remote code injection allows up to open the Meterpreter shell into the target. 
      - Once this shell is opened, this opens the door to access the full database. 

    - Aftermath
      - Having access to the full database, provided the opportunity to find the flag, demonstrating the ability to access sensitive data. 

# Blue Team

A considerable amount of data is available in the logs. Specifically, evidence of the following was obtained upon inspection:

  - Traffic from attack VM to target, including unusually high volume of requests
  - Access to sensitive data in the secret_folder directory
  - Brute-force attack against the HTTP server
  - POST request corresponding to upload of shell.php

**Unusual Request Volume**: Logs indicate an unusual number of requests and failed responses between the Kali VM and the target. Note that 401, 301, 200, 207, and 404 are the top responses.

| HTTP Status Code | Meaning | Count |
|----------|------------|----------|
|   401    |  Unauthorized  | 16,067 |
|   301    |  Moved Permanently | 2 |
|   200    |    OK     | 536 |
|   207    | Multi-Status(WebDAV; RFC 4918) | 10 |
|   404    |  Not Found   | 4 |

In addition, note the connection spike in the Connections over time, which indicates the time the spike occurred at 2:46PM (1446 hours).

![alt text](https://github.com/laurapratt87/Capstone-Engagement-Project-Red-Team-v.-Blue-Team/blob/main/Resources/time%20attack%20occurred.PNG) 

This shows the Top Hosts Creating Traffic, which indicates the Kali-Linux Machine have the most traffic at 2:46PM.

![alt text](https://github.com/laurapratt87/Capstone-Engagement-Project-Red-Team-v.-Blue-Team/blob/main/Resources/host%20creating%20traffic.PNG)

**Access to Sensitive Data in secret_folder**: On the dashboard, a look at the Top 10 HTTP requests panel shows that the /company_folders/secret_folder was requested 16,071.

![alt text](https://github.com/laurapratt87/Capstone-Engagement-Project-Red-Team-v.-Blue-Team/blob/main/Resources/requests%20into%20secret%20directory.PNG)

**HTTP Brute Force Attack**: Searching for `url.path: /company_folders/secret_folder/` shows conversations involving the sensitive data. Specifically, the results contain requests from the brute-forcing tool Hydra, identified under the user_agent.original section.

![alt text](https://github.com/laurapratt87/Capstone-Engagement-Project-Red-Team-v.-Blue-Team/blob/main/Resources/brute%20force%20hydra.PNG)

![alt text](https://github.com/laurapratt87/Capstone-Engagement-Project-Red-Team-v.-Blue-Team/blob/main/Resources/user%20agent%20hydra%20filter.PNG)

In addition, the logs contain evidence of a large number of requests for the sensitive data, of which only 2 were successful. This is a telltale signature of a brute-force attack. 

![alt text](https://github.com/laurapratt87/Capstone-Engagement-Project-Red-Team-v.-Blue-Team/blob/main/Resources/response%20code%20200%20OK.PNG)

**WebDAV Connection & Upload of shell.php**: The logs also indicate that an unauthorized actor was able to access protected data in the webdav directory. This image shows that the /webdav/shell.php has a count of 10 with a http status 207, meaning that there are several different responses based on the sub-requests that were made.

![alt text](https://github.com/laurapratt87/Capstone-Engagement-Project-Red-Team-v.-Blue-Team/blob/main/Resources/http%20request%20code%20breakdown.PNG)

## Mitigation steps are provided below.

  * Blocking the Port Scan

    * The local firewall can be used to throttle incoming connections
    * ICMP traffic can be filtered
    * An IP allowed list can be enabled
    * Regularly run port scans to detect and audit any open ports

  * High Volume of Traffic from Single Endpoint

    * Rate-limiting traffic from a specific IP address would reduce the web server's susceptibility to DoS conditions, as well as provide a hook against which to trigger alerts against suspiciously suspiciously fast series of requests that may be indicative of scanning.

  * Access to sensitive data in the secret_folder directory

    * The secret_folder directory should be protected with stronger authentication. 
    * Data inside of secret_folder should be encrypted at rest.
    * Filebeat should be configured to monitor access to the secret_folder directory and its contents.
    * Access to secret_folder should be whitelisted, and access from IPs not on this whitelist, logged.

  * Brute-force attack against the HTTP server

    * The **fail2ban utility** can be enabled to protect against brute force attacks.
    * Create a policy that locks out accounts after 10 failed attempts
    * Create a policy that increases password complexity (requirements)
    * Enable MFA

  * Identifying reverse shell uploads
  
    * Write permissions can be restricted	on the host.
	  * Uploads can be isolated into a dedicated storage partition.
	  * Filebeat should be enabled and configured.

## Assessment Summary

| **Red Team**     | **Blue Team** |
|----------|------------|
| Accessed the system via HTTP Port 80 CVE-2019-6579   |  Confirmed that a port scan occurred  |
| Found Root accessibility  | Found requests for a hidden directory   |
|Found the occurrence of simplistic usernames and weak passwords | Found evidence of a brute force attack |
|Brute forced passwords to gain system access CVE-2019-3746 | Found requests to access critical system folders and files |
|Cracked a hashed password to gain system access and use a shell script | Identified a WebDAV vulnerability |
|Identified Directory Indexing Vulnerability CWE-548| Recommended alarms   |
|   |  Recommended system hardening |


## Group

- [Laura Pratt](https://github.com/laurapratt87)
- [Josh Black](https://github.com/joshblack07)
- [Courtney Templeton](https://github.com/cltempleton1127)
- [Robbie Drescher](https://github.com/RobDresch)
- Julian Baker
