# Vuln Scanner

This note is used to check if the vulnerbility detected by scanner via version fingerprinting, fast locate the PoC/EXP location.

| CVE / SRC No.  | Vuln Name | PoC Software | PoC Location |
|:-----------:|:---------------:|:--------------:|:-------------:|
| MS15-034 | HTTP.sys Could Allow Remote Code Execution | MSF | auxiliary/scanner/http/ms15_034_http_sys_memory_dump |
| CVE-2011-1511 | Oracle GlassFish Server - Administration Console Authentication Bypass | ExploitDB |  17276 |
| CVE-2009-1979 | Oracle Database Server AUTH_SESSKEY Stack Buffer Overflow - Ver2 | MSF | exploit/windows/oracle/tns_auth_sesskey |
| CVE-2015-3306 | ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution | MSF |exploit/unix/ftp/proftpd_modcopy_exec |
| CVE-2010-0071 | Oracle Database CVE-2010-0071 Remote Listener Memory Corruption Vulnerability | GitRepo |CVE-2010-0071.py |
| CVE-2016-6662 | Oracle MySQL through 5.5.52, 5.6.x through 5.6.33, and 5.7.x through 5.7.15; MariaDB before 5.5.51, 10.0.x before 10.0.27, and 10.1.x before 10.1.17; and Percona Server before 5.5.51-38.1, 5.6.x before 5.6.32-78.0, and 5.7.x before 5.7.14-7 allow local users to create arbitrary configurations and bypass certain protection mechanisms by setting general_log_file to a my.cnf configuration. NOTE: this can be leveraged to execute arbitrary code with root privileges by setting malloc_lib. NOTE: the affected MySQL version information is from Oracle's October 2016 CPU. Oracle has not commented on third-party claims that the issue was silently patched in MySQL 5.5.52, 5.6.33, and 5.7.15. | GitRepo |CVE-2016-6662 (From SQL Injection To Root Shell, Network) |
| CVE-2009-1020 | The Network Foundation component in Oracle Database versions 9.2.0.8, 9.2.0.8DV, 10.1.0.5, 10.2.0.4, and 11.1.0.7 suffers from an unspecified vulnerability. Proof of concept code included. |GitRepo|CVE-2009-1020 (From PacketStormSecurity)|
|CVE-2015-5600|The kbdint_next_device function in auth2-chall.c in sshd in OpenSSH through 6.9 does not properly restrict the processing of keyboard-interactive devices within a single connection, which makes it easier for remote attackers to conduct brute-force attacks or cause a denial of service (CPU consumption) via a long and duplicative list in the ssh -oKbdInteractiveDevices option, as demonstrated by a modified client that provides a different password for each pam element on this list.|GitRepo|CVE-2015-5600.sh (From Network)|
|CVE-2016-6515|The auth_password function in auth-passwd.c in sshd in OpenSSH before 7.3 does not limit password lengths for password authentication, which allows remote attackers to cause a denial of service (crypt CPU consumption) via a long string.|GitRepo|CVE-2016-6515.py (Self-Written)|
| CVE-2016-6304 | Multiple memory leaks in t1_lib.c in OpenSSL before 1.0.1u, 1.0.2 before 1.0.2i, and 1.1.0 before 1.1.0a allow remote attackers to cause a denial of service (memory consumption) via large OCSP Status Request extensions. |GitRepo|CVE-2016-6304 (From PSS)|
||
||
||