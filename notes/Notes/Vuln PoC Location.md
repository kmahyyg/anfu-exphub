# Vuln Scanner

This note is used to check if the vulnerbility detected by scanner via version fingerprinting, fast locate the PoC/EXP location.

| CVE / SRC No.  | Vuln Name | PoC Software | PoC Location |
|:-----------:|:---------------:|:--------------:|:-------------:|
| MS15-034 | HTTP.sys Could Allow Remote Code Execution | MSF | auxiliary/scanner/http/ms15_034_http_sys_memory_dump |
| CVE-2011-1511 | Oracle GlassFish Server - Administration Console Authentication Bypass | ExploitDB |  17276 |
| CVE-2009-1979 | Oracle Database Server AUTH_SESSKEY Stack Buffer Overflow - Ver2 | MSF | exploit/windows/oracle/tns_auth_sesskey |
| CVE-2015-3306 | ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution | MSF |exploit/unix/ftp/proftpd_modcopy_exec |
| CVE-2010-0071 | Oracle Database CVE-2010-0071 Remote Listener Memory Corruption Vulnerability | GitRepo |CVE-2010-0071.py |
| CVE-2016-6662 | Oracle MySQL through 5.5.52, 5.6.x through 5.6.33, and 5.7.x through 5.7.15; MariaDB before 5.5.51, 10.0.x before 10.0.27, and 10.1.x before 10.1.17; and Percona Server before 5.5.51-38.1, 5.6.x before 5.6.32-78.0, and 5.7.x before 5.7.14-7 allow local users to create arbitrary configurations and bypass certain protection mechanisms by setting general_log_file to a my.cnf configuration. NOTE: this can be leveraged to execute arbitrary code with root privileges by setting malloc_lib. NOTE: the affected MySQL version information is from Oracle's October 2016 CPU. Oracle has not commented on third-party claims that the issue was silently patched in MySQL 5.5.52, 5.6.33, and 5.7.15. | GitRepo |CVE-2016-6662 (From SQL Injection To Root Shell) |
|               |                                                              |||

