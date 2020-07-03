# Vuln Scanner

This note is used to check if the vulnerbility detected by scanner via version fingerprinting but not have any PoC or EXP.

|Severity|CVE No.|Name|
|:-------:|:-------:|:------:|
|High|CVE-2016-2108|The ASN.1 implementation in OpenSSL before 1.0.1o and 1.0.2 before 1.0.2c allows remote attackers to execute arbitrary code or cause a denial of service (buffer underflow and memory corruption) via an ANY field in crafted serialized data, aka the "negative zero" issue.|
|High|CVE-2016-2842|OpenSSL 'crypto/bio/b_print.c' Denial of Service Vulnerability|
|High|CVE-2016-0705|OpenSSL Double-free in DSA code|
|High|CVE-2016-0799|The fmtstr function in crypto/bio/b_print.c in OpenSSL 1.0.1 before 1.0.1s and 1.0.2 before 1.0.2g improperly calculates string lengths, which allows remote attackers to cause a denial of service (overflow and out-of-bounds read) or possibly have unspecified other impact via a long string, as demonstrated by a large amount of ASN.1 data, a different vulnerability than CVE-2016-2842.|
|   High   | CVE-2016-0639 | Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier and 5.7.11 and earlier allows remote attackers to affect confidentiality, integrity, and availability via vectors related to Pluggable Authentication. |
|   High   | CVE-2016-0499 | Unspecified vulnerability in the Java VM component in Oracle Database Server 11.2.0.4, 12.1.0.1, and 12.1.0.2 allows remote authenticated users to affect confidentiality, integrity, and availability via unknown vectors, a different vulnerability than CVE-2015-4794. |

