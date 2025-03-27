# IPSwamp Honeypot - Reportable Events Guide

This document explains what events are detected and reported as potential attacks by each honeypot module.

## SSH Honeypot Module

The SSH honeypot module reports the following events:

| Event Type            | Description                                           | Trigger Conditions                                                                |
| --------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------- |
| `PORT_SCAN`           | Quick SSH connections without authentication attempts | Connection established but closed within 5 seconds with no authentication attempt |
| `SSH_BRUTEFORCE`      | SSH login attempts                                    | Any authentication attempt                                                        |
| `SSH_COMMAND`         | Execution of commands via SSH exec                    | Command executed via SSH session after successful authentication                  |
| `SSH_SHELL_COMMAND`   | Commands entered in interactive SSH shell             | Any command entered in an interactive shell session                               |
| `SSH_BRUTEFORCE_SCAN` | Rapid connection attempts from same IP                | 10+ connection attempts from the same IP within 1 minute                          |

## HTTP Honeypot Module

The HTTP honeypot module reports the following events:

| Event Type              | Description                    | Trigger Conditions                                            |
| ----------------------- | ------------------------------ | ------------------------------------------------------------- |
| `SQL_INJECTION`         | SQL injection attempts         | Request with SQL injection patterns in parameters or body     |
| `COMMAND_INJECTION`     | Command injection attempts     | Request with command injection patterns in parameters or body |
| `XSS`                   | Cross-site scripting attempts  | Request with XSS patterns in parameters or body               |
| `PATH_TRAVERSAL`        | Directory traversal attempts   | Request with path traversal patterns in parameters            |
| `SUSPICIOUS_ENDPOINT`   | Access to suspicious endpoints | Request to admin panels, configuration pages, etc.            |
| `SUSPICIOUS_USER_AGENT` | Suspicious user agent strings  | Known scanner or attack tool user agents                      |
| `CREDENTIAL_HARVESTING` | Login attempts                 | Any submission to login forms                                 |

## FTP Honeypot Module

The FTP honeypot module reports the following events:

| Event Type               | Description             | Trigger Conditions                                            |
| ------------------------ | ----------------------- | ------------------------------------------------------------- |
| `FTP_LOGIN_ATTEMPT`      | FTP login attempts      | Any authentication attempt                                    |
| `FTP_SUSPICIOUS_COMMAND` | Suspicious FTP commands | Use of commands like DELE, RMD, STOR in sensitive directories |

## MySQL Honeypot Module

The MySQL honeypot module reports the following events:

| Event Type           | Description                   | Trigger Conditions                                    |
| -------------------- | ----------------------------- | ----------------------------------------------------- |
| `mysql_scan`         | Port scanning activity        | Very short connections with no authentication attempt |
| `mysql_bruteforce`   | MySQL authentication attempts | Multiple authentication attempts                      |
| `mysql_sqli_attempt` | SQL injection attempts        | Queries containing SQL injection patterns             |

## Mail Honeypot Modules

The mail honeypot modules (SMTP, POP3, IMAP) report the following events:

| Event Type                                                | Description              | Trigger Conditions                                              |
| --------------------------------------------------------- | ------------------------ | --------------------------------------------------------------- |
| `smtp_scan`, `pop3_scan`, `imap_scan`                     | Port scanning activity   | Very short connections with no/minimal commands                 |
| `smtp_auth_attempt`, `pop3_bruteforce`, `imap_bruteforce` | Authentication attempts  | Multiple authentication attempts                                |
| `smtp_spam_attempt`                                       | Spam email attempts      | Emails with spam characteristics                                |
| `email_harvesting`                                        | Email address harvesting | Multiple VRFY/EXPN commands or large number of RCPT TO commands |
| `smtp_relay_attempt`                                      | Mail relay attempts      | Many recipients across different domains                        |

## HTTPS Honeypot Module

The HTTPS honeypot module reports the following events:

| Event Type            | Description                       | Trigger Conditions                                    |
| --------------------- | --------------------------------- | ----------------------------------------------------- |
| `management_access`   | Management portal access attempts | Multiple requests to admin/management paths           |
| `admin_portal_access` | Admin login attempts              | Login attempts to the simulated admin portal          |
| `suspicious_request`  | Suspicious HTTPS requests         | Requests to unusual paths or with suspicious patterns |
