# MFA4ATIP Software

## Software Components

MFA4ATIP is implemented using [Gluu Server](https://www.gluu.org/products/), a container distribution of open source software for identity and access management (IAM). The MFA4ATIP application architecture consists of the following 4 software components:

### HTTP Reverse Proxy

Product: Apache HTTP Server

The Apache HTTP Server is a secure, efficient and extensible server that provides HTTP services in sync with the current HTTP standards.

MFA4ATIP uses the Apache HTTP Server as a reverse proxy, accepting all incoming HTTP requests and routing them to the appropriate web application (oxAuth or oxTrust).

Version: 2.4.6

Website: https://httpd.apache.org/

Source code: https://github.com/apache/httpd/

### OpenID Provider

Product: oxAuth

oxAuth is an open source [OpenID Connect](https://openid.net/connect/) Provider
(OP) and [UMA](https://kantarainitiative.org/confluence/display/uma/Home)
Authorization Server (AS).

oxAuth is the core component of MFA4ATIP, responsible for the user interface
and business logic. As an [OpenID Connect](https://openid.net/connect/)
Provider, it also provides the application programming interface used by the
Sign In Canada Acceptance Platform to integrate using [OpenID
Connect](https://openid.net/connect/).

Version: 4.1

Website: https://www.gluu.org/

Source code: https://github.com/GluuFederation/oxAuth/

### Administration Web Interface

Product: oxTrust

oxTrust is a Weld based web application for Gluu Server administration.

oxTrust enables administrators to manage what information about people is being
exposed to partner websites. oxTrust is also the local management interface that
handles other server instance specific configurations, and provides a mechanism
for IT administrators to support people at the organization who are having
trouble accessing a website or network resource.

When MFA4ATIP is first installed, oxTrust is used to configure the OpenID
Connect integration with Sign In Canada Acceptance Platform. Once the
integration is configured, oxTrust is no longer needed and can be uninstalled.

Version: 4.1

Website: https://www.gluu.org/

Source code: https://github.com/GluuFederation/oxTrust/

### NoSQL Database

Product: Couchbase Enterprise Server

Couchbase Server is an open-source, distributed, multi-model NoSQL
document-oriented database software package that is optimized for interactive
applications.

MFA4ATIP uses a Couchbase database to store and manage configuration settings,
as well as user accounts.

Version: 6.5

Website: https://www.couchbase.com/

Source code: https://github.com/couchbase/

## System Software

### Application Server

Product: Jetty

Both the OpenID Provider oxAuth and the Administration Web Interface oxTrust are
built using the Java 2 Enterprise Edition (J2EE) [Servlet] standard. Jetty is the
HTTP server and Servlet container used to run both these applications.

Version: 9.4

Website: https://www.eclipse.org/jetty/

Source Code: https://github.com/eclipse/jetty.project/

### Operating System

Product: Red Hat Enterprise Linux

Red Hat Enterprise Linux is a Linux distribution developed by Red Hat for the commercial market.

Version: 7.8

Website: https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux/

Source Code: https://access.redhat.com/downloads/
