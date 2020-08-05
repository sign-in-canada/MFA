# MFA4ATIP Communication Connections

The table below lists all of the network connections that support communication
between the various components of the MFA4ATIP application. Connections listed as
"Node Local" support communication between software components that are running
on the same compute node (i.e. via the the localhost loopback network interface).

|Client|Server|Node Local?|Protocol|Encryption|Server Authentication|Client Authentication|Port|
|------|------|----------|---------|----------|---------------------|---------------------|----|
|User Web Browser|HTTP Reverse Proxy|No|HTTP|TLS|Yes|No|443|
|Sign In Canada Acceptance Platform|HTTP Reverse Proxy|No|HTTP|TLS|Yes|No|443|
|HTTP Reverse Proxy|OpenID Provider|Yes|HTTP|No|No|No|8081|
|HTTP Reverse Proxy|Administration Web Interface|Yes|HTTP|No|No|No|8082|
|OpenID Provider|NoSQL Database|No|memcached (data service)|TLS|yes|client secret|11207|
|OpenID Provider|NoSQL Database|No|REST (cluster administration)|TLS|yes|client secret|18091|
|OpenID Provider|NoSQL Database|No|REST (views and XDCR access)|TLS|yes|client secret|18092|
|OpenID Provider|NoSQL Database|No|REST (query service)|TLS|yes|client secret|18093|
