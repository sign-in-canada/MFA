#!/bin/sh

echo 'Stopping services...'
systemctl stop httpd oxauth identity

echo 'Enabling the keyvault service...'
systemctl enable keyvault

echo 'Installing the application insights SDK...'
install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-web-auto-2.5.1.jar /opt/gluu/jetty/oxauth/custom/libs

echo 'Installing the UI...'
tar xzf /opt/dist/signincanada/custom.tgz -C /opt/gluu/jetty/oxauth/custom
chown -R jetty:jetty /opt/gluu/jetty/oxauth/custom
chmod 755 $(find /opt/gluu/jetty/oxauth/custom -type d -print)
chmod 644 $(find /opt/gluu/jetty/oxauth/custom -type f -print)

echo "Configuring httpd chain certificate..."
sed -i "17i\ \ \ \ \ \ \ \ SSLCertificateChainFile /etc/certs/httpd.chain" /etc/httpd/conf.d/https_gluu.conf

echo 'Done.'
echo
echo 'To complete configuration...'
echo '  1) edit the keyvault name in /etc/default/azure'
echo '  2) log out and restart the container'
