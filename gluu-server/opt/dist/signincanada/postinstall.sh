#!/bin/sh

echo 'Stopping services...'
systemctl stop httpd oxauth identity

echo 'Enabling the keyvault service...'
systemctl enable keyvault

echo 'Installing audit logging patch...'
pushd /opt/dist/gluu/patch > /dev/null 2>&1
zip -u /opt/gluu/jetty/oxauth/webapps/oxauth.war WEB-INF/classes/org/gluu/oxauth/audit/ApplicationAuditLogger.class
popd > /dev/null 2>&1

echo 'Installing the application insights SDK...'
install -m 644 -o jetty -g jetty /opt/dist/signincanada/applicationinsights-web-auto-2.6.1.jar /opt/gluu/jetty/oxauth/custom/libs

echo 'Updating Corretto...'
rm -f /opt/jre
rm -rf /opt/amazon-corretto-*
tar xf /opt/dist/corretto/amazon-corretto-8-x64-linux-jdk.tar.gz -C /opt
ln -s /opt/amazon-corretto-* /opt/jre

echo 'Installing the UI...'
tar xzf /opt/dist/signincanada/custom.tgz -C /opt/gluu/jetty/oxauth/custom
chown -R jetty:jetty /opt/gluu/jetty/oxauth/custom
chmod 755 $(find /opt/gluu/jetty/oxauth/custom -type d -print)
chmod 644 $(find /opt/gluu/jetty/oxauth/custom -type f -print)

echo "Configuring httpd chain certificate..."
sed -i "22i\ \ \ \ \ \ \ \ SSLCertificateChainFile /etc/certs/httpd.chain" /etc/httpd/conf.d/https_gluu.conf

echo 'Done.'
