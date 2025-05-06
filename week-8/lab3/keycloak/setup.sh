#!/bin/bash

# Wait for Keycloak to be ready
until curl -s http://lab-keycloak:8080 >/dev/null; do
  echo "Waiting for Keycloak..."
  sleep 5
done

# Authenticate with Keycloak admin CLI
docker exec lab-keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user admin \
  --password admin123

# Create a new realm
docker exec lab-keycloak /opt/keycloak/bin/kcadm.sh create realms -s realm=LabRealm -s enabled=true

# Configure LDAP User Federation
docker exec lab-keycloak /opt/keycloak/bin/kcadm.sh create components -r LabRealm -s name=ldap -s providerId=ldap -s providerType=org.keycloak.storage.UserStorageProvider -s config.enabled=true -s config.connectionUrl=ldap://ldap:389 -s config.usersDn=ou=users,dc=lab,dc=org -s config.bindDn=cn=admin,dc=lab,dc=org -s config.bindCredential=admin123 -s config.usernameLDAPAttribute=uid -s config.rdnLDAPAttribute=uid -s config.uuidLDAPAttribute=entryUUID -s config.userObjectClasses=inetOrgPerson

# Create SAML client for Flask
docker exec lab-keycloak /opt/keycloak/bin/kcadm.sh create clients -r LabRealm -s clientId=flask-sp -s protocol=saml -s enabled=true -s 'redirectUris=["http://localhost:5000/saml/sso"]' -s adminUrl=http://flask-app:5000 -s baseUrl=http://localhost:5000

# Output SAML descriptor URL for manual download if needed
echo "Keycloak SAML Descriptor: http://localhost:8080/realms/LabRealm/protocol/saml/descriptor"
