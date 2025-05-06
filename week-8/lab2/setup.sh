#!/bin/bash

set -e

# Step 1: Start containers
printf "[*] Starting containers...\n"
docker compose up -d --build

# Step 2: Wait for Keycloak to be up
KEYCLOAK_URL="http://localhost:8080"
RETRIES=30
until curl -sf $KEYCLOAK_URL || [ $RETRIES -eq 0 ]; do
  echo "Waiting for Keycloak..."
  sleep 3
  RETRIES=$((RETRIES - 1))
done

if [ $RETRIES -eq 0 ]; then
  echo "[!] Keycloak did not become ready in time. Exiting."
  exit 1
fi

# Step 3: Configure Keycloak using kcadm.sh
printf "[*] Configuring Keycloak...\n"

KEYCLOAK_ADMIN_USER="admin"
KEYCLOAK_ADMIN_PASS="admin"
KEYCLOAK_CONTAINER=$(docker ps --filter "ancestor=quay.io/keycloak/keycloak:latest" --format "{{.Names}}")

if [ -z "$KEYCLOAK_CONTAINER" ]; then
  echo "[!] Keycloak container not found. Exiting."
  exit 1
fi

# Step 4: Ensure fixed ldap-config.json
cat > ldap-config.json <<EOF
{
  "name": "ldap",
  "providerId": "ldap",
  "providerType": "org.keycloak.storage.UserStorageProvider",
  "config": {
    "editMode": ["READ_ONLY"],
    "enabled": ["true"],
    "vendor": ["other"],
    "connectionUrl": ["ldap://lab2-ldap-1:389"],
    "usersDn": ["dc=example,dc=org"],
    "authType": ["simple"],
    "bindDn": ["cn=admin,dc=example,dc=org"],
    "bindCredential": ["admin"],
    "userObjectClasses": ["inetOrgPerson, organizationalPerson"],
    "searchScope": ["1"],
    "usernameLDAPAttribute": ["uid"],
    "rdnLDAPAttribute": ["uid"],
    "uuidLDAPAttribute": ["entryUUID"],
    "userEnabledAttribute": ["userAccountControl"],
    "pagination": ["true"],
    "allowKerberosAuthentication": ["false"],
    "syncRegistrations": ["false"],
    "trustEmail": ["true"],
    "importEnabled": ["true"]
  }
}
EOF

# Step 4.1: Create sample LDAP user LDIF
cat > sample-user.ldif <<EOF
dn: uid=jdoe,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
uid: jdoe
userPassword: password
mail: jdoe@example.org
EOF

# Step 4.2: Copy sample user to ldap container and import
LDAP_CONTAINER=$(docker ps --filter "ancestor=osixia/openldap:1.5.0" --format "{{.Names}}")
docker cp sample-user.ldif $LDAP_CONTAINER:/tmp/sample-user.ldif || true
docker exec $LDAP_CONTAINER ldapadd -x -D "cn=admin,dc=example,dc=org" -w admin -f /tmp/sample-user.ldif || echo "[!] Failed to bind to LDAP and add sample user."

# Step 4.3: Write corrected saml-client.json
cat > saml-client.json <<EOF
{
  "clientId": "flask-saml-sp",
  "protocol": "saml",
  "name": "Flask SAML SP",
  "enabled": true,
  "attributes": {
    "saml.assertion.signature": "false",
    "saml.force.post.binding": "true",
    "saml.authnstatement": "true",
    "saml_force_name_id_format": "true",
    "saml_name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    "saml.encrypt": "false",
    "saml.multivalued.roles": "false"
  },
  "adminUrl": "http://app:5000",
  "redirectUris": ["http://app:5000/*"],
  "baseUrl": "http://app:5000",
  "rootUrl": "http://app:5000",
  "protocolMappers": [
    {
      "name": "username",
      "protocol": "saml",
      "protocolMapper": "saml-user-property-mapper",
      "consentRequired": false,
      "config": {
        "user.attribute": "username",
        "friendly.name": "username",
        "attribute.name": "username",
        "attribute.nameformat": "Basic"
      }
    },
    {
      "name": "email",
      "protocol": "saml",
      "protocolMapper": "saml-user-property-mapper",
      "consentRequired": false,
      "config": {
        "user.attribute": "email",
        "friendly.name": "email",
        "attribute.name": "email",
        "attribute.nameformat": "Basic"
      }
    }
  ]
}
EOF

# Copy configs into container
docker cp ldap-config.json $KEYCLOAK_CONTAINER:/tmp/ldap-config.json
docker cp saml-client.json $KEYCLOAK_CONTAINER:/tmp/saml-client.json

# Authenticate with Keycloak
docker exec $KEYCLOAK_CONTAINER /opt/keycloak/bin/kcadm.sh config credentials \
  --server $KEYCLOAK_URL \
  --realm master \
  --user $KEYCLOAK_ADMIN_USER \
  --password $KEYCLOAK_ADMIN_PASS

# Step 5: Create Realm
REALM="FintechApp"
REALM_EXISTS=$(docker exec $KEYCLOAK_CONTAINER /opt/keycloak/bin/kcadm.sh get realms | jq -r ".[] | select(.realm==\"$REALM\") | .realm")

if [ "$REALM_EXISTS" != "$REALM" ]; then
  docker exec $KEYCLOAK_CONTAINER /opt/keycloak/bin/kcadm.sh create realms -s realm=$REALM -s enabled=true
fi

REALM_ID=$(docker exec $KEYCLOAK_CONTAINER /opt/keycloak/bin/kcadm.sh get realms | jq -r ".[] | select(.realm==\"$REALM\") | .id")

if [ -z "$REALM_ID" ] || [ "$REALM_ID" == "null" ]; then
  echo "[!] Failed to retrieve internal realm ID. Exiting."
  exit 1
fi

# Step 6: Create LDAP User Federation
if ! docker exec $KEYCLOAK_CONTAINER /opt/keycloak/bin/kcadm.sh get components -r $REALM | grep -q ldap; then
  docker exec $KEYCLOAK_CONTAINER /opt/keycloak/bin/kcadm.sh create components -r $REALM -f /tmp/ldap-config.json
fi

# Step 7: Create SAML Client
CLIENT_ID="flask-saml-sp"
if ! docker exec $KEYCLOAK_CONTAINER /opt/keycloak/bin/kcadm.sh get clients -r $REALM | jq -e ".[] | select(.clientId == \"$CLIENT_ID\")" > /dev/null; then
  docker exec $KEYCLOAK_CONTAINER /opt/keycloak/bin/kcadm.sh create clients -r $REALM -f /tmp/saml-client.json
fi

# Step 8: Automated test of login endpoint
printf "[*] Verifying login page is reachable...\n"
if curl -sSf http://localhost:15001/sso/login | grep -q "<form"; then
  echo "[✓] Login page is accessible."
else
  echo "[✗] Login page failed to load."
  echo "[*] Suggestion: Enable debug mode in Flask app to trace error."
fi

printf "[*] Setup complete. Verify: http://localhost:15001/sso/metadata\n"
# Done
