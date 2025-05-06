# Lab Session: SAML + LDAP Hybrid Authentication

This lab demonstrates a hybrid authentication system using SAML and LDAP with Keycloak as the Identity Provider (IdP), Flask as the Service Provider (SP), and LDAP as the user directory.

## Overview
- **Keycloak**: SAML IdP configured with LDAP user federation.
- **LDAP**: User storage with a sample user.
- **Flask**: SAML SP that authenticates users via Keycloak.

## Prerequisites
- Docker and Docker Compose installed.
- Basic understanding of SAML, LDAP, and Docker.

## Project Structure
```
lab-saml-ldap/
├── docker-compose.yml
├── keycloak/
│   └── setup.sh
├── flask-app/
│   ├── Dockerfile
│   ├── app.py
│   └── requirements.txt
├── ldap/
│   └── users.ldif
├── Makefile
└── README.md
```

## Setup Instructions
1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd lab-saml-ldap
   ```

2. **Run the setup**:
   - Use the Makefile to automate the process:
     ```bash
     make all
     ```
   - This will build and start the containers, then configure Keycloak.

3. **Access the Flask application**:
   - Open `http://localhost:5000` in your browser.
   - Click "Login with SAML" to initiate the SAML authentication flow.

4. **Log in**:
   - Use the credentials:
     - Username: `testuser`
     - Password: `password123`
   - You should be redirected back to the Flask app with a welcome message.

## Makefile Targets
- **`make up`**: Build and start containers.
- **`make down`**: Stop and remove containers.
- **`make reset`**: Reset the environment (down and up).
- **`make logs`**: View container logs.
- **`make setup`**: Run Keycloak setup script.
- **`make all`**: Run `up` and `setup` for a complete setup.

## Troubleshooting
- **Containers not starting**: Check Docker logs with `make logs`.
- **Keycloak not accessible**: Ensure it's running at `http://localhost:8080`.
- **LDAP user not syncing**: Verify LDAP configuration in Keycloak.
- **SAML issues**: Check Flask and Keycloak logs for errors.

## Additional Resources
- [Keycloak Documentation](https://www.keycloak.org/docs/latest)
- [Python SAML Documentation](https://github.com/onelogin/python3-saml)
- [OpenLDAP Docker Image](https://github.com/osixia/docker-openldap)

