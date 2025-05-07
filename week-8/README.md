# IAM Hands-On Labs (v2)

Prebuilt Docker labs for the *Identity & Access Management* guide.

## Usage

```bash
make lab13   # run Lifecycle SCIM lab
make clean   # shutdown all labs
```

## Lab Index

- **Lab 1 – OpenLDAP + Keycloak + SCIM** — `make lab1`
- **Lab 2 – Keycloak Federation with SimpleSAML** — `make lab2`
- **Lab 3 – LocalStack IRSA emulation** — `make lab3`
- **Lab 4 – ZITADEL + Postgres RLS** — `make lab4`
- **Lab 5 – Envoy + OPA ABAC** — `make lab5`
- **Lab 6 – Strata Hexa Orchestration** — `make lab6`
- **Lab 7 – Authelia + Caddy FIDO2** — `make lab7`
- **Lab 8 – OPA Zanzibar-style graph** — `make lab8`
- **Lab 9 – Falco + OPA adaptive authN** — `make lab9`
- **Lab 10 – step-ca short-lived certs** — `make lab10`
- **Lab 11 – Passkeys demo with WebAuthn.js** — `make lab11`
- **Lab 12 – Hyperledger Indy DID** — `make lab12`
- **Lab 13 – Automated provisioning & deprovisioning via SCIM and Terraform** — `make lab13`
- **Lab 14 – Authelia adaptive MFA & passwordless** — `make lab14`
- **Lab 15 – OPA + Cedar PBAC with JIT elevation** — `make lab15`
- **Lab 16 – Keycloak role hierarchies & SAML/OIDC SSO** — `make lab16`
- **Lab 17 – OpenLDAP ↔ Keycloak bidirectional sync** — `make lab17`