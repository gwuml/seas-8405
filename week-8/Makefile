SHELL := /bin/bash


lab1:
	cd centralized-iam-lab && docker compose up -d


stop1:
	cd centralized-iam-lab && docker compose down -v


lab2:
	cd federated-iam-lab && docker compose up -d


stop2:
	cd federated-iam-lab && docker compose down -v


lab3:
	cd cloudnative-iam-lab && docker compose up -d


stop3:
	cd cloudnative-iam-lab && docker compose down -v


lab4:
	cd multitenant-iam-lab && docker compose up -d


stop4:
	cd multitenant-iam-lab && docker compose down -v


lab5:
	cd zerotrust-iam-lab && docker compose up -d


stop5:
	cd zerotrust-iam-lab && docker compose down -v


lab6:
	cd identity-fabric-lab && docker compose up -d


stop6:
	cd identity-fabric-lab && docker compose down -v


lab7:
	cd passwordless-webauthn-lab && docker compose up -d


stop7:
	cd passwordless-webauthn-lab && docker compose down -v


lab8:
	cd graph-policy-lab && docker compose up -d


stop8:
	cd graph-policy-lab && docker compose down -v


lab9:
	cd ai-anomaly-lab && docker compose up -d


stop9:
	cd ai-anomaly-lab && docker compose down -v


lab10:
	cd pki-mutual-tls-lab && docker compose up -d


stop10:
	cd pki-mutual-tls-lab && docker compose down -v


lab11:
	cd mobile-passkeys-lab && docker compose up -d


stop11:
	cd mobile-passkeys-lab && docker compose down -v


lab12:
	cd did-lab && docker compose up -d


stop12:
	cd did-lab && docker compose down -v


lab13:
	cd lifecycle-scim-lab && docker compose up -d


stop13:
	cd lifecycle-scim-lab && docker compose down -v


lab14:
	cd adaptive-mfa-lab && docker compose up -d


stop14:
	cd adaptive-mfa-lab && docker compose down -v


lab15:
	cd pbac-jit-lab && docker compose up -d


stop15:
	cd pbac-jit-lab && docker compose down -v


lab16:
	cd role-sso-lab && docker compose up -d


stop16:
	cd role-sso-lab && docker compose down -v


lab17:
	cd directory-sync-lab && docker compose up -d


stop17:
	cd directory-sync-lab && docker compose down -v


clean:
	for d in $(shell ls -d */ | tr -d /); do cd $$d && docker compose down -v || true; cd ..; done
