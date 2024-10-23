VERSION := $(shell git describe --tags --always --dirty="-dev" --match "v*.*.*" 2>/dev/null || echo "v0.0.0" )

.PHONY: build
build:
	@mkdir -p ./bin
	@CGO_ENABLED=0 go build \
			-ldflags "-X main.version=${VERSION}" \
			-o ./bin/vault-auth-plugin-attest \
		github.com/flashbots/vault-auth-plugin-attest/cmd

.PHONY: snapshot
snapshot:
	@goreleaser release --snapshot --clean

.PHONY: help
help:
	@go run github.com/flashbots/vault-auth-plugin-attest/cmd \
		login --help

.PHONY: plugin
plugin:
	@go run github.com/flashbots/vault-auth-plugin-attest/cmd

.PHONY: quote-tdx
quote-tdx: build
	@bin/vault-auth-plugin-attest \
		quote --td-attestation-type tdx

.PHONY: quote-tpm2
quote-tpm2: build
	@bin/vault-auth-plugin-attest \
		quote --td-attestation-type tpm2

.PHONY: vault
vault: build
	@vault server \
		-dev \
		-dev-plugin-dir ./bin \
		-dev-root-token-id root \
		-dev-tls \
		-log-level debug

.PHONY: vault-enable-plugin
vault-enable-plugin:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault login -tls-skip-verify \
			-no-print root

	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault auth enable -tls-skip-verify \
			-path=attest vault-auth-plugin-attest

.PHONY: vault-configure-tdx
vault-configure-tdx:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault write -tls-skip-verify \
			auth/attest/tdx/test totp_secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB

.PHONY: vault-configure-tpm2
vault-configure-tpm2:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault write -tls-skip-verify \
			auth/attest/tpm2/test \
				totp_secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB \
				tpm2_ak_public=AAEACwAFBHIAAAAQABQACwgAAAAAAAEAyu13GNxpWKvQxvFAMZg06yBsTtHVTFygGItu0GS1pFMs7Erzv80lhfCdM3atgvO9du8ruwYstIGm0sHezUR/jjogvoxsFPKte19bZJ4ojQ+D/6FHF5GalsLxbsyy93GCVbrCYrr9xmaIWR/nsH1YucA6Rn/vLxAEwaGc3QUUh9UkUtKwzXUmVz0yV62/bfRNudo6DKEmxAORaCTreK8FuYv3zFG95v0q5YYNF4wXicmgnO5bLNz1T1tcKqhabzwekR4QdnzkmXbtTQdynri2w2xru2FQ3WKXoE1qcKJgwBbtX5CbZuspkBU4ZKkOyRYBealz89o90zODsW58VTE3jw==

.PHONY: vault-configure-tdx-mrs
 vault-configure-tdx-mrs:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault write -tls-skip-verify \
			auth/attest/tdx/test \
				tdx_mr_td=XVYIDrnvjOC7r2vc2t7rBufFsKTR7Ba+hoqFqVO6vgxeVNAcjgUKVP4coHg3JTDS \
				tdx_rtmr0=VXM6iiMfT6GTTiJLWQDfEyqvMFJuA9r6D8AC1HQEdC1b1X30lPxB254Z7vCuUTrb \
				tdx_rtmr1=jcKdw+at1QfkGRY0lRMokD8/cK61C9fS2ZYQqFMmFle1WnTOfHwL5CcA17ZexwJK \
				tdx_rtmr2=""

.PHONY: vault-configure-tpm2-pcrs
vault-configure-tpm2-pcrs:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault write -tls-skip-verify \
			auth/attest/tpm2/test \
				tpm2_pcr00=DMqewWGwkoiALloRIlXSE0DtW3l/X+Kc7Mz9j2e5+AI= \
				tpm2_pcr01=WYFW4Z2Q0aezq9Yqod5frqxSJqsWLH8PW/hGhbPxkZU=

.PHONY: vault-read-tdx
vault-read-tdx:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault read -tls-skip-verify \
			auth/attest/tdx/test

.PHONY: vault-read-tpm2
vault-read-tpm2:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault read -tls-skip-verify \
			auth/attest/tpm2/test

.PHONY: vault-list-tdx
vault-list-tdx:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault list -tls-skip-verify \
			auth/attest/tdx/

.PHONY: vault-list-tpm2
vault-list-tpm2:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault list -tls-skip-verify \
			auth/attest/tpm2/

.PHONY: vault-delete-tdx
vault-delete-tdx:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault delete -tls-skip-verify \
			auth/attest/tdx/test

.PHONY: vault-delete-tpm2
vault-delete-tpm2:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault delete -tls-skip-verify \
			auth/attest/tpm2/test

.PHONY: vault-fetch-nonce
vault-fetch-nonce:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault write -tls-skip-verify \
			auth/attest/tdx/test/nonce totp_code=

.PHONY: vault-login-tdx
vault-login-tdx: build
	@VAULT_ADDR=https://127.0.0.1:8200 \
		bin/vault-auth-plugin-attest --tls-skip-verify  login \
				--td-attestation-type tdx \
				--td-totp-secret AAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB \
			test

.PHONY: vault-login-tpm2
vault-login-tpm2: build
	@VAULT_ADDR=https://127.0.0.1:8200 \
		bin/vault-auth-plugin-attest --tls-skip-verify login \
				--td-attestation-type tpm2 \
				--td-totp-secret AAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB \
				--td-tpm2-ak-private-blob eyJLZXlFbmNvZGluZyI6MiwiVFBNVmVyc2lvbiI6MiwiUHVibGljIjoiQUFFQUN3QUZCSElBQUFBUUFCUUFDd2dBQUFBQUFBRUF5dTEzR054cFdLdlF4dkZBTVpnMDZ5QnNUdEhWVEZ5Z0dJdHUwR1MxcEZNczdFcnp2ODBsaGZDZE0zYXRndk85ZHU4cnV3WXN0SUdtMHNIZXpVUi9qam9ndm94c0ZQS3RlMTliWko0b2pRK0QvNkZIRjVHYWxzTHhic3l5OTNHQ1ZickNZcnI5eG1hSVdSL25zSDFZdWNBNlJuL3ZMeEFFd2FHYzNRVVVoOVVrVXRLd3pYVW1WejB5VjYyL2JmUk51ZG82REtFbXhBT1JhQ1RyZUs4RnVZdjN6Rkc5NXYwcTVZWU5GNHdYaWNtZ25PNWJMTnoxVDF0Y0txaGFiendla1I0UWRuemttWGJ0VFFkeW5yaTJ3MnhydTJGUTNXS1hvRTFxY0tKZ3dCYnRYNUNiWnVzcGtCVTRaS2tPeVJZQmVhbHo4OW85MHpPRHNXNThWVEUzanc9PSIsIkNyZWF0ZURhdGEiOiJBQUFBQUFBZzQ3REVRcGo4SEJTYSsvVEltVys1SkNldVFlUmttNU5NcEpXWkczaFN1RlVCQUFzQUlnQUw5SFFoVUp5RXZHN1ppaGEvZW5hMElaUUk4SnUzQ29ubVVDcDVzM00zVEZBQUlnQUxHS2ZFdnR2VDJwZytWcm4vdDQzVmxQV3FQMDNnYkpTOVpEc2pzbTA3TTBJQUFBPT0iLCJDcmVhdGVBdHRlc3RhdGlvbiI6Ii8xUkRSNEFhQUNJQUMxSzJndVVaazhKZXEzTFJiejZZcS8zc2VXaW82ZjUxbCtQb0RVUTJ6MUluQUFBQUFBQUFacGlpSDFuZDJXdlZ1Q3NGQVEzTWpPVzF3K1pjQUNJQUMvZDFCTEFHZW02Nkh2Wm5CR3Q3a0pqcjAyTms2VFBhVmlMRFg0SVFuUnB6QUNBY1NOVGw0dFRYdW1aSG5QOTJ5cnRmTit4bmE2KzBZZlJpTEEvZXV0SFpDdz09IiwiQ3JlYXRlU2lnbmF0dXJlIjoiQUJRQUN3RUFQSGdLb1VHU1VjUnBOdDc5Z0lJeWt0bGU1WElhL25LeitHNEpuU3RFdHRQRFlRWVF1V2VwWnRmWThNelAxT2F3d1FxQUF3ZGtySWZjN2tQMU91OWIzVTNCVnBpYUFnRFNKbFg0NVVNc2tGSmdQV216bUk4dVY1SmJUNHMvR0Q3Ukx3RmhGaGxyM2Uwb2N1bDhrWUk5QlRRdUo2YnFWOXhlU0t2NmVFV2NmRUQ0NlFBWjZia2xaeUxXeDg5N0xRT2RiaDh4QitXdVhCZmo0aXRBemFZVDZwSmlGNWVNZkY3LzdKMUUxRU5aWUtDcWNVWitjR0tPaS9iQUlZc3NvV2RUbFhjYjhoMFNsWXE4aWJZd1dRMFRRZXl0L3Vtcm9EMll1dDV0aktyZ2htUy8vWWVCbGw5b2l1MEkwdVExajc2Z3pUeHZRak4zUTBiUlQ5Zm15TDZmOUE9PSIsIk5hbWUiOiIiLCJLZXlCbG9iIjoiQUNENzRFQWRWS2kySEwxYmx5Ny80czQxUG1CRU9Oemd4M3l1bVBhc3RZMUZNd0FRZlB6K1U2RDdmWXRlL01HY1BPelAycUdNUzFTNFJQMW9CYlZ3RDNVU2hhZVd4c1VSUk5rMjNQVXVXT1ZzQllzSFZacXozMjRta0VueWdpa2hwQk9jTm1ienJ1cWFjNHdmdDEyRHdzMVhwQ3hFZzFXaTVkM05MbzBiQmJHQVVna2IxMXkvVWR1N1BCSmtNZlo3aUQvWnRHTkdGYWd0N2RWL244WndPdndHaHBkektzd3BlS0pKbkpjNzJmSzA5V3NZclZRc29WRVdyRWU2eGRFY1pZMGhKbjExUGNiUlJnU1ZVQWF3dURsL255U0oxRWZqczhWam1XaW8ifQ== \
			test
