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
quote-tdx:
	@go run github.com/flashbots/vault-auth-plugin-attest/cmd \
		quote --td-attestation-type tdx

.PHONY: vault
vault:
	@vault server \
		-dev \
		-dev-plugin-dir ./bin \
		-dev-root-token-id root \
		-dev-tls \
		-log-level debug

.PHONY: vault-enable-plugin
vault-enable-plugin: build
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
			auth/attest/tdx/test totp_secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

.PHONY: vault-configure-tdx-mrs
 vault-configure-tdx-mrs:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault write -tls-skip-verify \
			auth/attest/tdx/test \
				tdx_mr_td=XVYIDrnvjOC7r2vc2t7rBufFsKTR7Ba+hoqFqVO6vgxeVNAcjgUKVP4coHg3JTDS \
				tdx_rtmr0=VXM6iiMfT6GTTiJLWQDfEyqvMFJuA9r6D8AC1HQEdC1b1X30lPxB254Z7vCuUTrb \
				tdx_rtmr1=QKV//vF9S9irqJaav/3DvnzyrGVWSkr+zcstQoLjwZEbcd6pMIzCgOKvSybXW/ZV \
				tdx_rtmr2=v7K8YLrNv3NasPi7EJQr0MXeg+72+VXiAJOUysspfl7M6xO1g5N2ucv0/a2zhTpZ

.PHONY: vault-read-tdx
vault-read-tdx:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault read -tls-skip-verify \
			auth/attest/tdx/test

.PHONY: vault-list-tdx
vault-list-tdx:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault list -tls-skip-verify \
			auth/attest/tdx/

.PHONY: vault-delete-tdx
vault-delete-tdx:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault delete -tls-skip-verify \
			auth/attest/tdx/test

.PHONY: vault-fetch-nonce
vault-fetch-nonce:
	@VAULT_ADDR=https://127.0.0.1:8200 \
		vault write -tls-skip-verify \
			auth/attest/tdx/test/nonce totp_code=

.PHONY: vault-login-tdx
vault-login-tdx: build
	@VAULT_ADDR=https://127.0.0.1:8200 \
		go run github.com/flashbots/vault-auth-plugin-attest/cmd --tls-skip-verify  login \
				--td-attestation-type tdx \
				--td-totp-secret AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
			test
