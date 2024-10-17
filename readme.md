# vault-auth-plugin-attest

Vault plugin for attested authentication.

Same binary can be used as a plugin, and as a login-helper tool with CLI similar
to the native Vault's CLI.

## TL;DR

- Make sure vault is [installed](https://developer.hashicorp.com/vault/docs/install).

- Make sure you run this on the TDX VM (the attestation won't work otherwise).

- Start vault in development mode:

    ```shell
    make vault
    ```

    ```text
    WARNING! dev mode is enabled! In this mode, Vault runs entirely in-memory
    and starts unsealed with a single unseal key. The root token is already
    authenticated to the CLI, so you can immediately begin using Vault.

    You may need to set the following environment variables:

        $ export VAULT_ADDR='https://127.0.0.1:8200'
        $ export VAULT_CACERT='/tmp/vault-tls2386973238/vault-ca.pem'


    The unseal key and root token are displayed below in case you want to
    seal/unseal the Vault or re-authenticate.

    Unseal Key: gSTqCSgHTRftevffJFE/f+vHPJR2UeX8cP/3wn5Zsc4=
    Root Token: root

    The following dev plugins are registered in the catalog:
        - vault-auth-plugin-attest

    Development mode should NOT be used in production installations!
    ```

- Enable vault-auth-plugin-attest plugin:

    ```shell
    make vault-enable-plugin
    ```

    ```text
    Success! Enabled vault-auth-plugin-attest auth method at: attest/
    ```

- Configure "test" TDX trusted domain with a dummy TOTP secret:

    ```shell
    make vault-configure-tdx
    ```

    ```text
    Key                          Value
    ---                          -----
    tdx_check_debug              true
    tdx_check_sept_ve_disable    true
    token_bound_cidrs            []
    token_explicit_max_ttl       0s
    token_max_ttl                0s
    token_no_default_policy      false
    token_num_uses               0
    token_period                 0s
    token_policies               []
    token_ttl                    0s
    token_type                   default
    totp_secret                  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    ```

- Add some actual checks to verify:

    (strictly speaking the above step could have been merged with this one)

    ```shell
    make vault-configure-tdx-mrs
    ```

    ```text
    Key                          Value
    ---                          -----
    tdx_check_debug              true
    tdx_check_sept_ve_disable    true
    tdx_mr_td                    XVYIDrnvjOC7r2vc2t7rBufFsKTR7Ba+hoqFqVO6vgxeVNAcjgUKVP4coHg3JTDS
    tdx_rtmr0                    VXM6iiMfT6GTTiJLWQDfEyqvMFJuA9r6D8AC1HQEdC1b1X30lPxB254Z7vCuUTrb
    tdx_rtmr1                    QKV//vF9S9irqJaav/3DvnzyrGVWSkr+zcstQoLjwZEbcd6pMIzCgOKvSybXW/ZV
    tdx_rtmr2                    v7K8YLrNv3NasPi7EJQr0MXeg+72+VXiAJOUysspfl7M6xO1g5N2ucv0/a2zhTpZ
    token_bound_cidrs            []
    token_explicit_max_ttl       0s
    token_max_ttl                0s
    token_no_default_policy      false
    token_num_uses               0
    token_period                 0s
    token_policies               []
    token_ttl                    0s
    token_type                   default
    ```

    > [!IMPORTANT]
    >
    > The measurements on your VM will probably differ (which is the whole point).

- Login with the attestation quote:

    ```shell
    make vault-login-tdx
    ```

    ```text
    Success! You are now authenticated. The token information displayed
    below is already stored in the token helper. You do NOT need to login
    again. Future Vault requests will automatically use this token.

    Key                  Value
    ---                  -----
    token                hvs.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    token_accessor       XXXXXXXXXXXXXXXXXXXXXXXX
    token_duration       768h
    token_renewable      true
    token_policies       ["default"]
    identity_policies    []
    policies             ["default"]
    token_meta_tdx       test
    ```

    > [!IMPORTANT]
    >
    > The CLI helper is using `/dev/tdx_guest` device that should be available
    > in the TD VM. Make sure necessary packages/drivers are installed. Also,
    > the permissions will most likely require `root` access.

- Stir some things:

    ```shell
    apt-get upgrade --yes
    reboot now
    ```

- Try to re-login:

    ```shell
    make vault-login-tdx
    ```

    ```text
    Failed with error:

    failed to fetch tdx-attested token: Error making API request.

    URL: PUT https://127.0.0.1:8200/v1/auth/attest/tdx/test/login
    Code: 400. Errors:

    * failed to validate tdx quote
    ```

    At the same time, in Vault's logs:

    ```text
    failed to validate tdx quote: domain=test error="2 errors occurred: rtmr[1] mismatch; rtmr[2] mismatch"
    ```

## Login workflow

- Trusted domain is pre-configured with TOTP secret that's shared between the TD
  and Vault.

- Firstly, the TD will request a nonce from Vault by providing it with TOTP code
  that is generated with the use of that shared secret.

- If the TOTP code is valid and wasn't used before, Vault will issue a nonce
  with limited validity period.

- Upon receipt of the nonce, the TD will wait until the next TOTP code can be
  generated, produce the attestation quote that incorporates the nonce issued by
  Vault, and request the authentication token from Vault by providing it with
  the 2nd TOTP code _and_ the attestation quote.

- Vault then will verify the validity of the TOTP code, validate the
  attestation quote, and verify that it's measurements do match the values
  pre-configured in Vault.
