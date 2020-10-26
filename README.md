# vault-plugin-secrets-oauth-client-credentials

This is a standalone secrets engine plugin for use with [Hashicorp
Vault](https://www.github.com/hashicorp/vault).

This plugin provides a secure wrapper around OAuth 2 authorization client credentials grant, also know as 2-legged OAuth which does not require authorization.  
Client credentials grant is used by clients to obtain an access token outside of the context of a user.  This is typically used by clients to access resources about themselves rather than to access a user's resources.

## Usage

Download plugin's binary and [register the plugin with Vault](https://www.vaultproject.io/docs/internals/plugins.html#plugin-registration). 
Usually you register the plugin with the following commands.

```console
$ vault write sys/plugins/catalog/secret/oauthapp \
    sha256=<calculated_sha256_hash> \
    command=vault-plugin-secrets-oauth-client-credentials
```

We will assume it is registered under the name
`oauthapp`.

Mount the plugin at the path of your choosing:

```console
$ vault secrets enable -path=oauth2/my-provider oauthapp
Success! Enabled the oauthapp secrets engine at: oauth2/my-provider/
```

Configure it with the necessary information to exchange tokens. Token URL shall point to an endpoint for obtaining tokens from your provider (it usually ends with `/token`).

```console
$ vault write oauth2/my-provider/config \
    client_id=hOEvqqbHVlSNpuvY \
    client_secret=6q2xrjZOJ1R9MfUvUxJzFAk \
    token_url=https://example.com/token \
    scopes=read.user,read.org
Success! Data written to: oauth2/my-provider/config
```

Once the client secret has been written, it will never be exposed again.

To retrieve a token, read from the `/creds/:name` endpoint. The `name` identifier can be any arbitrary string.

```console
$ vault read oauth2/my-provider/creds/my-user
Key             Value
---             -----
access_token    RRcJk5r2BBUKsIquXaoVJfnSUX6uTkVReSaEthrgJmd8p9xlWPD0d0ADFgW5p6Glki5UNGEBGr6hWCEu
expires         2020-10-25T13:43:56.6282713+01:00
```

You can override default scopes by specifying `scopes` parameter. This returns a new token with a new scope.
```console
$ vault read oauth2/my-provider/creds/my-user scopes=write.user,write.org
Key             Value
---             -----
access_token    vy7f9quvazKypM4FJ4WQMLCHkUEcDb2Z3ZifSWMi94Ur40Z3xf13dOj6Cydkp7vdoNRLQD2eOMFy0r2L
expires         2020-10-25T13:44:07.1123581+01:00
```

The client secret is never exposed to Vault clients.


## Endpoints

### `config`

#### `GET` (`read`)

Retrieve the current configuration settings (except the client secret).

#### `PUT` (`write`)

Write new configuration settings. This endpoint completely replaces the existing
configuration.

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `client_id` | The OAuth 2.0 client ID. | String | None | Yes |
| `client_secret` | The OAuth 2.0 client secret. | String | None | Yes |
| `token_url` | URL to obtain access tokens. | String | None | Yes |
| `scopes` | Comma separated list of default explicit scopes. | List of String | None | No |

#### `DELETE` (`delete`)

Remove the current configuration. This does not invalidate any existing access
tokens.

### `creds/:name`

#### `GET` (`read`)

Retrieve a current access token for the given credential.

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `scopes` | A comma separated list of explicit scopes to override default scopes from config. If not specified, default `scopes` from config are used. | List of String | None | No |

#### `DELETE` (`delete`)

Remove the credential information from storage. This removes all scopes identified by the credential's `name`.
