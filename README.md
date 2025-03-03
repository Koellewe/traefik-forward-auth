# What is Koellewe/traefik-forward-auth ?

A fork of https://github.com/funkypenguin/traefik-forward-auth, which is a fork of https://github.com/noelcatt/traefik-forward-auth, which is in turn a fork of https://github.com/thomseddon/traefik-forward-auth.

Why all the forkery? @thomseddon's version supports only Google OIDC, while @noelcatt's version supports any OIDC, but doesn't have a docker image build pipeline setup. @funkypenguin's version does have a containerisation, but misses a convenient feature I wanted, which is role-based authentication for specific endpoints. More details on this below.

For proper documentation, check out the upstream ([funkypenguin/traefik-forward-auth](https://github.com/funkypenguin/traefik-forward-auth)).

## Role-based authentication

Some OIDC providers (e.g., Keycloak) have the notion of roles for a user, which essentially determines what permissions they have. My fork allows you to configure role-based permissions such that particular roles are allowed access to particular sub/domains. See config details below.

(Btw, see [here](https://stackoverflow.com/a/62359540/3900981) for passing client-level roles to the client from Keycloak)


## Configuration

The following configuration is supported (on top of the upstream's):


|Flag                   |Type  |Description|
|-----------------------|------|-----------|
|-role-auth-file|string|*Role authentication file path (optional)|

Configuration can also be supplied as environment variables (use upper case and swap `-`'s for `_`'s e.g. `-client-id` becomes `CLIENT_ID`)

Configuration can also be supplied via a file, you can specify the location with `-config` flag, the format is `flag value` one per line, e.g. `client-id your-client-id`)

### Role auth file

This file should be a json map with keys being role names and values being a set of hosts that role is allowed to access. E.g.,

```json
{
    "EXAMPLE_ROLE": [
        "example.com",
        "sub.example.com"
    ],
    "DENY_ALL_ROLE": []
}
```

// TODO example in `example/`

# License

[MIT](https://github.com/thomseddon/traefik-forward-auth/blob/master/LICENSE.md)
