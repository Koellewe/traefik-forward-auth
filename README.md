# What is Koellewe/traefik-forward-auth ?

A fork of https://funkypenguin/traefik-forward-auth, which is a fork of https://github.com/noelcatt/traefik-forward-auth, which is in turn a fork of https://github.com/thomseddon/traefik-forward-auth.

Why all the forkery? @thomseddon's version supports only Google OIDC, while @noelcatt's version supports any OIDC, but doesn't have a docker image build pipeline setup. @funkypenguin's version does have a containerisation, but misses a convenient feature I wanted, which is role-based authentication for specific endpoints. More details on this below.

For proper documentation, check out the upstream ([funkypenguin/traefik-forward-auth](https://funkypenguin/traefik-forward-auth)).

## Role-based authentication

Keycloak has the notion of roles for a user, which essentially determines what permissions they have. 

// Todo implementation details...

https://stackoverflow.com/a/62359540/3900981



## Configuration

The following configuration is supported (on top of the upstream's):


|Flag                   |Type  |Description|
|-----------------------|------|-----------|
|-role-auth-file|string|*Role authentication file (optional)|

Configuration can also be supplied as environment variables (use upper case and swap `-`'s for `_`'s e.g. `-client-id` becomes `CLIENT_ID`)

Configuration can also be supplied via a file, you can specify the location with `-config` flag, the format is `flag value` one per line, e.g. `client-id your-client-id`)

# License

[MIT](https://github.com/thomseddon/traefik-forward-auth/blob/master/LICENSE.md)
