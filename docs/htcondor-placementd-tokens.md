# Accepting HTCondor Placement Daemon Tokens at a POSIX V2 Origin

## Goal

An access point that runs HTCondor's placement daemon (`condor_placementd`) already hands its users a credential: an IDToken minted by the daemon for a sign-in identity it has mapped. This document describes how a V2 (POSIXv2) Pelican origin accepts that credential as proof of *who* a request is from, and authorizes the request as the Pelican user that identity belongs to.

The point is to spare a user who already holds an access-point credential from acquiring a second one. It is not a way to grant access that Pelican would not otherwise grant: the placement daemon is an authentication source and nothing more.

## Why the origin cannot check the token itself

An HTCondor IDToken is signed with a symmetric key held by the pool's daemons. There is no JWKS to fetch, so there is no signature a Pelican origin can verify, and the token's claims are HTCondor authorizations (`condor:/WRITE`) rather than storage scopes, so there would be nothing in it to honor even if the signature could be checked.

What the pool can do is answer a question. The origin opens a CEDAR connection to the placement daemon offering the caller's token as its only credential and sends `DC_NOP`, which HTCondor's daemon core registers at `ALLOW` and whose handler reads nothing. The daemon's security layer either refuses the credential or completes the handshake and reports the identity it authenticated. That is what `condor_ping` does, and the reported identity is the answer the origin is after.

## Trust model

- The pool decides whether a token is genuine, and which identity it names. The origin takes the identity from the handshake, not from the token's `sub` claim, because the daemon may map a credential onto a different identity and only the mapped one means anything.
- Pelican decides what that identity may do. The authorization is the one the embedded issuer would compute for the same user: the configured authorization templates plus the collection ACLs the user holds.
- The link between the two is one row an administrator adds: an identity whose issuer is `Origin.Placementd.IdentityIssuer` and whose subject is what the placement daemon reports. There is no auto-enrollment — an identity with no such row is refused, never served as a default user.
- Revoking access in Pelican revokes it for the placement-daemon token too, because every decision is made from the Pelican user's current entitlements. Disabling the Pelican account refuses the token outright.
- An export's capabilities still have the last word. A read-only export stays read-only however much the user is otherwise entitled to.

## Keeping the placement daemon out of the request path

Verifying a token costs a round trip to somebody else's daemon, so the origin does as few as it can.

1. **Recognition.** Before anything else, the token is judged from itself alone: three segments, an HMAC (`HS*`) algorithm, an `iss` claim equal to `Origin.Placementd.TrustDomain`, and an `exp` that has not passed. Every other token the origin serves — Pelican's own, WLCG, SciTokens, share tokens, malformed strings — fails this for free and never reaches the network. A token signed with an asymmetric key is by definition one the origin can check itself.
1. **Memoization.** Both outcomes are remembered: a reported identity for `Origin.Placementd.IdentityCacheTimeout` (never past the token's own expiry), a refusal for `Origin.Placementd.RefusalCacheTimeout`. A client retrying with a bad token does not reach the daemon again. A daemon that could not be reached is deliberately *not* remembered, since that says nothing about the token and caching it would refuse good tokens for as long as the outage lasted.
1. **Collapsing.** Concurrent requests bearing the same unseen token share one round trip.
1. **Rate limiting.** What survives all of that is metered by `Origin.Placementd.VerificationsPerSecond` and `Origin.Placementd.VerificationBurst`. A verification waits for budget up to `Origin.Placementd.VerificationTimeout` and is then refused, so a flood of distinct unseen tokens cannot be turned into a flood of connections.

Above that sits the origin's ordinary authorization cache, so a verified token is re-authorized at most every few minutes rather than per request.

## What the origin presents to the daemon

The CEDAR connection offers the caller's token and nothing else: no token file, no token directory, and `IDTOKENS` as the only method. If the origin ever holds HTCondor credentials of its own, a token the daemon refuses has to fail rather than quietly succeed as the origin's own identity and hand the caller whatever that identity may do. Authentication and encryption are both required — the first so that an anonymous session is a failure rather than a handshake naming nobody, the second because a bearer token is on the wire. The client session cache is partitioned per token, so one token can never resume a session another authenticated and be reported as that identity.

## Setting it up

1. Point the origin at the daemon and name its pool:

   ```yaml
   Origin:
     Placementd:
       Address: placement.example.com:9618
       TrustDomain: pool.example.com
   ```

   `Address` accepts a sinful string as well as `host:port`. `TrustDomain` is the pool's HTCondor trust domain, which is what the daemon stamps as `iss`. Without it the origin refuses to start, because there would be nothing to recognize a token by and every token that arrived would become a connection to the daemon.

1. Decide which issuer the identities are recorded under. By default it is the trust domain, which is what the tokens themselves carry. Set `Origin.Placementd.IdentityIssuer` where a deployment already records these identities under another name.

1. For each user, add an identity to their Pelican account whose issuer is that value and whose subject is the identity the placement daemon reports for them — the fully-qualified `user@domain` its own `ALLOW`/`DENY` lists match, which `condor_ping` prints.

1. Grant the user access as usual, through `Issuer.AuthorizationTemplates` (globally or per export) or by adding them to a collection ACL. Nothing about this path is specific to the placement daemon: a user whose template and ACL grants are right already has them.

The origin logs the daemon it will talk to, the trust domain it recognizes and the issuer it matches identities against at startup, and logs a refusal with the identity that could not be placed, so an unlinked identity is diagnosable from the origin's log alone.

## Limits

- Only an identity is carried across. The token's HTCondor authorizations and project claim are read by nobody, so a token minted with a narrowed bounding set authorizes the same storage access as a full one.
- The placement daemon is reached directly by address; it is not discovered through a collector.
- The data plane acts as the resolved Pelican user. An operator who needs a different local account on a multi-user backend maps the Pelican username in `Origin.ScitokensNameMapFile`.
