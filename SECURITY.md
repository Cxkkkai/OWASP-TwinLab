# Security and responsible use

This repository intentionally contains vulnerable code paths for a bounded
university teaching project.

## Do not deploy it

Run the application only on a computer you control and keep it bound to
`127.0.0.1`. Do not expose it to the internet or a shared network. Do not add
real users, credentials, personal data, packages, secrets or external targets.

The hard-coded demonstration key, observer capability and synthetic passwords
are public laboratory fixtures. They must never be reused in another
application.

## Expected versus unintended weaknesses

The vulnerable routes and incomplete Candidate controls are deliberate and are
described in the module and Auditor specifications. They do not need to be
reported as security defects.

An unintended issue is one that escapes the stated boundary—for example,
binding outside loopback, contacting an external target, exposing non-synthetic
data, or allowing a reset to affect a database outside this lab. Do not include
real secrets or personal information in a public issue.

## Safe evaluation

Use only the included synthetic inputs and the documented local test commands.
The project is not an offensive scanner and should not be pointed at another
system.

