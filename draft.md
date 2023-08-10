# Open Identity Certification with OpenID Connect (OIDC²)

Last Update: August 10, 2023


## Abstract

In modern user-to-user communication systems like email, instant messenger, and video conferencing, authentication often relies on service accounts controlled by the communication service provider.
In zero-trust scenarios, users want to authenticate communication partners using accounts from trusted identity providers of their choice, rather than relying on specific service providers.

This document describes a technology, called Open Identity Certification with OpenID Connect (OIDC²), where End-Users authenticate themselves with an Identity Certification Token (ICT).
This ICT is issued by an OpenID Provider and contains identity claims and a verified public key of the End-User.
This allows End-Users to authenticate themselves end-to-end as the owner of an OpenID Connect account and the holder of a short-lived key pair, which can also be used to negotiate an end-to-end encrypted channel.


## 1. Introduction

Assume Alice and Bob participating in an online meeting through a video conferencing (VC) system.
Although they have not previously met, their employers have a nondisclosure agreement allowing them to share confidential information.
Mallory is the VC system administrator and manages the VC accounts of both Alice and Bob.
Therefore, Bob needs to trust that Mallory will not impersonate Alice to obtain confidential information from his employer.

This document proposes an extension for an OpenID Provider that enables Alice's Client to obtain a short-lived Identity Certification Token (ICT).
Alice's Client presents the ICT to Bob's Client to authenticate herself as an employee of Bob's trusted employer.
To achieve this, Alice logs into her employer's OpenID Provider and authorizes her Client for end-to-end authentication.
In the background, Alice's Client generates an ephemeral signing key pair and presents the public key to the OpenID Provider, which verifies that the Client possesses of the corresponding private key.
The OpenID Provider then issues the ICT, which includes Alice's identity claims and the verified public key.
Alice's Client presents the ICT to Bob's Client and proves possession of the corresponding private key.
Bob's Client successfully authenticated Alice using her OpenID Connect account as he trusts Alice's employer's OpenID Provider.

As Alice also trusts Bob's OpenID Provider, Bob can also authenticate himself to Alice the other way around.
After exchaning the verified public signing keys mutually, Alice and Bob can also negotiate an end-to-end encryption between their Clients.

### 1.1. Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC2119](https://datatracker.ietf.org/doc/html/rfc2119).


### 1.2. Terminology

This specification uses the terms "Access Token", "Refresh Token", "Authorization Code", "Authorization Endpoint", "Authorization Grant", "Refresh Token", "Response Type", and "Token Endpoint" defined by The OAuth 2.0 Authorization Framework in [RFC6749](https://datatracker.ietf.org/doc/rfc6749/), the terms "Claim Name", "Claim Value", "JSON Web Token (JWT)", and "JWT Claims Set" defined by JSON Web Token (JWT) in [RFC7519](https://datatracker.ietf.org/doc/7519/), and the terms "Authentication Request", "Relying Party (RP)", and "ID Token" defined by [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).

This specification also defines the following terms:

**Identity Certification Token (ICT)**
A JWT according to [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) which is signed by an OpenID Provider and contains information to identify its End-User.
It follows the Proof-of-Possession Key Semantics for JSON Web Tokens of [RFC7800](https://www.rfc-editor.org/rfc/rfc7800) and therefore contains the public key of the End-User's Client.
It is like an ID Token, as defined in [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html), but since it is meant to be shared with third parties, it contains only a configurable subset of the identity claims granted in the Authorization Request.

**End-User (EU)**
An End-User as defined in [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html).
This is the user who wants to authenticate himself to a third party.

**Client**
The client application of an End-User.
The End-User authorizes the Client to obtain an ICT to perform the end-to-end user authentication to a third party.

**Authenticating User**
The third party (typically a user) which authenticates the End-User.

**Authenticating Party**
The Authenticating User's client application.
It verifies the ICT and the Client's proof of possession.
An Authenticating Party may also be a server-side application instance of a service that the End-User cryptographically wants to authenticate himself to.


## 2. Overview

The mechanism has the following four basic steps, as depicted in Fig. 1:

1. **Client Authorization**: The End-User authenticates to its own OpenID Provider and authorizes its Client for end-to-end authentication in a specific context. This is done with an OAuth 2.0 Authorization Code Grant to obtain a sufficient Access Token.
2. **Identity Certification Token Request**: The Client proves authorization by providing a sufficient Access Token to the OpenID Provider. The Client also presents its public key and prove possession of the corresponding private key. If valid, the OpenID Provider issues an Identity Certification Token to the Client.
3. **End-to-End Authentication**: The Client authenticates end-to-end as its End-User the Authenticating Party by presenting the Identity Certification Token and proving the possession of the corresponding private key.
4. **Trust Request**: The Authenticating Party verifies whether or not to trust the OpenID Provider. This may require interaction with the Authenticating User.

```
           +------------+                          +----------------+
           |   OpenID   |                          | Authenticating |
           |  Provider  |                          |      User      |
           +------------+                          +----------------+
             ^        ^                                    ^         
             |        |                                    |         
   +--- +   (1)      (2)                                  (4)        
   | EU |  Client    ICT                                 Trust       
   +----+  AuthZ   Request                              Request      
             |        |                                    |         
             v        v                                    v         
           +------------+                          +----------------+
           |   Client   |  (3) E2E Authentication  | Authenticating |
           |            |<------------------------>|     Party      |
           +------------+                          +----------------+
```
Fig. 1: The four steps for end-to-end authentication with OIDC².


## 3. Client Authorization

To authorize the Client, the End-User is treated as a Resource Owner that authorizes his Client using the OAuth 2.0 Authorization Code Grant according to Section 4.1 of [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749).
Thereby, the Client MUST use a Proof Key for Code Exchange (PKCE) according to [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636).


## 3.1. End-to-End Authentication Context

The End-User MUST authorize the Client for end-to-end authentication in specific application contexts.
Therefore, the Client MUST request a pre-registered Access Token Scope that follows the rules of Section 3.3 of [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749) and is prefixed with the string `e2e_auth_`.
For example, the Access Token Scope for the `email` authentication context is `e2e_auth_email`.
The OpenID Provider MUST inform the End-User that granting this scope authorizes the Client to impersonate the End-User and authenticate in the requested context.

It is RECOMMENDED to use a registered end-to-end authentication context as defined in [Section 9.1](#91-end-to-end-authentication-contexts).
If none of the registered end-to-end authentication contexts fit for the application, or the context should be further restricted for a specific application, a developer of a Client MAY define a specific end-to-end authentication context for its own application, e.g., `e2e_auth_example_app` for his `example_app`.
Developers SHOULD consider, that third party Authenticating Parties may not accept this scope!

The Client MAY also request multiple end-to-end authentication scopes.
For example, an email client which is also an instant messaging client can request the scopes `e2e_auth_email` and `e2e_auth_instant_messaging` at once.


## 4. Identity Certification Token Request

TODO


## 5. End-to-End Authentication

TODO


## 6. Mutual Authentication

TODO


## 7. Negotiation of End-to-End Encryption

TODO


## 8. Security Considerations

TODO


## 9. IANA Considerations

### 9.1. End-to-End Authentication Contexts

This specification establishes the OIDC² Authentication Context registry.

This document registers the following End-to-End Authentication Contexts:

**Email**
  The `e2e_auth_email` scope is REQUIRED to authorize a Client for the `email` authentication context.
  It permits a Client to be authenticated with an ICT in an electronic mail that is transferred using the Simple Mail Transfer Protocol (SMTP) according to [RFC5321](https://datatracker.ietf.org/doc/html/rfc5321).

**Instant Messaging**
  The `e2e_auth_instant_messaging` scope is REQUIRED to authorize a Client for the `instant_messaging` authentication context.
  It permits a Client to be authenticated with an ICT in an instant messaging service.

**Video Conferencing**
  The `e2e_auth_video_conferencing` scope is REQUIRED to authorize a Client for the `video_conferencing` authentication context.
  It permits a Client to be authenticated with an ICT in a video conferencing service.
