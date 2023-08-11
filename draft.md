# Open Identity Certification with OpenID Connect (OIDC²)

Last Update: August 11, 2023


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


## 4. Obtaining an Identity Certification Token

The Identity Certification Token Request and Response is depicted in Figure 2.

```
     +--------+                       +----------+
     |        |    (1) ICT Request    |          |
     |        | --------------------> |          |
     |        |  AT, K+, PoP, claims  |  OpenID  |
     | Client |                       | Provider |
     |        |   (2) ICT Response    |          |
     |        | <-------------------- |          |
     |        |          ICT          |          |
     +--------+                       +----------+
```
Fig. 2: The Identity Certification Token Request.


### 4.1. Requirements

To obtain an Identity Certification Token (ICT), the Client MUST have an OAuth 2.0 Access Token (AT) with the following scopes:

- At least one end-to-end authentication context scope
- A sufficient scope to access the desired identity claims.


### 4.2. Preparation

To obtain an Identity Certification Token, the Client needs an asymmetric signing key pair and MUST prove the possession of the corresponding private key.


#### 4.2.1. Signing Key Pair

It is RECOMMENDED, that this is an ephemeral signing key pair, uniquely generated for the Identity Certification Token that is being requested.
If developers prefer to reuse another signing key pair, it is RECOMMENDED to read the security considerations in [Section 8.1](#81-reusing-a-signing-key-pair).

It is RECOMMENDED that the private key is protected from access via cross-side scripting attacks.
If the key pair is ephemeral, the private key MUST be protected against it, if possible by the implementation.
In JavaScript, this can be done by generating it using the [`generateKey` function](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey) of the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) and setting the `extractable` parameter to `false`.

In the following example, we assume the JSON encoded elliptic P-384 curve key pair in Figure 3.

```json
{
  "publicKey": {
    "kty": "EC",
    "crv": "P-384",
    "x": "-8Ln5J2jiG9R6YpopZzk-CcGoDXjtdvd16qBTwA4FKrtWBrlhgw7fyh0mGvxhclV",
    "y": "QkE_Ij2H6nCoO9WGqAtATEN3on_BilyNcl5uH3Zk_OFa4qzudCmiWS10TIGVuS5P"
  },
  "privateKey": {
    "kty": "EC",
    "crv": "P-384",
    "d": "LkQGZ-AZU1ARLfM-swdW-hzuvMOkoWtm3V5Eup4r44FLheChlx1PIyScwMIvkHPd",
    "x": "-8Ln5J2jiG9R6YpopZzk-CcGoDXjtdvd16qBTwA4FKrtWBrlhgw7fyh0mGvxhclV",
    "y": "QkE_Ij2H6nCoO9WGqAtATEN3on_BilyNcl5uH3Zk_OFa4qzudCmiWS10TIGVuS5P"
  }
}
```
Fig. 3: JSON-encoded example signing key pair. Additional line breaks and spaces are for displaying purposes only.


#### 4.2.2. Proof of Possession

The Client must prove to the OpenID Provider that it possesses the corresponding private key of the presented public key in the Identity Certification Token Request.
Therefore, it provides a Proof of Possession Token (PoP Token) as a [JWT](https://datatracker.ietf.org/doc/html/rfc7519) that fulfills the following requirements:

1. It MUST contain the Client's public key.
2. It MUST be signed with the Client's corresponding private key.
3. It MUST be replay protected.

To fulfill requirement 1 and 2, the PoP Token MUST contain the Client's public key as `jwk` claim in its header and MUST be signed with the Client's corresponding private key.

To fulfill the replay protection requirements, the payload claims MUST be as follows:

**`iss` (Issuer)**
  REQUIRED.
  MUST be the Client ID of the Client requesting the Identity Certification Token.

**`sub` (Subject)**
  REQUIRED.
  MUST be the End-User's Subject Identifier provided in the ID Token according to [Section 2 of the OpenID Connect Core Specification](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).

**`aud` (Audience)**
  REQUIRED.
  MUST be the OpenID Provider's Issuer Identifier according to [Section 16.15 of the OpenID Conenct Core Specification](https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier).

**`iat` (Issued At)**
  REQUIRED.
  MUST be the unix timestamp with seconds precision when issuing the PoP Token.

**`nbf` (Not Before)**
  OPTIONAL.
  MUST be the unix timestamp with seconds precision when the PoP Token becomes valid.
  This is typically the same as the `iat` claim.

**`exp` (Expiration Time)**
  REQUIRED.
  MUST be the unix timestamp with seconds precision when the PoP Token expires.
  This timestamp MUST NOT be before the `iat` timestamp and MUST NOT be more than 5 minutes after the `iat` timestamp.
  Therefore, the maximum lifetime of the PoP Token is 5 minutes.

**`jti` (JWT ID)**
  REQUIRED.
  MUST be a randomly generated STRING as specified in [Section 4.1.7 of RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7) that is unique for the combination of Issuer, Subject, and Audience within the lifespan of the PoP Token.


**Example:**

Figure 4 shows a decoded example of the PoP Token's header and payload using the elliptic curve key pair in Figure 3.

```json
// Header:
{
  "alg": "ES384",
  "typ": "jwt+pop",
  "jwk": {
    "kty": "EC",
    "crv": "P-384",
    "x": "-8Ln5J2jiG9R6YpopZzk-CcGoDXjtdvd16qBTwA4FKrtWBrlhgw7fyh0mGvxhclV",
    "y": "QkE_Ij2H6nCoO9WGqAtATEN3on_BilyNcl5uH3Zk_OFa4qzudCmiWS10TIGVuS5P"
  }
}
// Payload:
{
  "iss": "exampleclient", // Client ID
  "sub": "1234567890", // User ID
  "aud": "https://op.example.com", // OP's Issuer URL
  "iat": 1691712000, // Current unix timestamp
  "nbf": 1691712000, // (Optional) current unix timestamp
  "exp": 1691712060, // Current unix timestamp + 1 min
  "jti": "d6_ptZmZ8laX4DKoWXD08oZX5yo" // Random PoP ID.
}
```
Fig. 4: Example of a decoded header and payload of the PoP Token. Additional line breaks, spaces, and comments are for displaying purposes only.

Figure 5 shows the PoP Token from Figure 4 as an encoded PoP Token.

```jwt
eyJhbGciOiJFUzM4NCIsInR5cCI6Imp3dCtwb3AiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTM4NCIsIngiOiItOExuNUoyamlHOVI2WXBvcFp6ay1DY0dvRFhqdGR2ZDE2cUJUd0E0RktydFdCcmxoZ3c3ZnloMG1HdnhoY2xWIiwieSI6IlFrRV9JajJINm5Db085V0dxQXRBVEVOM29uX0JpbHlOY2w1dUgzWmtfT0ZhNHF6dWRDbWlXUzEwVElHVnVTNVAifX0
.
eyJpc3MiOiJleGFtcGxlY2xpZW50Iiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20iLCJpYXQiOjE2OTE3MTIwMDAsIm5iZiI6MTY5MTcxMjAwMCwiZXhwIjoxNjkxNzEyMDYwLCJqdGkiOiJkNl9wdFptWjhsYVg0REtvV1hEMDhvWlg1eW8ifQ
.
LZnTlZldaUX6RjO9ZqO3hsQR8dyIHBAeZu_s7CsFPs1mre-5Kq6FcxRaGDC7WIVLV5-QHD_quOqbc6PY_jYbQWizmxYZvYvJYu-yj4Nt04RHPAmFowNNZ6REge5fMHHX
```
Fig. 5: Example of an encoded PoP Token. Additional line breaks are for displaying purposes only.


### 4.3. Identity Certification Token Request

The Client sends the Identity Certification Token Request to the Identity Certification Token (ICT) Endpoint of the OpenID Provider.

If the OpenID Provider supports this endpoint, it MUST be referenced in the OpenID Connect Discovery Document specified in [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), using the following metadata attribute:

**`ict_endpoint`**
  REQUIRED.
  URL of the OpenID Provider's Identity Certification Token Endpoint.
  This URL MUST use the https scheme and MAY contain port and path components.

The Identity Certification Token Endpoint is an HTTP POST endpoint with the following headers:

**`Authorization`**
  REQUIRED.
  Contains the Access Token as a bearer token according to [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750).
  The OpenID Provider MUST verify this header as described in [Section 4.4](#44-identiy-certification-token-request-verification)

**`Content-Type`**
  REQUIRED.
  MUST be set to `application/json`

In the HTTP POST Body, the Client MUST provide a JSON object, containing the following attributes:

**`pop_token`**
  REQUIRED.
  The generated PoP Token.

**`required_claims`**
  OPTIONAL.
  An array of claims according to [Section 5 of the OpenID Connect Core Specification](https://openid.net/specs/openid-connect-core-1_0.html#Claims) which MUST be present in the requested Identity Certification Token.
  If the scope of the Access Token is not sufficient or any claim is not known, the OpenID Provider MUST respond with an HTTP `404 Not Found` error.

**`optional_claims`**
  OPTIONAL.
  An array of claims according to [Section 5 of the OpenID Connect Core Specification](https://openid.net/specs/openid-connect-core-1_0.html#Claims) which MAY be present in the requested Identity Certification Token.
  If the scope of the Access Token is sufficient and the claims are present to the OpenID Provider, they MUST be included in the issued Identity Certification Token.

**`with_audience`**
  OPTIONAL.
  A boolean value which defines whether the `aud` claim MUST be present in the Identity Certification Token (`true`), or not (`false`).

**Example:**

Figure 6 contains a sample Identity Certification Token Request.

```http
POST /ict HTTP/1.1
Authorization: bearer ey...
Content-Type: application/json

{
  "pop_token": "eyJhbGciOiJFUzM4NCIsInR5cCI6Imp3dCtwb3AiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTM4NCIsIngiOiItOExuNUoyamlHOVI2WXBvcFp6ay1DY0dvRFhqdGR2ZDE2cUJUd0E0RktydFdCcmxoZ3c3ZnloMG1HdnhoY2xWIiwieSI6IlFrRV9JajJINm5Db085V0dxQXRBVEVOM29uX0JpbHlOY2w1dUgzWmtfT0ZhNHF6dWRDbWlXUzEwVElHVnVTNVAifX0.eyJpc3MiOiJleGFtcGxlY2xpZW50Iiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20iLCJpYXQiOjE2OTE3MTIwMDAsIm5iZiI6MTY5MTcxMjAwMCwiZXhwIjoxNjkxNzEyMDYwLCJqdGkiOiJkNl9wdFptWjhsYVg0REtvV1hEMDhvWlg1eW8ifQ.LZnTlZldaUX6RjO9ZqO3hsQR8dyIHBAeZu_s7CsFPs1mre-5Kq6FcxRaGDC7WIVLV5-QHD_quOqbc6PY_jYbQWizmxYZvYvJYu-yj4Nt04RHPAmFowNNZ6REge5fMHHX",
  "required_claims": [
    "name"
  ],
  "optional_claims": [
    "email",
    "phone_number"
  ]
}

```
Fig. 6: Example of an Identity Certification Token Request.


### 4.4. Identiy Certification Token Request Verification

When receiving an Identity Certification Token Request on the Identity Certification Token Request Endpoint, the OpenID Provider MUST verify the validity of the provided Access Token, the validity of the Proof of Possession Token, and the other request attributes.


#### 4.4.1. Access Token Verification

The OpenID Provider MUST verify the Access Token like a Resource Owner described in [Section 7 of RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-7).
If the Access Token does not authorize the Client for any end-to-end context, the OpenID Provider MUST reject the Identity Certification Token Request with an HTTP `401 Unauthorized` response.

If the Access Token is valid, the Client successfully proved authorization by the End-User to authenticate as the End-User in the provided contexts.


#### 4.4.2. PoP Token Verification

The OpenID Provider MUST verify the PoP Token as follows:

- The signature of the PoP Token MUST be valid for the public key defined in the `jwk` header attribute of the PoP Token.
- The `iss` claim of the PoP Token MUST be equal to the Client ID of the Client that the Access Token is issued for.
- The `sub` claim of the PoP Token MUST be equal to the subject of the Access Token.
- The `aud` claim of the PoP Token MUST be equal to the Issuer Identifier of the OpenID Provider.
- The current unix timestamp must be after the timestamp of the `iss` claim in the PoP Token.
- If the `nbf` claim is present in the PoP Token, the current unix timestamp MUST be after it.
- The current unix timestamp must be before the timestamp of the `exp` claim in the PoP Token.
- The `jti` claim must be unique for the issuer and subject within the validity time of the PoP Token. To verify this, the OpenID Provider MAY cache any used `jti` claim for an `iss` and `sub` claim until the PoP Token with the `jti` expires.

If the PoP Token passes all verifications, the PoP Token is valid an the Client has successfully proved the possession of the private key corresponding to the public key provided in the `jwk` header attribute of the PoP Token.


#### 4.4.3. Request Attribute Verification

The OpenID Provider MUST verify the other attributes of JSON object in the Identity Certification Token Request as described in [Section 4.3](#43-identity-certification-token-request).


### 4.5. Identity Certification Token Issuance

If the Identity Certification Token Request is valid, the OpenID Provider MUST issue an Identity Certification Token.

The Identity Certification Token is a JWT according to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) that fulfills the following header and payload requirements.

An example of a decoded Identity Certification Token header and payload shown in Figure 7.

```json
// Header:
{
  "typ": "jwt+ict",
  "alg": "ES384",
  "kid": "sEr97rt9UKFu__ei_ZBDziTneZ4"
}
// Payload:
{
  "iss": "https://op.example.com",
  "sub": "1234567890",
  "aud": "exampleclient",
  "iat": 1691712030,
  "nbf": 1691712030,
  "exp": 1691712330, // 5 minutes after iat / nbf
  "jti": "EhSh55vH9eK353-r1i2y5Bp7tRk",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-384",
      "x": "-8Ln5J2jiG9R6YpopZzk-CcGoDXjtdvd16qBTwA4FKrtWBrlhgw7fyh0mGvxhclV",
      "y": "QkE_Ij2H6nCoO9WGqAtATEN3on_BilyNcl5uH3Zk_OFa4qzudCmiWS10TIGVuS5P"
    }
  },
  "name": "John Smith",
  "email": "john.smith@mail.example.com"
}
```
Fig. 7: Example of decoded Identity Certification Token header and payload.

The JSON Web Token using the example OpenID Provider key pair of Figure 9 is shown in Figure 8.

```jwt
eyJ0eXAiOiJqd3QraWN0IiwiYWxnIjoiRVMzODQiLCJraWQiOiJzRXI5N3J0OVVLRnVfX2VpX1pCRHppVG5lWjQifQ
.
eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6ImV4YW1wbGVjbGllbnQiLCJpYXQiOjE2OTE3MTIwMzAsIm5iZiI6MTY5MTcxMjAzMCwiZXhwIjoxNjkxNzEyMzMwLCJqdGkiOiJFaFNoNTV2SDllSzM1My1yMWkyeTVCcDd0UmsiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0zODQiLCJ4IjoiLThMbjVKMmppRzlSNllwb3BaemstQ2NHb0RYanRkdmQxNnFCVHdBNEZLcnRXQnJsaGd3N2Z5aDBtR3Z4aGNsViIsInkiOiJRa0VfSWoySDZuQ29POVdHcUF0QVRFTjNvbl9CaWx5TmNsNXVIM1prX09GYTRxenVkQ21pV1MxMFRJR1Z1UzVQIn19LCJuYW1lIjoiSm9obiBTbWl0aCIsImVtYWlsIjoiam9obi5zbWl0aEBtYWlsLmV4YW1wbGUuY29tIn0
.
CPDCaV6iS6AjDX_3AUsfwlTDcK6VcX1bdOiQFw486rxlItE27r4hHzm-iDp2aG2WHFacUd1SYtkMKR-aV4xmgKuiNREwGv-QO0b1zmz_nmblqNCVNc-pIsROxllJy2QK
```
Fig. 8: Example of encoded Identity Certification Token using the example key pair of Figure 9.

```json
{
  "publicKey": {
    "kty": "EC",
    "crv": "P-384",
    "x": "rTM4gnV_1uUMcmLEWVffSzXRN25etn42j54a5_Gyw_wJXckrdsUQMnMgpenOUySX",
    "y": "gkC9pdQqEhW6xGrwcDVNZaaYPaPFo9J0FGt8RCEyydbHjdSw_CKZRNBiVgjVKzmm"
  },
  "privateKey": {
    "kty": "EC",
    "crv": "P-384",
    "d": "MfbEM7MkDcnXJiqoy87CQmKv39vfUVJeHqkWFs-JPJXlVxnL3WvzalNl73wvuy2D",
    "x": "rTM4gnV_1uUMcmLEWVffSzXRN25etn42j54a5_Gyw_wJXckrdsUQMnMgpenOUySX",
    "y": "gkC9pdQqEhW6xGrwcDVNZaaYPaPFo9J0FGt8RCEyydbHjdSw_CKZRNBiVgjVKzmm"
  }
}
```
Fig. 9: Example elliptic curve key pair for an OpenID Provider.


#### 4.5.1. Header

The header is a JOSE header with the following attributes:

**`typ` (Type)**
  REQUIRED.
  MUST be set to `jwt+ict`.

**`alg` (Algorithm)**
  REQUIRED.
  The signature algorithm as defined in [Section 4.1.1 of RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1).
  It MUST be an asymmetric signing algorithm as defined in [Section 3.1 of RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1).
  A value of `none` is not allowed.

**`kid` (Key ID)**
  REQUIRED.
  The Key ID of the private key used by the OpenID Provider to sign the Identity Certification Token.
  The corresponding public key MUST be provided with this Key ID on the JWKS URI of the OpenID Provider.


#### 4.5.2. Payload

The payload contains JWT Claims as defined in [Section 4 of RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-4).
The following JWT Claims are allowed:

**`iss` (Issuer)**
  REQUIRED.
  MUST be set to the Issuer Identifier of the OpenID Provider.

**`sub` (Subject)**
  REQUIRED.
  MUST be set to the Subject Identifier of the End-User that was present in the Access Token and the PoP Token.

**`aud` (Audience)**
  OPTIONAL by default.
  It MAY be REQUIRED depending on the `with_audience` attribute was present in the Identity Certification Token Request object.
  If `with_audience` is `true`, it is REQUIRED.
  If `with_audience` is `false`, it MUST not be present.
  If `with_audience` is not present, the presence of the claim is not defined.
  If the claim is present, it MUST be set to the Client ID of the Client that requested the Identity Certification Token.

**`iat` (Issued At)**
  REQUIRED.
  The unix timestamp with seconds-precision when the Identity Certification Token was issued.

**`nbf` (Not Before)**
  OPTIONAL.
  The unix timestamp with seconds-precision when the Identity Certification Token becomes valid.

**`exp` (Expiration Time)**
  REQUIRED.
  The expiration time of the Identity Certification Token as a unix timestamp with seconds-precision.
  This must be at most one hour after the Issued At (`iat`) timestamp.

**`jti` (JWT ID)**
  REQUIRED.
  MUST be a randomly generated STRING as specified in [Section 4.1.7 of RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7) that is unique for the combination of Issuer and Subject within the lifespan of the Identity Certification Token.

**`cnf` (Confirmation)**
  REQUIRED.
  A JSON object that contains the JSON Web Key representation of the verified public key of the Client as defined in [Section 3.2 of RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800#section-3.2).
  This object contains only the `jwk` attribute which represents the public key of the Client as provided in the `jwk` header attribute of the PoP Token.

The Payload MUST also contain the Identity Claims of the End-User that the Client requested in the `required_claims`.
The Payload MUST also contain the Identity Claims of the End-User that the Client requested in the `optional_claims`, if known to the OpenID Provider, and the Access Token's scope is sufficient.

### 4.6. Identity Certification Token Response

If the Identity Certification Token Request Verification was valid and generating the Identity Certification Token was successful, the OpenID Provider responds with a JSON object containing the following parameters.

**`identity_certification_token`**
  REQUIRED.
  The Identity Certification Token.

**`identity_certification_token_expires_in`**
  OPTIONAL.
  The number of seconds in which the Identity Certification Token expires.


## 5. End-to-End Authentication

TODO


## 6. Mutual Authentication

TODO


## 7. Negotiation of End-to-End Encryption

TODO


## 8. Security Considerations

### 8.1. Reusing a Signing Key Pair

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
