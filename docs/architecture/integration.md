# MFA4ATIP Integration

The Sign In Canada Acceptance Platform integrates with MFA4ATIP using the OpenID Connect authorization code flow.

![Sequence Diagram](diagrams/sequence.png)

## Sequence of Events

The end-user first authenticates to the Acceptance Platform using their
preferred first-factor credential (e.g. GCKey or CBS Sign In Partner). If the
Acceptance Platform determines that two-factor authentication is required then:

1. The Acceptance redirects the end-user's browser to the MFA4ATIP
   [authorization
   endpoint](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint)
   with and OpenID Connect [authentication
   request](data_elements.md#authentication-request).
   The login_hint parameter of the request includes a [pairwise pseudonym](data_elements.md#pairwise-pseudonym-pai) created
   by the Acceptance Platform for the end-user.
2. MFA4ATIP authenticates (or registers) the end-user's second factor authenticator. (See the [User Flow](ui_flows.md))
3. MFA4ATIP redirects the browser back to the Acceptance Platform with an
   [authentication response](https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse)
   containing an [authorization code](data_elements.md#authorization-code).
4. The Acceptance Platform sends a [token request](data_elements.md#token-request) to the MFA4ATIP token endpoint.
5. MFA4ATIP returns an [ID Token](data_elements.md#id-token) containing the user's pairwise pseudonym.
6. The Acceptance Platform compares the pairwise pseudonym returned in the ID
   token with the one it sent in the login hint of the authentication request.
   If they match then two-factor authentication has been successful.
