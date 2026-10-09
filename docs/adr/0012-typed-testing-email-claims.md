# Script standard email claims through a narrow testing API

<a id="adr-0012"></a>

- **Decision:** the public local issuer accepts `EmailClaims(email: Option(String), verified: Option(Bool))` for one subject through `with_email_claims` and `set_email_claims`. The same explicit assertions feed newly issued ID tokens and userinfo. None omits a field; false remains a boolean assertion.
- **Need:** relying parties must distinguish missing email, absent verification, unverified email and changed contact evidence while retaining the same issuer/subject identity. Fixed verified email defaults cannot exercise those consumer boundaries through real protocol validation.
- **Alternatives:** caller-forged identities bypass the verifier; a general JSON claim bag can override issuer/audience/nonce; application-specific login hooks move permission policy into the library. Two independently optional standard claims provide the required negative cases without those extra authorities.
- **Compatibility:** no override preserves the original token and userinfo defaults. Another subject is unaffected. A runtime update changes future evidence; previously signed tokens and immutable identity values are unchanged. Refresh behavior, protocol claims, trust configuration and constructor ownership retain their contracts.
- **Scope:** this is explicitly trusted test-provider scripting, not email validation, registration, invitation or authorization policy. Consumers still use public login/userinfo operations. Native public-consumer and constructor-negative checks qualify this boundary; provider interoperability and release certification remain independent obligations.
