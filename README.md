This project investigates whether protocol-aware rules combined with supervised ma
chine learning enhances the detection of OAuth 2.0/OpenID Connect (OIDC) middle
ware vulnerabilities. A Flask relying party (RP) and a Keycloak identity provider (IdP)
are used in a controlled lab environment, with deliberate misconfigurations in redirect
URI validation, PKCE, and refresh token mishandling. HTTP flows are captured in
order to create trace-level features. A hybrid model that combines rules and Gradient
Boosting, and a purely rule-based detector based on best current practices, are compared
on a held-out test set. The project also aims to evaluate whether graph-based flow visu
alization makes analysis easier, and also focuses on evaluating the value of lightweight
flow-based monitoring as an additional assurance layer of OAuth/OIDC middleware.
