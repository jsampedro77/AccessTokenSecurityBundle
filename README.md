AccessToken Security Bundle
===========================

Secures an API access checking AccessToken header to authenticate a user.

The API Firewall expects a "AccessToken" parameter in each Request header.
If the AccessToken is valid then an ApiToken is introduced in the SecurityContext.

In order to create new AccessTokens a UsernamePasswordLoginManager is provided.
It expects an username/password combination, and delegates its validation to a
firewall (configurable, 'main' by default). When the username/password combination
is correct then a new AccessToken is created.

A SecurityController is also included, it is prepared to work with FOSRestBundle
and creates an "AccessToken" resource to provide an REST way to login. I.E
GET /api/v2/accesstoken?username=user&password=pass

TODO

* Document installation and configuration (security.yml, routing.yml, ... )

* Make AccessToken parameter name configurable

* Decouple from Redis to allow different persistence options

* Add an entity listener to remove accesstokens when user credentials are removed.

* AccessTokens are always created with ROLE_USER, enable role configuration based on user provider. 

