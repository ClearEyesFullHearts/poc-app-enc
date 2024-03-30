Feature: Single Test

    For a single

Scenario: Create a user
  Given I set body to { "username": "test@example.com", "password": "aaaaaaaaaaaa" }
  When I API POST to /users
  And response code should be 200
  Then response body path $.success should be true

Scenario: Log as a user
  Given I generate a session key pair
  And I set body to { "username": "test@example.com", "password": "aaaaaaaaaaaa", "publicKey": "`PK_ENC`", "signingKey": "`PK_SIG`" }
  When I API POST to /login
  Then response header x-auth-token should exist
  And response header x-servenc-pk should exist
  And response header x-servsig-pk should exist
  And I set session from response headers
  Then response body path $.username should be test@example.com
  Then response body path $.password should be aaaaaaaaaaaa