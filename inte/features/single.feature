Feature: Single Test

    For a single

Scenario: Create a user
  Given I set body to { "username": "test@example.com", "password": "aaaaaaaaaaaa" }
  When I API POST to /users
  And response code should be 200
  Then response body path $.success should be true

Scenario: Log as a user
  Given I set body to { "username": "test@example.com", "password": "aaaaaaaaaaaa" }
  When I API POST to /login
  Then response header x-auth-token should exist
  And response header x-servenc-pk should exist
  And response header x-servsig-pk should exist
  Then response body path $.email should be test@example.com
  Then response body path $.id should be 1
  Then response body path $.role should be user

  Scenario: Get all users
    Given I set body to { "username": "test@example.com", "password": "aaaaaaaaaaaa" }
    And I API POST to /login
    When I API GET /users
    Then response body path $.0.username should be test
    Then response body path $.1.username should be hello
    Then response body path $.2.username should be admin
    Then response body path $.3.username should be muad dib