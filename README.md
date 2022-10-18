# Python sample app

This is a sample application showing integration with FusionAuth and OAuth/OIDC.

This is based on the [5 minute setup guide](https://fusionauth.io/docs/v1/tech/5-minute-setup-guide) but using python3 instead of JavaScript.

## Prerequisites

* FusionAuth
* python3
* pip3

## Installation

* `python3 -m venv venv`
* `. venv/bin/activate`
* `pip3 install -r requirements.txt`
* Create an application in FusionAuth
  * In the OAuth tab for the application configs:
    - Set authorized redirect URLs:
        - `http://localhost:5000/oauth-callback`
        - `http://localhost:5000/`
    - Turn on the "Generate Refresh Tokens" setting. This is required in order to receive a refresh token
    - Select "Refresh Token" as an enabled grant. This is required in order to enable refresh requests to work
    - Create a role in the application called "deactivated". See discussion below under [User invalidation](#user-invalidatin)
    - Note the client id and client secret
  * Register a user for this application
* Create an API key in FusionAuth. (Optional, only if you want to use the client for API operations.)
* Update `app/views.py` with the values gathered above (look for the `#UPDATE ME` section), or set the following environment variables to use as-is:
  * `FUSIONAUTH_API_KEY`
  * `FUSIONAUTH_CLIENT_ID`
  * `FUSIONAUTH_CLIENT_SECRET`

## Running

`flask --app app --debug run`

Visit `http://localhost:5000`

## About the auth implementation

It is not recommended to store sensitive user data in a Flask session. See, for example,
[How Secure Is the Flask User Session](https://blog.miguelgrinberg.com/post/how-secure-is-the-flask-user-session)

The [FusionAuth Flask portal example](https://github.com/FusionAuth/fusionauth-example-flask-portal)
stores both the oAuth2 access token (a non-revokable JWT) as well as the full FusionAuth
user payload in the Flask session. This seems like a mistake.

The FusionAuth workflow specified [here](https://fusionauth.io/learn/expert-advice/authentication/webapp/oauth-authorization-code-grant-jwts-refresh-tokens-cookies)
claims to be secure because it uses HTTP-only cookies. This does enhance security in
that the cookies are not accessible via Javascript. However, a workflow like that described
seems to be a bit elusive as FusionAuth does not seem to consistently set these cookies
during the authentication callback. Sometimes it does, sometimes it does not, and it is
not clear what the conditions are for ensuring these cookies to be set.

Regardless, part of this workflow still requires explicitly setting the cookies at certain
points. Doing this in Flask is a bit quirky -- cookies can only be set directly via the
response object, which is only available after the request call. If cookies are set by
the app, one should consider potential security options (i.e., the [`secure`, `httponly`,
and `samesite` options](https://flask.palletsprojects.com/en/2.2.x/security/?highlight=sessions#set-cookie-options).

As a much simpler alternative approach, the example code here makes use of the
[Flask-Session](https://flask-session.readthedocs.io) extension which provides a number
of server-side backends for session data storage (including redis, memcached, filesystem,
mongodb, and sqlalchemy). With this approach, only a session key is sent to the client,
and all sensitive info from FusionAuth is only stored server-side.

## Security considerations


### Irrevocable access tokens

A caveat should be mentioned regarding access tokens: FusionAuth does not
provide an API endpoint for revoking OAuth2 access tokens. These tokens are JWTs which
are meant to be portable and are not persisted by FusionAuth itself. Therefore, there is
no mechanism for invalidating these tokens. The philosophy of this design decision is
explained somewhat in the issue [here](https://github.com/FusionAuth/fusionauth-issues/issues/25).
See also [this discussion thread](https://fusionauth.io/community/forum/topic/270/logout-questions).
There is a relevant [RFC for access token revocation as a feature](https://github.com/FusionAuth/fusionauth-issues/issues/201)
and I recommend giving it a thumbs up, as this seems like a valid security concern and
there is not a lot of traction on this request at this time.

As it is, the current approach mitigates these concerns by deleting the access_token
session data during the logout, which means the browser will not have any path to
triggering a call with that token even if the session itself is still valid. Furthermore,
the access token itself is never exposed externally due to the server-side data storage
approach of the Flask-Session extension.

If the inability to revoke the access token before it times out is still of concern,
there is a workaround described in [this issue](https://github.com/FusionAuth/fusionauth-python-client/issues/15)
which essentially involves implementing webhooks which keep track of historically
invalidated access tokens and ensuring any new requests are not using such a token.

Note that these concerns do not apply to refresh tokens, as FusionAuth provides an
endpoint to revoke refresh tokens which is used in this example during the logout cycle.


### User invalidation

For the given workflow of self-registration, there is not a straightforward path to
administratively deactivating a user for a given application. Neither deleting the
user's application registration nor deleting the actual user is a sure path to success
as the user and/or registration may be re-generated through certain application requests.

An attempt was made at an approach of utiling an active role for the application. The
workflow for this approach is a bit elusive: the role cannot be the default, or it 
will simply be re-generated along with the re-generated registration. Setting the role
explicitly upon registration can be a bit tricky because the related workflow issues
make it difficult to descern a legitimate registration callback from various workflow
callbacks. The following approach is being explored as a result:

The selected approach to dealing with this is to add a "deactivated" role for the
application. This role is checked during the user lookup, and a user with the
deactivated role is considered not to be registered with the application. Thus, to
administratively deactivate the user for the application, do not delete the user or
the user's registrations, but instead assign the user to the deactivated role.
This is not a perfect solution, but it seems to work better than an "active" role approach.
"""

# Contributors

* [Nishant Trivedi/nishant009](https://github.com/nishant009) did the initial implementation. 

