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
    - Set the redirect url to `http://localhost:5000/oauth-callback`
    - Turn on the "Generate Refresh Tokens" setting
    - Select "Refresh Token" as an enabled grant
    - Note the client id and client secret
  * Register a user for this application
* Create an API key in FusionAuth. (Optional, only if you want to use the client for API operations.)
* Update `app/views.py` with the values gathered above (look for the `#UPDATE ME` section), or set the following environment variables to use as-is:
  * `FUSIONAUTH_API_KEY`
  * `FUSIONAUTH_CLIENT_ID`
  * `FUSIONAUTH_CLIENT_SECRET`

## Running

`flask --app app run`

Visit `http://localhost:5000`

# Contributors

* [Nishant Trivedi/nishant009](https://github.com/nishant009) did the initial implementation. 

