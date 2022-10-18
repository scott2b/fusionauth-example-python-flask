import os
import urllib.parse
from app import app
from flask import Flask, redirect, request, render_template, send_from_directory, session, url_for
from fusionauth.fusionauth_client import FusionAuthClient
import pkce


#UPDATE ME (or set the environment variables)
API_KEY = os.environ["FUSIONAUTH_API_KEY"]
CLIENT_ID = os.environ["FUSIONAUTH_CLIENT_ID"]
CLIENT_SECRET = os.environ["FUSIONAUTH_CLIENT_SECRET"]
FUSIONAUTH_HOST_IP = os.environ.get("FUSIONAUTH_HOST_IP", "localhost")
FUSIONAUTH_HOST_PORT = os.environ.get("FUSIONAUTH_HOST_PORT", "9011")
#/UPDATE ME


client = FusionAuthClient(API_KEY, f"http://{FUSIONAUTH_HOST_IP}:{FUSIONAUTH_HOST_PORT}")


### User object

class UnauthenticatedUser:

    @property
    def is_authenticated(self):
        return False


class User:

    def __init__(self, *, active, id, email, insertInstant,
            lastUpdateInstant, lastLoginInstant, passwordLastUpdateInstant,
            passwordChangeRequired, firstName=None, lastName=None, **kwargs):
        """Enable `First name` and `Last name` in the application registration configs if
        you want FusionAuth to provide them to be passed in here.
        """
        # TODO: extract group memberships from `memberships` kwarg
        # TODO: username is application specific and needs to be extracted from registrations
        self.active = active
        self.user_id=id
        self.email=email
        self.first_name = firstName
        self.last_name = lastName
        self.created_at=insertInstant
        self.updated_at=lastUpdateInstant
        self.last_login=lastLoginInstant
        self.pwd_updated_at=passwordLastUpdateInstant
        self.pwd_change_required=passwordChangeRequired

    @property
    def is_authenticated(self):
        return True


### Helpers

"""
Any callback / redirect URLs must be specified in the "Authorized Redirect URLs" for the
application OAuth config in FusionAuth.

Be aware of trailing slash issues when configuring these URLs. E.g. Flask's url_for
will include a trailing slash here on `url_for("index")`
"""

def fusionauth_register_url(code_challenge, scope="offline_access"):
    """offline_access scope is specified in order to recieve a refresh token."""
    callback = urllib.parse.quote_plus(url_for("oauth_callback", _external=True))
    return f"http://{FUSIONAUTH_HOST_IP}:{FUSIONAUTH_HOST_PORT}/oauth2/register?client_id={CLIENT_ID}&response_type=code&code_challenge={code_challenge}&code_challenge_method=S256&scope={scope}&redirect_uri={callback}"


def fusionauth_login_url(code_challenge, scope="offline_access"):
    """offline_access scope is specified in order to recieve a refresh token."""
    callback = urllib.parse.quote_plus(url_for("oauth_callback", _external=True))
    return f"http://{FUSIONAUTH_HOST_IP}:{FUSIONAUTH_HOST_PORT}/oauth2/authorize?client_id={CLIENT_ID}&response_type=code&code_challenge={code_challenge}&code_challenge_method=S256&scope={scope}&redirect_uri={callback}"


def fusionauth_logout_url():
    """
    Alternatively to specifying the `post_logout_redirect_uri`, set the Logout URL in
    the application configuration OAuth tab.
    """
    redir = urllib.parse.quote_plus(url_for("index", _external=True))
    return f"http://{FUSIONAUTH_HOST_IP}:{FUSIONAUTH_HOST_PORT}/oauth2/logout?client_id={CLIENT_ID}&post_logout_redirect_uri={redir}"


def user_is_registered(registrations, app_id=CLIENT_ID):
    return all([
        registrations is not None,
        len(registrations) > 0,
        any(r["applicationId"] == app_id and not "deactivated" in r["roles"] for r in registrations)])


### Handlers

@app.before_request
def load_user():
    """Using the session-stored access and refresh tokens provided by the FusionAuth
    login, fetch the user info from FusionAuth and set the user object on the request.

    It is not recommended to directly set the user in the session due to the fact that
    user info may be modified in FusionAuth, including administrative deactivation,
    during the session lifecycle. In any case, it is not recommended to set any
    sensitive info in client-side cookies, thus the server-side Flask-Session extension
    is used for session data storage.
    """
    user = UnauthenticatedUser()
    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token")
    if access_token:
        user_resp = client.retrieve_user_using_jwt(access_token)
        if not user_resp.was_successful() and refresh_token:
            token_resp = client.exchange_refresh_token_for_access_token(
                refresh_token,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET)
            if token_resp.was_successful():
                access_token = token_resp.success_response["access_token"]
                refresh_token = token_resp.success_response["refresh_token"]
                session["access_token"] = access_token
                session["refresh_token"] = refresh_token
            else:
                access_token = None
                refresh_token = None
        if access_token is not None:
            user_resp = client.retrieve_user_using_jwt(access_token)
            if user_resp.was_successful():
                registrations = user_resp.success_response["user"]["registrations"]
                if user_is_registered(registrations):
                    user = User(**user_resp.success_response["user"])
                else: # The user registration may have been administratively deleted
                    pass
    request.user = user


### Routes

@app.route("/")
def index():
    return render_template("public/index.html")


@app.route("/oauth-callback")
def oauth_callback():
    request.user = UnauthenticatedUser()
    if "access_token" in session:
        del session["access_token"]
    if "refresh_token" in session:
        del session["refresh_token"]

    if not request.args.get("code"):
        return render_template(
            "public/error.html",
            msg="Failed to get auth token.",
            reason=request.args["error_reason"],
            description=request.args["error_description"]
        )
    uri = url_for("oauth_callback", _external=True),
    tok_resp = client.exchange_o_auth_code_for_access_token_using_pkce(
        request.args.get("code"),
        uri,
        session['code_verifier'],
        CLIENT_ID,
        CLIENT_SECRET,
    )
    if not tok_resp.was_successful():
        return render_template(
            "public/error.html",
            msg="Failed to get auth token.",
            reason=tok_resp.error_response["error_reason"],
            description=tok_resp.error_response["error_description"],
        )
    access_token = tok_resp.success_response["access_token"]
    refresh_token = tok_resp.success_response.get("refresh_token")
    assert refresh_token is not None, 'To receive a refresh token, be sure to enable ' \
        '"Generate Refresh Tokens" for the app, and specify `scope=offline_access` in '\
        'the request to the authorize endpoint.'

    user_resp = client.retrieve_user_using_jwt(access_token)
    if not user_resp.was_successful():
        return render_template(
            "public/error.html",
            msg="Failed to get user info.",
            reason=tok_resp.error_response["error_reason"],
            description=tok_resp.error_response["error_description"],
        )

    registrations = user_resp.success_response["user"]["registrations"]

    if not user_is_registered(registrations):
        return render_template(
            "public/error.html",
            msg="User not registered for this application.",
            reason="Application id not found in user object.",
            description="Did you create a registration for this user and this application?"
        )

    request.user = User(**user_resp.success_response["user"])
    session["access_token"] = access_token
    session["refresh_token"] = refresh_token
    return redirect("/")


@app.route("/register")
def register():
    """To use registration, enable self-service registration in the Registration tab of
    the application configuration in FusionAuth. You may also want to enable specific
    registration properties such as First Name and Last Name to be passed into the
    User constructor.
    """
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    session['code_verifier'] = code_verifier
    return redirect(fusionauth_register_url(code_challenge))


@app.route("/login")
def login():
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    # save the verifier in session to send it later to the token endpoint
    session['code_verifier'] = code_verifier
    return redirect(fusionauth_login_url(code_challenge))


@app.route("/logout")
def logout():
    revoke_resp = client.revoke_refresh_tokens_by_application_id(CLIENT_ID)
    # TODO: should we check for success?

    # IMPORTANT: For the access token especially, if we do not delete it from
    # the session, the user will still be logged in for the duration of the token's
    # lifetime, which is specified by the application's "JWT duration" setting in
    # FusionAuth. FusionAuth does not provide a way to invalidate the access token.
    # See [RFC 7009](https://github.com/FusionAuth/fusionauth-issues/issues/201)
    if "access_token" in session:
        del session["access_token"]
    if "refresh_token" in session:
        del session["refresh_token"]

    return redirect(fusionauth_logout_url())


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "app/static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )
