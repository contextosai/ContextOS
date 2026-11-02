"""Obtains a Keycloak delegated token: the agent acting for a user.

1. The user signs in to the login client asking to delegate to the agent
   (`delegation:client:<agent>`), and consents. Keycloak adds `may_act` to the
   user's token. (This drives the login and consent forms the way a browser would.)
2. The agent gets its own token (client credentials).
3. The agent exchanges the user's token, presenting its own as `actor_token`.
   Keycloak returns a token whose `sub` is the user and whose `act` names the agent.

Prints {"user_token", "agent_token", "delegated_token"} as JSON.

Usage: python3 delegate.py <issuer> <agent client id> <agent secret> <login client id>
           <username> <password>
"""

import html
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ISSUER, AGENT, SECRET, LOGIN_CLIENT, USERNAME, PASSWORD = sys.argv[1:7]
REDIRECT = "http://localhost/callback"
TOKEN = f"{ISSUER}/protocol/openid-connect/token"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


cookies = http.cookiejar.CookieJar()
browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies), NoRedirect)
LOCAL = urllib.parse.urlparse(ISSUER).hostname in ("localhost", "127.0.0.1")


def visit(url, form=None):
    """Returns (status, location, body) without following redirects."""
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    if LOCAL:
        # Browsers send Secure cookies to http://localhost; Python's jar does not.
        for cookie in cookies:
            cookie.secure = False
    try:
        with browser.open(urllib.request.Request(url, data=data)) as response:
            return response.status, None, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("Location"), error.read().decode()


def form_of(page, prefer=None):
    """The action and hidden fields of the page's form."""
    action = html.unescape(re.search(r'<form[^>]*action="([^"]+)"', page).group(1))
    action = urllib.parse.urljoin(ISSUER, action)
    fields = dict(re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page))
    if prefer:
        fields.update(prefer)
    return action, fields


def token(form):
    try:
        with urllib.request.urlopen(TOKEN, urllib.parse.urlencode(form).encode()) as response:
            return json.load(response)["access_token"]
    except urllib.error.HTTPError as error:
        raise SystemExit(f"token request failed: {error.code} {error.read().decode()}") from None


def user_token():
    query = urllib.parse.urlencode({
        "client_id": LOGIN_CLIENT, "response_type": "code", "redirect_uri": REDIRECT,
        "scope": f"openid organization delegation:client:{AGENT}",
    })
    status, location, page = visit(f"{ISSUER}/protocol/openid-connect/auth?{query}")
    # Username, password (organizations sign in identity first) and consent pages.
    for _ in range(6):
        if location is not None and not location.startswith(REDIRECT):
            status, location, page = visit(urllib.parse.urljoin(ISSUER, location))
            continue
        if location is not None or "<form" not in page:
            break
        answers = {}
        if 'name="username"' in page:
            answers["username"] = USERNAME
        if 'name="password"' in page:
            answers["password"] = PASSWORD
        if 'name="accept"' in page:
            answers["accept"] = "Yes"
        status, location, page = visit(*form_of(page, answers))
    if location is None or "code=" not in location:
        raise SystemExit(f"sign-in did not return a code (status {status}, location {location})")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
    return token({"grant_type": "authorization_code", "client_id": LOGIN_CLIENT,
                  "code": code, "redirect_uri": REDIRECT})


def main():
    subject = user_token()
    actor = token({"grant_type": "client_credentials", "client_id": AGENT, "client_secret": SECRET,
                   "scope": "organization"})
    access = "urn:ietf:params:oauth:token-type:access_token"
    delegated = token({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": AGENT, "client_secret": SECRET,
        "subject_token": subject, "subject_token_type": access,
        "actor_token": actor, "actor_token_type": access,
        "scope": "organization",
    })
    print(json.dumps({"user_token": subject, "agent_token": actor, "delegated_token": delegated}))


main()
