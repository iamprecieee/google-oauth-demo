"""
Google OAuth Demo
==========================================
1. We receive Google's ID token (a short-lived JWT from Google)
2. We verify it and extract claims (sub, email, name)
3. We issue OUR OWN JWT access token
4. We DISCARD the Google ID token — it is NOT stored anywhere

The Google ID token expires in ~1 hour and changes every sign-in.
The 'sub' claim is the only stable identifier — stored in user_identities.provider_user_id
"""

import datetime
import logging
import os

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from jose import JWTError, jwt

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(message)s")
logger = logging.getLogger("google-oauth-demo")

app = FastAPI(title="Google OAuth Demo")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
JWT_SECRET = os.getenv("JWT_SECRET", "demo-secret")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

security = HTTPBearer()


# ---------------------------------------------------------------------------
# Verify Google ID token → issue our own JWT
# ---------------------------------------------------------------------------
@app.post("/auth/google/authenticate")
async def verify_google_token(request: Request):
    body = await request.json()
    google_credential = body.get("credential")

    if not google_credential:
        raise HTTPException(400, "Missing credential")

    # ── Step 1: Verify the Google ID token ──────────────────────────
    try:
        id_info = id_token.verify_oauth2_token(
            google_credential, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except ValueError as exc:
        logger.error(f"❌ Google token verification FAILED: {exc}")
        raise HTTPException(401, "Invalid Google ID token")

    # ── Step 2: Extract the claims we need ──────────────────────────────
    google_sub = id_info["sub"]  # ← This is the STABLE identifier
    email = id_info.get("email")
    name = id_info.get("name")
    picture = id_info.get("picture")

    logger.info(f"Verified Google user: {email} (sub: {google_sub})")

    # ── Step 4: Issue OUR OWN JWT ───────────────────────────────────────
    payload = {
        "sub": google_sub,
        "email": email,
        "name": name,
        "picture": picture,
        "provider": "google",
        "exp": datetime.datetime.utcnow()
        + datetime.timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    our_jwt = jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

    logger.info("Issued our own JWT for this user")

    # ── Step 5: DISCARD Google ID token ─────────────────────────────────
    # We do NOT store google_credential anywhere. It's already verified,
    # claims extracted, and it expires in ~1 hour anyway.
    logger.info("Google ID token DISCARDED — not stored anywhere")

    return {
        "status": "success",
        "message": f"Authenticated {email} via Google",
        "access_token": our_jwt,
        "token_type": "bearer",
        "extracted_claims": {
            "sub": google_sub.replace("1", "*").replace("2", "*").replace("5", "*"),
            "email": email,
            "name": name,
            "picture": picture,
        },
        "flow_explanation": {
            "step_1": "Received Google ID token. Verified signature against Google's public keys",
            "step_2": f"Extracted stable identifier: sub={google_sub.replace('1', '*').replace('2', '*').replace('5', '*')}",
            "step_3": "Issued OUR OWN JWT using extracted claims",
            "step_4": "DISCARDED the Google ID token",
            "why_not_store": (
                "The Google ID token expires in ~1 hour and changes every "
                "sign-in. The 'sub' claim is what stays constant, that's "
                "what goes in user_identities.provider_user_id"
            ),
        },
    }


# ---------------------------------------------------------------------------
# Protected endpoint — uses OUR JWT, not Google's
# ---------------------------------------------------------------------------
@app.get("/auth/me")
async def get_me(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(401, "Invalid or expired token")

    return {
        "authenticated_with": "Our own JWT (NOT Google's token)",
        "google_token_stored": False,
        "user": {
            "google_sub": payload["sub"]
            .replace("1", "*")
            .replace("2", "*")
            .replace("5", "*"),
            "email": payload["email"],
            "name": payload["name"],
            "picture": payload.get("picture"),
            "provider": payload["provider"],
        },
        "note": (
            "This response comes from decoding OUR JWT. "
            "The Google ID token was discarded after verification. "
            "We only kept the 'sub' as the stable user identifier."
        ),
    }


# ---------------------------------------------------------------------------
# Landing page with Google Sign-In button
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def landing_page():
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Google OAuth Demo</title>
<script src="https://accounts.google.com/gsi/client" async></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',system-ui,sans-serif;min-height:100vh;
display:flex;align-items:center;justify-content:center;padding:24px}}
.container{{max-width:640px;width:100%}}

h1{{font-size:28px;font-weight:800;
-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}}
.subtitle{{font-size:14px;margin-bottom:32px}}
.card{{border:1px solid #27272a;border-radius:12px;padding:32px;margin-bottom:16px}}
.g-btn-wrap{{display:flex;justify-content:center;margin:8px 0}}

.steps{{display:none;margin-top:24px}}
.step{{display:flex;gap:14px;padding:14px 0;border-bottom:1px solid #27272a}}
.step:last-child{{border:none}}
.step-num{{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;
font-size:12px;font-weight:700;flex-shrink:0}}
.step-num.done{{background:#22c55e}}
.step-num.discard{{background:#ef4444}}
.step-label{{font-size:13px;line-height:1.5}}
.step-label strong{{}}
.step-label code{{padding:2px 6px;border-radius:4px;font-size:12px}}

.result{{margin-top:20px;border:1px solid #27272a;border-radius:8px;padding:20px;display:none}}
.result h3{{font-size:14px;margin-bottom:12px;text-transform:uppercase;letter-spacing:1px}}
.result pre{{font-size:12px;white-space:pre-wrap;word-break:break-all;line-height:1.6}}

.me-btn{{margin-top:16px;color:#fff;border:none;padding:10px 20px;border-radius:8px;
font-family:inherit;font-weight:600;cursor:pointer;font-size:13px;transition:background .2s}}
.me-btn:hover{{background:#4f46e5}}

.me-result{{margin-top:12px;display:none}}

.tag{{display:inline-block;font-size:11px;font-weight:600;padding:3px 8px;border-radius:4px;margin-bottom:8px}}
.tag-green{{background:#052e16;color:#4ade80;border:1px solid #14532d}}
.tag-red{{background:#2a0a0a;color:#f87171;border:1px solid #450a0a}}
.tag-blue{{color:#60a5fa;border:1px solid #1e3a6e}}

</style>
</head>
<body>
<div class="container">
<h1>Google OAuth Demo</h1>

<div class="card">
<div class="g-btn-wrap">
<div id="g_id_onload"
     data-client_id="{GOOGLE_CLIENT_ID}"
     data-callback="handleCredentialResponse"
     data-auto_prompt="false">
</div>
<div class="g_id_signin" data-type="standard" data-size="large"
     data-theme="filled_black" data-text="sign_in_with" data-shape="rectangular">
</div>
</div>

<div class="steps" id="steps">
<div class="step" id="s1">
<div class="step-num done">1</div>
<div class="step-label"><strong>Received</strong> Google ID token from client<br>
<span style="color:#71717a;font-size:12px">This is a short-lived JWT issued by Google (~1hr expiry)</span></div>
</div>
<div class="step" id="s2">
<div class="step-num done">2</div>
<div class="step-label"><strong>Verified</strong> token signature against Google's public keys</div>
</div>
<div class="step" id="s3">
<div class="step-num done">3</div>
<div class="step-label"><strong>Extracted</strong> claims: <code id="extracted"></code></div>
</div>
<div class="step" id="s4">
<div class="step-num done">4</div>
<div class="step-label"><strong>Issued</strong> our own JWT using extracted claims<br>
<span class="tag tag-green">&#x2713; This is what we store &amp; use for auth</span></div>
</div>
<div class="step" id="s5">
<div class="step-num discard">5</div>
<div class="step-label"><strong>DISCARDED</strong> Google ID token<br>
<span class="tag tag-red">&#x2717; NOT stored anywhere, expires in ~1hr anyway</span></div>
</div>
</div>
</div>


<div class="result" id="result">
<h3>Server Response</h3>
<pre id="result-json"></pre>
<button class="me-btn" onclick="callMe()">Call /auth/me with generated JWT &rarr;</button>
<div class="me-result" id="me-result">
<br><span class="tag tag-blue">Response from /auth/me</span>
<pre id="me-json"></pre>
</div>
</div>
</div>

<script>
let storedToken = null;

function handleCredentialResponse(response) {{
    document.getElementById('steps').style.display='block';
    fetch('/auth/google/authenticate', {{
        method:'POST',
        headers:{{'Content-Type':'application/json'}},
        body:JSON.stringify({{credential:response.credential}})
    }})
    .then(r=>r.json())
    .then(data=>{{
        if(data.error){{alert(data.detail||'Auth failed');return;}}
        storedToken=data.access_token;
        const c=data.extracted_claims||{{}};
        document.getElementById('extracted').textContent=
            'sub='+c.sub+', email='+c.email+', name='+c.name;
        document.getElementById('result').style.display='block';
        document.getElementById('result-json').textContent=JSON.stringify(data,null,2);
    }})
    .catch(e=>alert('Error: '+e));
}}

function callMe(){{
    if(!storedToken)return;
    fetch('/auth/me',{{headers:{{'Authorization':'Bearer '+storedToken}}}})
    .then(r=>r.json())
    .then(data=>{{
        document.getElementById('me-result').style.display='block';
        document.getElementById('me-json').textContent=JSON.stringify(data,null,2);
    }});
}}
</script>
</body>
</html>"""
