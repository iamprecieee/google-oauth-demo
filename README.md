# Google OAuth Demo — Correct ID Token Flow

A minimal FastAPI app that demonstrates the **correct** way to handle Google OAuth:

1. Receive Google's ID token from the client
2. **Verify** it against Google's public keys
3. **Extract** claims (`sub`, `email`, `name`)
4. **Issue our own JWT** using the extracted claims
5. **Discard** the Google ID token — it is **NOT** stored anywhere

## Quick Start

### 1. Get a Google OAuth Client ID

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Go to **APIs & Services → Credentials**
4. Click **Create Credentials → OAuth 2.0 Client ID**
5. Application type: **Web application**
6. Add **Authorized JavaScript origins**: `http://localhost:8000`
7. Copy the **Client ID**

### 2. Configure & Run

```bash
cd google-oauth-demo

# Create .env from template
cp .env.example .env
# Edit .env and paste your GOOGLE_CLIENT_ID

# Install deps & run
uv sync
uv run fastapi dev main.py
```

Open **http://localhost:8000** and click "Sign in with Google".

## What This Proves

| Concern | Answer |
|---|---|
| "Where do you store the Google auth token?" | **We don't.** It's verified, claims extracted, then discarded. |
| "Google auth token doesn't change" | **It does.** It's a JWT that expires in ~1 hour. The `sub` claim is what's stable. |
| "Why not store it in a column?" | Because it's **useless after verification**. Storing an expired JWT serves no purpose. |
| "What's the stable identifier?" | `sub` — Google's unique user ID. Stored in `user_identities.provider_user_id`. |

## The Flow (Visual)

```
User clicks "Sign in with Google"
        │
        ▼
Google returns ID token (JWT, ~1hr expiry)
        │
        ▼
Backend VERIFIES token (google-auth library)
        │
        ▼
Backend EXTRACTS: sub, email, name, picture
        │
        ├──▶ Look up user by `sub` → create if new
        │    (this is what user_identities stores)
        │
        ├──▶ Issue OUR OWN JWT access token
        │
        └──▶ DISCARD Google ID token 
```

## References

- [Google: Verify ID tokens](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
- [Google: "Do not send ID tokens to your backend via URL parameters"](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
- [Auth0 architecture: federated identity tables](https://auth0.com/docs/manage-users/user-accounts/user-account-linking)
- [Supabase Auth: identities table](https://supabase.com/docs/guides/auth/managing-user-data)
