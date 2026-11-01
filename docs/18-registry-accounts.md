# 18 · Registry accounts (PyPI and TestPyPI)

For maintainers who publish SkillSentry. You create **two** accounts: one on PyPI and one on TestPyPI. They are separate services with separate passwords, two-factor methods, and recovery codes. You can use the same email address for both.

Only you can do these steps: they need your email, your phone, and your security key. The steps below come from PyPI's own documentation. Button labels can change, so follow the wording on screen when it differs.

## Before you start

- A **real email address you control**. Disposable addresses are rejected.
- A **password manager**, for the password and the recovery codes.
- An **authenticator app** on a phone, and ideally a **hardware security key** (a USB or NFC FIDO key). PyPI does not offer SMS codes.

## 1. Create the PyPI account

1. Open <https://pypi.org> and choose **Register**.
2. Enter your details and a long, unique password. Accept the Terms of Service. If you see "Too many registration attempts", wait and try again later.
3. **Verify your email.** PyPI sends a confirmation link. A verified email is required before you can register a project or upload. If the email does not arrive, open <https://pypi.org/manage/account/> and request a new one.

## 2. Turn on two-factor authentication (PyPI)

Two-factor authentication is mandatory on PyPI. Set it up in **Account settings** (<https://pypi.org/manage/account/>), in this order:

1. **Generate recovery codes first.** Choose **Generate recovery codes**. Save them in your password manager, or print them and keep them somewhere physically safe. Each code works once. Submit one code when PyPI asks, to prove you saved them. Generating a new set invalidates the old one.
2. **Add an authentication app.** Choose **Add 2FA with authentication application**. Scan the QR code, or type the key into your app, then enter the six-digit code it shows. PyPI allows one authentication app per account.
3. **Add a security key (strongly recommended).** Choose **Add 2FA with security device (e.g. USB key)**. Give the key a name, choose **Set up security device**, and follow your browser's prompt. A security key resists phishing, which is why PyPI recommends it when you can use one.

PyPI asks you to confirm your password for these steps. This is normal for sensitive actions.

**Test it:** sign out, then sign back in with your password and a two-factor code. Do not spend a recovery code on this test.

PyPI recommends at least two methods, so that losing one does not lock you out.

## 3. Create the TestPyPI account

Repeat sections 1 and 2 at <https://test.pypi.org/account/register/>. Use a separate password, separate two-factor methods, and separate recovery codes.

Two differences to know:

- TestPyPI's database is pruned from time to time, and accounts can be deleted. If your login stops working, register again.
- To install a test release, use the TestPyPI index for the package and the real index for its dependencies:

```bash
python -m pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ skill-sentry==<version>
```

## 4. Register the trusted publisher

Trusted publishing lets the release workflow publish without storing an API token. Register one *pending publisher* on each index, while signed in:

**Account settings → Publishing → Add a new pending publisher → GitHub Actions**

| Field | PyPI | TestPyPI |
|:---|:---|:---|
| PyPI project name | `skill-sentry` | `skill-sentry` |
| Owner | `EmberPhantom` | `EmberPhantom` |
| Repository name | `SkillSentry` | `SkillSentry` |
| Workflow filename | `release.yml` | `release.yml` |
| Environment name | `pypi` | `testpypi` |

Warnings from PyPI's documentation:

- **A pending publisher does not reserve the project name.** If someone else registers `skill-sentry` first, your pending publisher becomes invalid. Publish soon after you register.
- **The first successful publish converts it** into a normal publisher. No further setup is needed.

## 5. Set up GitHub to match

On GitHub, in the repository:

1. Turn on two-factor authentication for your own GitHub account. Anyone who can publish can change the release workflow, so protect the account.
2. Go to **Settings → Environments** and create `testpypi` and `pypi`.
3. On `pypi`, add a **required reviewer**. Nothing reaches PyPI until that reviewer approves the run.

## If you lose access

- **Forgotten password:** use the password reset page on the index, with your email or username.
- **Lost authentication app, security key, and recovery codes:** there is no self-service path. File an issue with PyPI's support tracker. Replies can take a week or more, which is why two methods and stored recovery codes matter.

## Checklist

- [ ] PyPI: email verified, recovery codes saved and one of them submitted, authentication app added, security key added
- [ ] TestPyPI: the same four items
- [ ] Pending publisher added on PyPI and on TestPyPI, with the values in section 4
- [ ] GitHub: two-factor on, environments `testpypi` and `pypi` created, required reviewer on `pypi`

## Sources

PyPI documentation: two-factor authentication, account recovery, managing your account, and creating a project through OIDC (trusted publishers). Python Packaging User Guide: using TestPyPI.
