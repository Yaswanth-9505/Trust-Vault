# Your step-by-step guide

This is for you, not for the judges. Delete it, or keep it out of the repo, before submitting.

Nobody can promise you a place in the next round. What gets people shortlisted on this brief is:

1. Nothing leaks on the live site.
2. An honest, thorough THREATS.md.
3. A PROMPTS.md built up during the week.
4. **Being able to explain and change the code live in the interview.**

The code gives you a strong base for the first two. The last two depend on you. Follow the steps below.

---

## Step 0: Set up on your machine (30 minutes)

1. Install Python 3.11 or newer (python.org) and Git.
2. Unzip the project, then open a terminal inside the `trustvault` folder.
3. Create a virtual environment and install:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate          # Windows
   source .venv/bin/activate       # Mac / Linux
   pip install -r requirements.txt
   ```

4. Seed and run:

   ```bash
   python -m scripts.seed
   python wsgi.py
   ```

   Then open http://127.0.0.1:5000.

5. Sign in as each demo account (the passwords are in README.md) and click through everything.
6. Run the tests:

   ```bash
   python -m unittest discover -s tests -t . -v
   ```

   Expect 85 tests, all OK.

7. Run the mutation check:

   ```bash
   python -m scripts.mutation_check
   ```

   Expect 28/28 killed. This takes a few minutes.

## Step 1: Put it on GitHub with honest history (day 1)

The brief says "history across the week rather than one commit at the end". **Do not fake commit dates.** The judges can see push times, and faking them is the kind of thing that ends a candidacy. Do this instead:

1. Create a **public** repository on GitHub called `trustvault`.
2. Commit in logical pieces, today, as you read each part:

   ```bash
   git init
   git add app/schema.sql app/db.py app/config.py app/security.py requirements.txt .gitignore
   git commit -m "Schema, config, crypto helpers"
   git add app/audit.py app/auth.py app/authz.py app/errors.py app/__init__.py
   git commit -m "Sessions, central authorisation, hash-chained audit log"
   git add app/routes app/uploads.py app/retention.py wsgi.py
   git commit -m "Document, sharing and admin routes"
   git add app/static
   git commit -m "UI"
   git add tests scripts
   git commit -m "Security tests, seed, mutation check"
   git add *.md docs Dockerfile .env.example
   git commit -m "Threat model, API docs, write-up, deployment"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/trustvault.git
   git push -u origin main
   ```

3. Through the rest of the week, every change you make (see Step 4) is a new commit with a real date. That is your history.

## Step 2: Deploy on day 1, not day 7

Follow "Deploy to PythonAnywhere" in README.md exactly. Then:

1. Put your live URL at the top of README.md, commit and push.
2. On the live site, do a quick attack check. Sign in as `victor@trustvault.test`, open a document he has access to, and copy its URL. Sign in as `ext@partner.test` in a private window and paste that URL. You should see "Document not found".
3. Generate the keys **on the server**. Never commit `.env`.
4. Save `TV_MASTER_KEY` and `TV_AUDIT_KEY` in a password manager. If you lose the master key, every uploaded file is unreadable.

## Step 3: Learn the code (days 1–3). This is the most important step.

Read these files in this order, with the questions beside them:

| File | Be able to answer |
|---|---|
| `app/authz.py` | What are the four rules? Why 404 and not 403 for strangers? Why does `access_level` ignore role? |
| `app/routes/documents.py` → `download()` | Where is the decision? Why is it inside `with transaction`? Why is the audit written *before* the bytes are returned? |
| `app/auth.py` | How does a cookie become a user? Why does revocation work instantly? What do `csrf_protect` and `SameSite=Strict` each stop? |
| `app/audit.py` | What exactly is hashed? Why HMAC and not plain SHA-256? What can't the chain detect (tail truncation), and what covers it? |
| `app/routes/grants.py` | Why is every grant lookup `WHERE id = ? AND document_id = ?`? Why can't suggestions grant access? |
| `app/uploads.py` | Why an allow-list? Why check magic bytes? Why do downloads still use octet-stream when the type has been checked? |
| `app/security.py` | What is envelope encryption? What does the associated data (`blob_id`) prevent? |

### The interview question they told you they will ask

**"Where is the authorisation decision made when someone downloads a file, and what happens if that line is removed?"**

Answer like this:

> It's in `app/routes/documents.py`, in `download()`: the line `doc = authorize(doc_id, "download")`, inside the transaction. `authorize()` in `app/authz.py` loads the document, refuses it if it's trashed or purged, computes my level from the database (owner, or a live, unexpired grant), and checks the level allows 'download'. If I remove that line, any signed-in user who knows or guesses a document id can download it. The version lookup is keyed on the document id, so that alone doesn't protect anything. The mutation check proves the tests catch it: the `download-authorize` mutant fails 16 tests, including the route-walker test, which tries every route as three different strangers.

Practise saying this out loud until you can do it without the file open.

## Step 4: Make the code yours (days 2–6): changes to make and log in PROMPTS.md

Make each of these changes yourself, with AI help if you like. For each one: commit it, and if the AI got something wrong, add a PROMPTS.md entry with the commit link. They are also likely "live change" tasks in the interview.

1. **Add a fourth category, `Procurement`.**
   - Touch `CATEGORIES` in `app/routes/__init__.py`, the `CHECK` constraint in `schema.sql`, `state.categories` in `app.js`, and add a test.
   - Watch for: an existing database keeps the old `CHECK`. That is a migration problem, so write that down.
2. **Require a grant expiry for HR documents.**
   - In `create_grant`, if `doc["category"] == "HR"` and there is no `expires_at`, return 400.
   - Add a test, and a mutant to `scripts/mutation_check.py`.
3. **Let owners see the activity record for one grantee only.**
   - Filter by `target_user_id` or `actor_id` in `document_activity`.
4. **Alert when a deactivated user's documents are still shared.**
   - Add a new block in `alerts()`.
5. **Show "last downloaded by" on the document page**, owner only.
   - Watch for: must this be owner-only? (Yes: it reveals who else has access.) A good PROMPTS.md entry if the AI exposes it to readers.

Each time, ask: "if I deleted the check I just added, would a test fail?" Then run the mutant and see.

## Step 5: Fill in PROMPTS.md honestly (all week)

- Follow the instructions in the box at the top of PROMPTS.md for entries 1–6.
- Add **at least two more of your own**, from Step 4 or anything else. Date them the day you actually do them, and commit the same day.

Good habit: before accepting any AI answer about permissions, ask the AI for "the test that would fail if this is wrong", run it, then delete the check and run it again.

## Step 6: Record the five-minute demo (day 6)

Use OBS or Loom, recording the live URL. Suggested script:

| Time | Show |
|---|---|
| 0:00–0:30 | What TrustVault is. The three roles. The one rule: "the server decides, every request". |
| 0:30–1:30 | As **Olivia**: upload a file, then share it with Vera as read with an expiry date. Open the custody record. |
| 1:30–2:15 | As **Vera** in another browser: download it. As **Olivia**: revoke. As **Vera**: click download again → refused. Back as Olivia: the custody record shows the refused attempt in red. |
| 2:15–2:45 | As **Victor**: paste Vera's document URL → "not found". As **admin**: the Documents tab shows metadata only, and there is no download. |
| 2:45–3:30 | **Admin → Alerts**: chain intact, repeated refusals flagged. Audit trail filtered to "Refused". Export. |
| 3:30–4:30 | Terminal: run the tests (85 OK), then `python -m scripts.mutation_check download-authorize revoked` → killed. Explain what that proves. |
| 4:30–5:00 | One accepted risk from THREATS.md (tail truncation or admin password reset) and what you would do next. |

Put the video link in README.md.

## Step 7: Final checklist (day 7)

- [ ] The live URL works in a private window. All six demo logins work.
- [ ] Run `python -m scripts.seed --reset` on the server so the judges start from clean data. Then reload the web app.
- [ ] `TV_DEMO_MODE=1` is set on the server.
- [ ] README: live URL, video link, credentials.
- [ ] PROMPTS.md: the note box is deleted, entries are in your words, commit links are filled, and there are at least 2 of your own entries.
- [ ] THREATS.md: you can explain every row. Add anything you found during the week.
- [ ] WRITEUP.md: the permission-model section is rewritten in your own words.
- [ ] `docs/GUIDE.md` (this file) is deleted from the repo.
- [ ] The tests and the mutation check pass on a fresh clone.
