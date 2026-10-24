# Deploying TrustVault

The target is **PythonAnywhere's free plan**: no credit card, HTTPS included, and it runs Flask and SQLite as they are. The whole process takes about 30 minutes. The result is a site at `https://YOURNAME.pythonanywhere.com`.

Replace `YOURNAME` with your PythonAnywhere username everywhere below.

---

## Part A: Put the code on GitHub (on your own computer)

You need a public repo for the hand-in anyway, and the server will pull the code from it.

1. Install **Git** (git-scm.com) and create a **GitHub** account if you don't have them.
2. On GitHub, click **New repository**:
   - Name it `trustvault`.
   - Choose **Public**.
   - Do **not** tick "Add a README".
   - Click **Create repository**.
3. Unzip `trustvault.zip`, open a terminal in the `trustvault` folder, and run:

   ```bash
   git init
   git add .
   git commit -m "TrustVault: initial version"
   git branch -M main
   git remote add origin https://github.com/YOUR-GITHUB-NAME/trustvault.git
   git push -u origin main
   ```

   If it asks for a password, use a GitHub **personal access token**, not your account password (GitHub → Settings → Developer settings → Personal access tokens).

   > For better marks on commit history, use the split commits in `docs/GUIDE.md` Step 1 instead of one big commit.

4. Check that `.env` and `instance/` are **not** in the repo. The `.gitignore` already excludes them.

## Part B: Create the PythonAnywhere account

1. Go to **pythonanywhere.com** → **Pricing & signup** → **Create a Beginner account** (free).
2. The username you choose becomes your URL, so pick something sensible.
3. Confirm your email.

## Part C: Set up the code on the server

1. In PythonAnywhere, open the **Consoles** tab → **Bash**. A terminal opens in your browser.
2. Paste these lines one at a time:

   ```bash
   git clone https://github.com/YOUR-GITHUB-NAME/trustvault.git
   cd trustvault
   python3.13 -m venv ~/tv-venv
   source ~/tv-venv/bin/activate
   pip install -r requirements.txt
   mkdir -p ~/trustvault-data
   ```

   If `python3.13` says "command not found", run `ls /usr/bin/python3.*` and use the newest version listed (3.10 or later works). Use **the same version** in Part D.

3. Generate two secret keys. Run this command **twice** and copy each output somewhere safe; they will be different each time:

   ```bash
   python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"
   ```

4. Create the settings file:

   ```bash
   cp .env.example .env
   nano .env
   ```

   Edit it so it looks like this, using your own username and the two keys:

   ```
   TV_ENV=production
   TV_DATABASE_PATH=/home/YOURNAME/trustvault-data/trustvault.db
   TV_MASTER_KEY=<first key>
   TV_AUDIT_KEY=<second key>
   TV_SECURE_COOKIES=1
   TV_TRUSTED_PROXIES=1
   TV_DEMO_MODE=1
   TV_SQLITE_JOURNAL=DELETE
   ```

   Save with **Ctrl+O**, then **Enter**, then exit with **Ctrl+X**.

   > **Save `TV_MASTER_KEY` in a password manager.** If it is lost, every uploaded file becomes unreadable for good.
   >
   > **`TV_TRUSTED_PROXIES=1` is required.** Without it the app thinks it is running on plain HTTP, and the cross-origin check will refuse every button click.

5. Create the database and demo data:

   ```bash
   python -m scripts.seed
   ```

   You should see: `Seeded 6 users, 7 documents, 7 grants.`

## Part D: Create the web app

1. Open the **Web** tab → **Add a new web app** → **Next**.
2. Choose **Manual configuration** (*not* "Flask"), then pick **the same Python version** you used in Part C, then **Next**.
3. On the page that appears, fill in these sections:
   - **Code:**
     - Source code: `/home/YOURNAME/trustvault`
     - Working directory: `/home/YOURNAME/trustvault`
   - **Virtualenv:** `/home/YOURNAME/tv-venv`
4. In the **Code** section, click the **WSGI configuration file** link (`/var/www/YOURNAME_pythonanywhere_com_wsgi.py`). **Delete everything** in it and paste:

   ```python
   import sys
   sys.path.insert(0, "/home/YOURNAME/trustvault")

   from wsgi import app as application  # noqa
   ```

   Click **Save**.
5. Back on the Web tab, scroll to **Security** and turn on **Force HTTPS**.
6. Scroll to the top and click the big green **Reload** button.
7. Open `https://YOURNAME.pythonanywhere.com` and sign in as `olivia@trustvault.test` / `Olivia-Demo-2026!`.

## Part E: Prove it is secure on the live site

From the Bash console on PythonAnywhere (or your own computer), run:

```bash
cd ~/trustvault
source ~/tv-venv/bin/activate
python -m scripts.check_live https://YOURNAME.pythonanywhere.com
```

Every line should say **PASS**. The script signs in as three demo users and confirms that, on the deployed site, Victor cannot reach Vera's salary letter, the admin cannot download it, search hides it, and the audit chain is intact.

Then try it by hand:

1. Sign in as Olivia and open "Salary letter - Vera". Copy the address bar.
2. Open a private window, sign in as `victor@trustvault.test` / `Victor-Demo-2026!`, and paste the address. You should see **"Document not found."**
3. Sign in as `admin@trustvault.test` → **Administration** → **Audit trail**, and filter **Result: Refused**. Victor's attempt is listed.

Running `check_live` creates a few audit records and refused attempts. That is fine, but do a reset before the judges arrive (Part G).

## Part F: Finish the README

Edit `README.md` on your computer:

1. Replace `https://YOUR-USERNAME.pythonanywhere.com` with your real URL.
2. Replace `YOUR-USERNAME` in the clone command with your GitHub name.

Commit and push:

```bash
git commit -am "Add live URL"
git push
```

## Part G: Updating, resetting and keeping it alive

- **After you change code:**
  1. On your computer: `git push`
  2. On PythonAnywhere Bash: `cd ~/trustvault && git pull`
  3. Web tab → **Reload**.
- **Reset to clean demo data** (do this just before submitting):

  ```bash
  cd ~/trustvault && source ~/tv-venv/bin/activate && python -m scripts.seed --reset
  ```

  Then **Reload** on the Web tab.
- **Daily purge of old trash (optional):** Tasks tab → add a daily task:

  ```bash
  cd /home/YOURNAME/trustvault && /home/YOURNAME/tv-venv/bin/python -m scripts.purge
  ```

- **Free sites go to sleep after 3 months.** Log in and click **"Run until 3 months from today"** on the Web tab before judging.
- **Backup:**

  ```bash
  sqlite3 ~/trustvault-data/trustvault.db ".backup /home/YOURNAME/tv-backup.db"
  ```

## When something goes wrong

On the Web tab, open the **Error log** and the **Server log** links. The last lines tell you what failed.

| What you see | Cause and fix |
|---|---|
| "Something went wrong" page, or `ConfigError: TV_MASTER_KEY is not set` in the error log | `.env` is missing or isn't in `/home/YOURNAME/trustvault/`. Check with `cat ~/trustvault/.env`. |
| `ModuleNotFoundError: No module named 'flask'` or `'cryptography'` | The Virtualenv path on the Web tab is wrong, or `pip install` ran outside the venv. Redo Part C step 2. |
| `ModuleNotFoundError: No module named 'wsgi'` or `'app'` | The path in the WSGI file is wrong. It must be `/home/YOURNAME/trustvault`. |
| Can sign in, but every button says **"Cross-origin request refused"** | `TV_TRUSTED_PROXIES=1` is missing from `.env`, or you didn't Reload after adding it. |
| Sign-in seems to work but you are immediately sent back to the login page | You opened the site over `http://`. Turn on **Force HTTPS** and use `https://`. |
| `database is locked` | Make sure `TV_SQLITE_JOURNAL=DELETE` is in `.env`, then Reload. |
| `InvalidTag` errors on download | The keys in `.env` changed after the data was seeded. Run `python -m scripts.seed --reset` and Reload. |
| "Email or password is incorrect" for a demo account | Five wrong tries lock an account for 15 minutes. Sign in as admin → Users → **Unlock**, or reset the demo. |

---

### Other hosts (optional)

There is a `Dockerfile` for Fly.io, Railway or Render:

- Mount a persistent volume at `/data`.
- Set `TV_MASTER_KEY` and `TV_AUDIT_KEY` as secrets.
- Run `python -m scripts.seed` once in the container's shell.

Free tiers on those hosts often lack persistent disks or sleep when idle. PythonAnywhere is the simplest choice for this brief.
