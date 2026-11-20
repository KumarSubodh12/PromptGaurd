# Putting a public demo of PromptGuard online

PromptGuard is built to run on your own computer. A public copy is possible, but it is a **demo**, not the same thing:

* Whatever visitors paste is sent to *your* server. It is deleted after about an hour, but it does leave the visitor's computer. The demo says so on every page. Never run the normal (non-demo) version on a public server: it has no login, and its history page would show everyone's scans.
* Demo mode (`PROMPTGUARD_DEMO=1`) switches off History, Overview, Analytics and Settings, deletes scans after an hour, limits each visitor to 20 scans per 10 minutes, and limits uploads to 2 MB and pasted text to 100,000 characters. On Render the demo mode turns on by itself, as a safety net.
* The free plan of a host sleeps when nobody visits. The first visit afterwards can take a minute or more while the models load.
* I could not test on Render itself from where I built this. The settings below follow Render's documentation, but the first deploy may need a small fix. Read the "Logs" tab if it fails.

## Step 1: put the code on GitHub

You need a free account at github.com.

1. Create a new repository (public is fine; the data inside is synthetic). Name it `promptguard`.
2. In the folder that contains `app.py`, run:
   ```
   git init
   git add .
   git commit -m "PromptGuard"
   git branch -M main
   git remote add origin https://github.com/YOUR-NAME/promptguard.git
   git push -u origin main
   ```
   (Or use "uploading an existing file" on the GitHub page and drag in the files. Upload the *contents* of the folder, so that `app.py` is at the top level of the repository.)

## Step 2: create the web service on Render

You need a free account at render.com (sign in with GitHub).

1. New, then **Web Service**, then pick your `promptguard` repository.
2. Fill in:
   * Language: **Python 3**
   * Build command: `pip install -r requirements.txt`
   * Start command: `gunicorn "app:create_app()" --workers 1 --threads 4 --timeout 120 --bind 0.0.0.0:$PORT`
   * Instance type: **Free**
3. Under Environment, add `PROMPTGUARD_DEMO` = `1`.
4. Create Web Service. The first build takes several minutes (it installs scikit-learn and others).
5. When the log says the service is live, open the address Render shows (it ends in `.onrender.com`).

The repository already has a `.python-version` file (3.13), which Render reads. A `render.yaml` is included if you prefer Render's "Blueprint" option.

## If something goes wrong

* **Build fails:** open the Logs tab. If it complains about a Python version, check that `.python-version` is at the top level of the repository.
* **"Out of memory" or the service keeps restarting:** the free plan has little memory. Try a paid instance, or run PromptGuard locally.
* **Page opens but a scan fails:** check the Logs tab for a Python error and send it to whoever maintains the project.
* **You want to stop the public copy:** delete the service in the Render dashboard.
