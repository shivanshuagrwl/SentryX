# Putting SENTRYX on GitHub

Two things need to happen: get the code up onto GitHub, then trigger the
"build all three installers" workflow. Both can be done from a browser or
GitHub Desktop — **no terminal needed for either.**

---

## Part 1 — Get the code onto GitHub

### Option A: GitHub Desktop (recommended — handles the full project cleanly)

1. Download and install **[GitHub Desktop](https://desktop.github.com/)**
   — it's a normal app, install it like any other program.
2. Open it and sign in with your GitHub account.
3. Unzip `sentryx-github-ready.zip` somewhere on your computer (e.g. your
   Desktop or Documents).
4. In GitHub Desktop: **File → Add Local Repository** → point it at the
   unzipped `sentryx` folder.
5. It'll say "this directory does not appear to be a Git repository" —
   click **"create a repository"** right there.
6. Fill in the name (`sentryx`), leave the rest default, click **Create Repository**.
7. Click **Publish repository** in the top bar. Choose whether it's
   Public or Private, and click **Publish**.

That's it — your code is now on GitHub, at
`https://github.com/<your-username>/sentryx`.

Any time you make changes later: open GitHub Desktop, you'll see the
changed files listed, type a short summary at the bottom left, click
**Commit to main**, then click **Push origin** at the top. No terminal.

### Option B: Upload straight from the GitHub website (fine for a first upload)

1. Go to [github.com/new](https://github.com/new) and create a new repository
   named `sentryx` (Public, don't add a README — you already have one).
2. On the new empty repo's page, click **"uploading an existing file."**
3. Drag the *contents* of your unzipped `sentryx` folder into the browser
   window (drag the folders like `cmd`, `internal`, `installers`, etc. —
   not the outer `sentryx` folder itself).
4. Scroll down, add a commit message like "Initial commit," click
   **Commit changes.**

This works fine for getting started, but GitHub Desktop is the better
long-term option once you're making regular changes.

---

## Part 2 — Build the installers (trigger the release)

Your repo already has a workflow file
(`.github/workflows/release.yml`) that automatically builds
`SentryxSetup.exe`, `SENTRYX-arm64.pkg`, and `sentryx_1.0_amd64.deb` and
attaches them to a GitHub Release — but it only runs when you publish a
release. You can do this entirely from the website:

1. On your repo's GitHub page, click **Releases** (right-hand sidebar),
   then **"Create a new release."**
2. Where it says **"Choose a tag,"** type a new version name, e.g.
   `v1.0.0`, and click **"Create new tag: v1.0.0 on publish."**
3. Give the release a title (e.g. `SENTRYX v1.0.0`) and, optionally, notes.
4. Click **Publish release.**

That single click on the website is what triggers everything — GitHub's
own servers now build all three installers in the background (takes a few
minutes). Once done, refresh the Releases page and you'll see
`SentryxSetup.exe`, `SENTRYX-arm64.pkg`, and `sentryx_1.0_amd64.deb`
attached to the release automatically. That's the link you share with
people — the same one used in `WHAT_IS_SENTRYX.md`.

You can watch it build live under the **Actions** tab on your repo if
you're curious, but you don't need to — it finishes on its own.

---

## Updating a release later

Repeat Part 2 with a new tag (e.g. `v1.0.1`) any time you've pushed new
changes and want a fresh build. Old releases stay up untouched.

---

<div align="right"><sub>SENTRYX — developed by Shivanshu</sub></div>
