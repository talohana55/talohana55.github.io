# talohana55.github.io

Personal one-pager — **[talohana55.github.io](https://talohana55.github.io)**

Single self-contained HTML page (Hebrew, RTL). No build step, no dependencies: edit `index.html`, push to `main`, GitHub Pages redeploys.

| File | Purpose |
|---|---|
| `index.html` | The page — markup, styles and the profile image are all inline |
| `og.png` | Link-preview image referenced by the Open Graph tags |
| `favicon.svg` | Browser tab icon |
| `CNAME` | *(add this when pointing a custom domain at the site)* |

## Analytics

A commented block near the top of `index.html` holds ready-to-use snippets for **GoatCounter** and **Google Analytics 4**. Create an account, paste your ID, uncomment one.

## Custom domain

1. Buy the domain.
2. Add a `CNAME` file containing the bare domain (e.g. `talohana.dev`).
3. At the registrar, point an `ALIAS`/`ANAME` record at `talohana55.github.io`, or `A` records at GitHub's Pages IPs.
4. Repo → Settings → Pages → set the custom domain and enable **Enforce HTTPS**.
5. Update the absolute URLs in the `og:*`, `canonical` and JSON-LD tags — link previews break if they still point at the old host.

---

**Tal Ohana** — Senior Full-Stack Engineer.
[Profile](https://github.com/talohana55) · [LinkedIn](https://www.linkedin.com/in/tal-ohana-a01abb1b4/) · taloh13@gmail.com
