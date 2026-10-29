# Deploying the OnionClaw site

The site is a static build (Vite + three.js). There is no server and no database:
everything runs in the visitor's browser. The GitHub star count is fetched live
from the public GitHub API on each visit, so it stays current on its own.

## Build

```bash
cd web
npm ci          # or: npm install
npm run build   # outputs a static site to web/dist/
npm run preview # serve the built site locally at http://127.0.0.1:4173
```

`web/dist/` is the whole site. Upload its contents to any static host.

## Before you go live: set your domain

Asset paths are relative, so the site works at a domain root **or** a subpath with no
changes. Four files hold an absolute URL, for SEO, social cards and the 404 page (which
must resolve at any depth). Replace the placeholder `https://onionclaw.example` with your
real URL (no trailing slash), then rebuild:

- `index.html` — `canonical`, `og:url`, `og:image`, `twitter:image`
- `public/robots.txt` — the `Sitemap:` line
- `public/sitemap.xml` — the `<loc>`

One-liner (run in `web/`, change the domain):

```bash
grep -rl 'onionclaw.example' index.html public \
  | xargs sed -i 's#https://onionclaw.example#https://YOUR-DOMAIN#g'
npm run build
```

Everything still works if you skip this; only share-card previews and the canonical URL
point at the placeholder. `404.html` needs no substitution — it carries its own inline
artwork and a root-relative "Back" link, so it renders correctly for a missing path at
any depth. (On a subpath deployment that link goes to the domain root rather than the
site root; change it to your subpath if that matters.)

## Deploy

**Netlify / Cloudflare Pages** — connect the repo; `netlify.toml` sets base `web`,
build `npm ci && npm run build`, publish `dist`. `public/_headers` and
`public/_redirects` are copied into the build and picked up automatically. Or drag
`web/dist/` onto app.netlify.com/drop.

**Vercel** — import the repo, set the root directory to `web`; `vercel.json` does
the rest.

**GitHub Pages** — push the contents of `web/dist/` to a `gh-pages` branch and set Pages
to serve that branch. Run `touch dist/.nojekyll` first, or GitHub's Jekyll step skips the
`_headers` and `_redirects` files.

**Any static host / S3 / nginx** — serve the contents of `web/dist/` as-is. Point
the host's 404 handler at `404.html` if it supports one.

## What's included

- SVG + PNG favicons, Apple touch icon, PWA web manifest with maskable icons
- Open Graph + Twitter Card tags and a 1200×630 `og-image.png`
- `robots.txt`, `sitemap.xml`, a styled `404.html`
- Long-cache headers for hashed assets (`_headers`, `vercel.json`)
- A readable no-WebGL version at `?static` (also used automatically for visitors
  with reduced-motion enabled or without WebGL)
