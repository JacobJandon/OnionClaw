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

Asset paths are relative, so the site works at a domain root **or** a subpath with
no changes. Three files hold an absolute URL for SEO and social cards. Replace the
placeholder `https://onionclaw.example` with your real URL (keep the trailing
slash), then rebuild:

- `index.html` — `canonical`, `og:url`, `og:image`, `twitter:image`
- `public/robots.txt` — the `Sitemap:` line
- `public/sitemap.xml` — the `<loc>`

One-liner (run in `web/`, change the domain):

```bash
grep -rl 'onionclaw.example' index.html public | xargs sed -i 's#https://onionclaw.example#https://YOUR-DOMAIN#g'
npm run build
```

## Deploy

**Netlify / Cloudflare Pages** — connect the repo; `netlify.toml` sets base `web`,
build `npm ci && npm run build`, publish `dist`. `public/_headers` and
`public/_redirects` are copied into the build and picked up automatically. Or drag
`web/dist/` onto app.netlify.com/drop.

**Vercel** — import the repo, set the root directory to `web`; `vercel.json` does
the rest.

**GitHub Pages** — push `web/dist/` to a `gh-pages` branch, or use an action that
builds `web/` and publishes `dist/`. Relative paths mean it works under
`USER.github.io/OnionClaw/` without extra config.

**Any static host / S3 / nginx** — serve the contents of `web/dist/` as-is. Point
the host's 404 handler at `404.html` if it supports one.

## What's included

- SVG + PNG favicons, Apple touch icon, PWA web manifest with maskable icons
- Open Graph + Twitter Card tags and a 1200×630 `og-image.png`
- `robots.txt`, `sitemap.xml`, a styled `404.html`
- Long-cache headers for hashed assets (`_headers`, `vercel.json`)
- A readable no-WebGL version at `?static` (also used automatically for visitors
  with reduced-motion enabled or without WebGL)
