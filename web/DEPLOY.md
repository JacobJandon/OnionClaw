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

## Live site and domain

The site is live on GitHub Pages at **https://jacobjandon.github.io/OnionClaw/**, served
from the `gh-pages` branch. Four files hold that absolute URL for SEO, social cards and the
404 page (which must work at any depth): `index.html`, `public/robots.txt`,
`public/sitemap.xml`, `public/404.html`. Everything else uses relative paths.

To move to a custom domain, replace the URL and rebuild (run in `web/`):

```bash
grep -rl 'jacobjandon.github.io/OnionClaw' index.html public \
  | xargs sed -i 's#https://jacobjandon.github.io/OnionClaw#https://YOUR-DOMAIN#g'
npm run build
```

## Redeploy to GitHub Pages

```bash
cd web && npm run build && touch dist/.nojekyll
cd dist && git init -q && git add -A && git commit -qm "deploy" \
  && git push -f https://github.com/JacobJandon/OnionClaw.git HEAD:gh-pages
```

`.nojekyll` stops GitHub's Jekyll step, which would otherwise skip files starting with `_`.

## Deploy

**Netlify / Cloudflare Pages** — connect the repo; `netlify.toml` sets base `web`,
build `npm ci && npm run build`, publish `dist`. `public/_headers` and
`public/_redirects` are copied into the build and picked up automatically. Or drag
`web/dist/` onto app.netlify.com/drop.

**Vercel** — import the repo, set the root directory to `web`; `vercel.json` does
the rest.

**GitHub Pages** — this is the live setup; see *Redeploy to GitHub Pages* above.

**Any static host / S3 / nginx** — serve the contents of `web/dist/` as-is. Point
the host's 404 handler at `404.html` if it supports one.

## What's included

- SVG + PNG favicons, Apple touch icon, PWA web manifest with maskable icons
- Open Graph + Twitter Card tags and a 1200×630 `og-image.png`
- `robots.txt`, `sitemap.xml`, a styled `404.html`
- Long-cache headers for hashed assets (`_headers`, `vercel.json`)
- A readable no-WebGL version at `?static` (also used automatically for visitors
  with reduced-motion enabled or without WebGL)
