# Aegis web

The Aegis marketing site and an interactive policy playground, built with Next.js, TypeScript, Tailwind, Framer Motion, and Lenis.

The playground runs the real policy engine in the browser. The engine is ported to TypeScript in `src/lib/engine`, and every allow or deny on the site comes from calling `decide()`, never from a fixed value.

## Develop

```
npm install
npm run dev      # http://localhost:3000
npm run build    # production build
npm run lint
```

## Structure

- `src/app` holds the routes: the landing page and `/playground`.
- `src/components` holds the hero, the scroll-driven gate section, the interactive same-call demo, the playground, and the shared motion and layout primitives.
- `src/lib/engine` is the TypeScript port of the policy engine and the default pack.

## Deploy

This deploys to Vercel as a standard Next.js app. Set the project Root Directory to `web`, since the app is a subfolder of the repository. The framework preset is detected automatically.
