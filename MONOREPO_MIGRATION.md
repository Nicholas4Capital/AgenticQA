# 4Capital Monorepo Migration — Complete Guide

> One repo. All history. All apps. One command to build, test, and deploy.

## Why you CAN keep your existing Vercel projects

**You absolutely can and should keep them.** Here's why:

Vercel projects are just pointers: `repo + branch + root directory`. When you move code from `4capitaldesign/portal` (root `/`) into `4capitaldesign/4capital` (root `apps/portal/`), you just update two settings in each Vercel project:

1. **Repository** → point to the new monorepo
2. **Root Directory** → set to `apps/portal/` (or `apps/cmhc/`, etc.)

Your custom domains, environment variables, deployment history, analytics, and team settings all stay intact. Zero downtime. No DNS changes.

### Vercel project repointing steps

For each project (portal, cmhc, onboarding, brain):

1. Go to **Project Settings → Git**
2. Disconnect the old repo
3. Connect the new `4capitaldesign/4capital` repo
4. Set **Root Directory** to `apps/<app-name>/`
5. Under **Build & Development Settings**, keep existing commands (`next build`, etc.)
6. Turborepo's remote caching works with Vercel out of the box — builds only what changed

That's it. Same project, same domains, same env vars, new repo location.

---

## Full Migration — Preserving ALL Git History

### Prerequisites

```bash
# Install pnpm if not already installed
npm install -g pnpm

# Install Turborepo
pnpm add -g turbo
```

### Step 1: Create the monorepo and import all apps with full history

```bash
# Create the new repo
mkdir 4capital && cd 4capital
git init
git commit --allow-empty -m "Initialize 4Capital monorepo"

# ─── Import Portal (full history) ───
git remote add portal-old https://github.com/4capitaldesign/portal.git
git fetch portal-old

# This preserves EVERY commit from portal, nested under apps/portal/
git subtree add --prefix=apps/portal portal-old main --squash=false

# ─── Import CMHC (full history) ───
git remote add cmhc-old https://github.com/4capitaldesign/cmhc.git
git fetch cmhc-old
git subtree add --prefix=apps/cmhc cmhc-old main --squash=false

# ─── Import Onboarding (full history) ───
git remote add onboarding-old https://github.com/4capitaldesign/onboarding.git
git fetch onboarding-old
git subtree add --prefix=apps/onboarding onboarding-old main --squash=false

# ─── Import Brain (full history) ───
git remote add brain-old https://github.com/4capitaldesign/4capital-brain.git
git fetch brain-old
git subtree add --prefix=apps/brain brain-old main --squash=false

# ─── Import AgenticQA (full history) ───
git remote add agenticqa-old https://github.com/Nicholas4Capital/AgenticQA.git
git fetch agenticqa-old
git subtree add --prefix=agenticqa agenticqa-old main --squash=false
```

**What `git subtree add` does vs `read-tree`:**
- `read-tree` = imports files only, no history
- `subtree add` = imports files AND every commit, rewritten with the prefix path
- After this, `git log apps/portal/` shows the full portal history
- `git blame apps/portal/src/app/page.tsx` shows original authors and dates

### Step 2: Clean up remotes

```bash
# Remove the old remotes (you don't need them anymore)
git remote remove portal-old
git remote remove cmhc-old
git remote remove onboarding-old
git remote remove brain-old
git remote remove agenticqa-old

# Add the new origin
git remote add origin https://github.com/4capitaldesign/4capital.git
```

### Step 3: Create root workspace config

```bash
# Root package.json
cat > package.json << 'EOF'
{
  "name": "4capital",
  "private": true,
  "scripts": {
    "build": "turbo run build",
    "dev": "turbo run dev",
    "dev:portal": "turbo run dev --filter=portal",
    "dev:cmhc": "turbo run dev --filter=cmhc",
    "dev:onboarding": "turbo run dev --filter=onboarding",
    "dev:brain": "turbo run dev --filter=brain",
    "lint": "turbo run lint",
    "test": "turbo run test",
    "test:e2e": "turbo run test:e2e",
    "qa": "cd agenticqa && python -m agenticqa.agents.team.runner .. --max-iterations 2",
    "db:migrate": "supabase db push",
    "db:generate": "supabase gen types typescript --local > packages/db/src/types.ts"
  },
  "devDependencies": {
    "turbo": "^2.0.0"
  },
  "packageManager": "pnpm@9.0.0"
}
EOF

# pnpm workspace
cat > pnpm-workspace.yaml << 'EOF'
packages:
  - "apps/*"
  - "packages/*"
EOF

# Turborepo config
cat > turbo.json << 'EOF'
{
  "$schema": "https://turbo.build/schema.json",
  "globalDependencies": ["**/.env.*local"],
  "tasks": {
    "build": {
      "dependsOn": ["^build"],
      "inputs": ["src/**", "package.json", "tsconfig.json"],
      "outputs": [".next/**", "dist/**"]
    },
    "dev": {
      "persistent": true,
      "cache": false
    },
    "lint": {
      "dependsOn": ["^build"]
    },
    "test": {
      "dependsOn": ["^build"]
    },
    "test:e2e": {
      "dependsOn": ["build"]
    }
  }
}
EOF

git add -A
git commit -m "Add Turborepo workspace configuration"
```

### Step 4: Create shared packages

```bash
# ─── packages/ui ───
mkdir -p packages/ui/src
cat > packages/ui/package.json << 'EOF'
{
  "name": "@4capital/ui",
  "version": "0.0.0",
  "private": true,
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "exports": {
    ".": "./src/index.ts",
    "./*": "./src/*.tsx"
  },
  "peerDependencies": {
    "react": "^18 || ^19",
    "react-dom": "^18 || ^19"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
EOF
echo '// Re-export shared UI components here' > packages/ui/src/index.ts

# ─── packages/db ───
mkdir -p packages/db/src
cat > packages/db/package.json << 'EOF'
{
  "name": "@4capital/db",
  "version": "0.0.0",
  "private": true,
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "exports": {
    ".": "./src/index.ts",
    "./types": "./src/types.ts"
  },
  "dependencies": {
    "@supabase/supabase-js": "^2.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
EOF
cat > packages/db/src/index.ts << 'EOF'
import { createClient } from '@supabase/supabase-js'
import type { Database } from './types'

export const supabase = createClient<Database>(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
)

export type { Database } from './types'
EOF
echo '// Generated by: pnpm db:generate\nexport type Database = Record<string, never>' > packages/db/src/types.ts

# ─── packages/config ───
mkdir -p packages/config
cat > packages/config/package.json << 'EOF'
{
  "name": "@4capital/config",
  "version": "0.0.0",
  "private": true,
  "exports": {
    "./tsconfig": "./tsconfig.base.json",
    "./tailwind": "./tailwind.config.ts",
    "./eslint": "./eslint.config.js"
  }
}
EOF
cat > packages/config/tsconfig.base.json << 'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["dom", "dom.iterable", "ES2022"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "paths": {
      "@4capital/ui": ["../../packages/ui/src"],
      "@4capital/db": ["../../packages/db/src"],
      "@4capital/utils": ["../../packages/utils/src"]
    }
  }
}
EOF

# ─── packages/utils ───
mkdir -p packages/utils/src
cat > packages/utils/package.json << 'EOF'
{
  "name": "@4capital/utils",
  "version": "0.0.0",
  "private": true,
  "main": "./src/index.ts",
  "types": "./src/index.ts"
}
EOF
echo '// Shared validators, formatters, constants' > packages/utils/src/index.ts

# ─── supabase directory ───
mkdir -p supabase/migrations supabase/seed

git add -A
git commit -m "Add shared packages: ui, db, config, utils, supabase"
```

### Step 5: Update each app to use shared packages

In each app's `package.json`, add:

```json
{
  "dependencies": {
    "@4capital/ui": "workspace:*",
    "@4capital/db": "workspace:*",
    "@4capital/utils": "workspace:*"
  }
}
```

In each app's `tsconfig.json`, extend the shared config:

```json
{
  "extends": "@4capital/config/tsconfig"
}
```

Then replace duplicated Supabase client code in each app:

```diff
- import { createClient } from '@supabase/supabase-js'
- const supabase = createClient(url, key)
+ import { supabase } from '@4capital/db'
```

```bash
git add -A
git commit -m "Wire apps to shared packages"
```

### Step 6: Install and verify

```bash
pnpm install
turbo build

git add -A
git commit -m "Install dependencies and verify builds"
```

### Step 7: Push and repoint Vercel

```bash
git push -u origin main
```

Then in Vercel dashboard for EACH project:

| Vercel Project | Root Directory | Build Command | No other changes needed |
|---|---|---|---|
| portal | `apps/portal` | `cd ../.. && turbo run build --filter=portal` | Domains stay |
| cmhc | `apps/cmhc` | `cd ../.. && turbo run build --filter=cmhc` | Domains stay |
| onboarding | `apps/onboarding` | `cd ../.. && turbo run build --filter=onboarding` | Domains stay |
| brain | `apps/brain` | `cd ../.. && turbo run build --filter=brain` | Domains stay |

### Step 8: Archive old repos

Once everything works, set old repos to **read-only** (Settings → Danger Zone → Archive):
- `4capitaldesign/portal` → archived
- `4capitaldesign/cmhc` → archived
- `4capitaldesign/onboarding` → archived
- `4capitaldesign/4capital-brain` → archived

Don't delete them — archiving preserves history as a backup.

### Step 9: Run full AgenticQA audit

```bash
cd agenticqa
python -m agenticqa.agents.team.runner .. --max-iterations 2
```

Now all 22 agents scan everything: portal, brain, cmhc, onboarding, shared packages, Supabase schema — in one pass.

---

## What you get after migration

| Before (4 repos) | After (1 monorepo) |
|---|---|
| Duplicated Supabase client in every app | Single `@4capital/db` package |
| Duplicated UI components | Single `@4capital/ui` package |
| Different tsconfig/eslint in each app | Shared `@4capital/config` |
| Can't share types across apps | Types in `@4capital/utils`, auto-generated from Supabase |
| AgenticQA only scans itself | AgenticQA scans everything |
| 4 separate CI pipelines | `turbo build` — only builds what changed |
| Change in shared logic = 4 PRs | Change in shared logic = 1 PR |
| No cross-app type safety | Full type safety across all apps |

## Vercel keeps working because

- **Custom domains**: Attached to the Vercel project, not the repo. Unchanged.
- **Environment variables**: Stored in Vercel project settings. Unchanged.
- **Deployment URLs**: Generated per-project. Unchanged.
- **Preview deployments**: Still work — Vercel + Turborepo detects which apps are affected by a PR.
- **Analytics/Web Vitals**: Per-project. Unchanged.

The only thing that changes is which repo and subdirectory Vercel pulls from. Everything else stays exactly the same.

## Quick reference commands after migration

```bash
# Development
pnpm dev:portal          # Run just portal
pnpm dev                 # Run everything
turbo dev --filter=portal --filter=brain  # Run specific apps

# Building
turbo build              # Build all (cached, incremental)
turbo build --filter=portal  # Build portal + its dependencies

# Testing
turbo test               # Test everything
turbo test --filter=@4capital/db  # Test just the db package

# Database
pnpm db:generate         # Regenerate Supabase types for all apps
pnpm db:migrate          # Push migrations

# QA
pnpm qa                  # Run full AgenticQA pipeline across everything
```
