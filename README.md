# Cipher Auth - Development Roadmap

> **Mission**: Build a modern, TypeScript-first authentication SDK that combines the flexibility of Passport with the DX of Clerk - fully open-source and self-hostable.

**Team**: Cipher & Jamal  
**Timeline**: 3-5 Months  
**Target Launch**: Month 5 (v1.0.0)

---

## 🎯 Project Vision

Cipher Auth will be a full-stack authentication SDK that provides:

- **Backend**: Strategy-based auth system (like Passport) with modern TypeScript
- **Frontend**: Pre-built UI components (like Clerk) that are fully customizable
- **Security**: Enterprise-grade security built-in from day one
- **Flexibility**: Self-hosted first, optional managed service later

### Key Differentiators

✅ Fully open-source & self-hostable  
✅ TypeScript-native with complete type safety  
✅ Customizable UI components (not iframes)  
✅ Database agnostic (Prisma, Mongoose, Drizzle, etc.)  
✅ Framework agnostic (Express, Fastify, Next.js, etc.)  
✅ No vendor lock-in

---

## 📦 Package Structure

```
@cipher-auth/
├── core                 # Backend SDK & strategies
├── client              # Framework-agnostic client
├── react               # React components & hooks
├── vue                 # Vue components (Phase 3)
├── svelte              # Svelte components (Phase 3)
├── cli                 # CLI tool for setup & generation
└── adapters/
    ├── prisma          # Prisma adapter
    ├── mongoose        # Mongoose adapter
    └── drizzle         # Drizzle adapter
```

---

## 🗓️ Development Phases

### **Month 1: Foundation & Core Backend**

**Owner**: Cipher (Lead) + Jamal (Support)

#### Week 1-2: Project Setup & Core Architecture

- [ ] Initialize monorepo (Turborepo + pnpm workspaces)
  ```bash
  npm install -g pnpm  # Install pnpm globally
  pnpm init
  pnpm add -D turbo
  # Create pnpm-workspace.yaml
  ```
- [ ] Setup TypeScript configs, linting, formatting
  ```bash
  pnpm add -D typescript eslint prettier -w
  ```
- [ ] Core strategy pattern implementation
  - [ ] Base `Strategy` abstract class
  - [ ] Strategy registration system
  - [ ] Middleware pipeline architecture
- [ ] Session management foundation
  - [ ] Session store interface
  - [ ] In-memory store (for dev)
  - [ ] Redis adapter
  ```bash
  pnpm add ioredis --filter @cipher-auth/core
  ```
- [ ] Security primitives
  - [ ] Password hashing (argon2)
  - [ ] CSRF token generation/validation
  - [ ] Rate limiting utilities
  ```bash
  pnpm add argon2 --filter @cipher-auth/core
  ```

#### Week 3-4: Framework Adapters & Database Layer

- [ ] Express adapter (priority)
  ```bash
  pnpm add express cors cookie-parser --filter @cipher-auth/core
  pnpm add -D @types/express @types/cors @types/cookie-parser --filter @cipher-auth/core
  ```
- [ ] Next.js API routes adapter
- [ ] Database adapter interface
  - [ ] User model schema
  - [ ] Session model schema
  - [ ] OAuth connection schema
- [ ] Mongoose adapter (MERN focus)
  ```bash
  pnpm add mongoose --filter @cipher-auth/mongoose
  pnpm add -D @types/mongoose --filter @cipher-auth/mongoose
  ```
- [ ] Prisma adapter (future-proofing)
  ```bash
  pnpm add @prisma/client --filter @cipher-auth/prisma
  pnpm add -D prisma --filter @cipher-auth/prisma
  ```
- [ ] JWT utilities (generate, verify, refresh)
  ```bash
  pnpm add jsonwebtoken --filter @cipher-auth/core
  pnpm add -D @types/jsonwebtoken --filter @cipher-auth/core
  ```

**Deliverable**: `@cipher-auth/core` v0.1.0 - Core SDK working with Express + MongoDB

---

### **Month 2: Essential Strategies & Client SDK**

**Owner**: Split - Cipher (Strategies) + Jamal (Client SDK)

#### Week 1-2: Authentication Strategies (Cipher)

- [ ] Local Strategy (email/password)
  - [ ] Registration with email verification
  - [ ] Login with password
  - [ ] Password reset flow
  - [ ] Account lockout after failed attempts
- [ ] Magic Link Strategy
  - [ ] Passwordless email auth
  - [ ] One-time tokens with expiry
- [ ] OAuth 2.0 Base Implementation
  - [ ] Generic OAuth 2.0 strategy with PKCE
  - [ ] State parameter validation
  - [ ] Token exchange handling

#### Week 3-4: Client SDK (Jamal)

- [ ] `@cipher-auth/client` package
  - [ ] Auth state management (login, logout, refresh)
  - [ ] Automatic token attachment to requests
  - [ ] Token refresh logic
  - [ ] CSRF handling
  - [ ] Local storage/cookie management
- [ ] TypeScript types for client
- [ ] Fetch/Axios interceptors
- [ ] Error handling & retries

**Parallel Tasks**:

- [ ] Google OAuth strategy (Cipher)
  ```bash
  pnpm add passport-google-oauth20 --filter @cipher-auth/strategies
  pnpm add -D @types/passport-google-oauth20 --filter @cipher-auth/strategies
  ```
- [ ] GitHub OAuth strategy (Cipher)
  ```bash
  pnpm add passport-github2 --filter @cipher-auth/strategies
  pnpm add -D @types/passport-github2 --filter @cipher-auth/strategies
  ```
- [ ] Client integration tests (Jamal)

**Deliverable**: Working local auth + OAuth with client SDK

---

### **Month 3: React Components & UI System**

**Owner**: Jamal (Lead) + Cipher (Review/Integration)

#### Week 1-2: Headless React Hooks

- [ ] `<AuthProvider>` context provider
- [ ] `useAuth()` hook (login, logout, signup)
- [ ] `useUser()` hook (current user data)
- [ ] `useSession()` hook (session state)
- [ ] `useOAuth()` hook (social login)
- [ ] Protected route component/HOC

#### Week 3-4: Pre-built UI Components

- [ ] Component architecture (Radix UI primitives)
  ```bash
  pnpm add @radix-ui/react-dialog @radix-ui/react-label @radix-ui/react-slot --filter @cipher-auth/react
  pnpm add class-variance-authority clsx tailwind-merge --filter @cipher-auth/react
  ```
- [ ] Theming system (CSS variables + Tailwind)
  ```bash
  pnpm add -D tailwindcss postcss autoprefixer --filter @cipher-auth/react
  ```
- [ ] `<SignInForm>` component
  - [ ] Email/password fields
  - [ ] Social login buttons
  - [ ] Error states
  - [ ] Loading states
- [ ] `<SignUpForm>` component
  - [ ] Email verification UI
  - [ ] Password strength indicator
  - [ ] Terms acceptance
- [ ] `<ForgotPasswordForm>` component
- [ ] `<ResetPasswordForm>` component
- [ ] `<ProfileSettings>` component
- [ ] Responsive design (mobile-first)
- [ ] Accessibility (WCAG 2.1 AA)

**Parallel Tasks**:

- [ ] Example app (Next.js + MongoDB) (Cipher)
  ```bash
  cd examples
  pnpm create next-app basic-nextjs --typescript --tailwind --app
  cd basic-nextjs
  pnpm add @cipher-auth/core @cipher-auth/react @cipher-auth/mongoose
  ```
- [ ] Component Storybook setup (Jamal)
  ```bash
  pnpm add -D @storybook/react @storybook/react-vite storybook --filter @cipher-auth/react
  ```

**Deliverable**: `@cipher-auth/react` v0.1.0 with full UI components

---

### **Month 4: Advanced Features & Security Hardening**

**Owner**: Split by feature

#### Week 1-2: Multi-Factor Authentication (Cipher)

- [ ] TOTP (Time-based OTP)
  - [ ] QR code generation
  - [ ] Backup codes
  - [ ] Recovery flow
  ```bash
  pnpm add otplib qrcode --filter @cipher-auth/strategies
  pnpm add -D @types/qrcode --filter @cipher-auth/strategies
  ```
- [ ] Email OTP strategy
- [ ] SMS OTP integration (Twilio)
  ```bash
  pnpm add twilio --filter @cipher-auth/strategies
  ```
- [ ] WebAuthn/Passkeys (FIDO2) - basic support
  ```bash
  pnpm add @simplewebauthn/server --filter @cipher-auth/core
  pnpm add @simplewebauthn/browser --filter @cipher-auth/react
  ```
- [ ] MFA UI components (Jamal helps)

#### Week 2-3: Enterprise Features (Jamal)

- [ ] RBAC (Role-based access control)
  - [ ] Role definition system
  - [ ] Permission checking middleware
  - [ ] UI components for role management
- [ ] Organization/Team support (multi-tenancy)
  - [ ] Organization model
  - [ ] Member invitations
  - [ ] Team switching UI
- [ ] Audit logging system
  - [ ] Event tracking
  - [ ] Export capabilities

#### Week 3-4: Security Hardening (Both)

- [ ] Advanced session management
  - [ ] Device tracking
  - [ ] Concurrent session limits
  - [ ] "Force logout all devices"
- [ ] Anomaly detection (suspicious login alerts)
- [ ] Bot protection (hCaptcha/Turnstile integration)
- [ ] Security headers middleware
- [ ] Complete security audit
- [ ] Penetration testing

**Parallel Tasks**:

- [ ] More OAuth providers: Facebook, Twitter, LinkedIn (Cipher)
  ```bash
  pnpm add passport-facebook passport-twitter passport-linkedin-oauth2 --filter @cipher-auth/strategies
  ```
- [ ] Email provider integrations: SendGrid, Resend (Jamal)
  ```bash
  pnpm add @sendgrid/mail resend --filter @cipher-auth/core
  ```

**Deliverable**: Enterprise-ready auth system with MFA & RBAC

---

### **Month 5: Polish, Documentation & Launch**

**Owner**: Both (Equal split)

#### Week 1-2: Developer Experience

- [ ] CLI tool (`@cipher-auth/cli`)
  ```bash
  cipher-auth init
  cipher-auth add-strategy google
  cipher-auth generate migration
  ```
- [ ] VS Code extension with snippets
- [ ] Testing utilities & mocks
- [ ] Migration scripts from Passport
- [ ] TypeScript config templates

#### Week 2-3: Documentation (CRITICAL)

- [ ] Documentation site (Nextra or VitePress)
  - [ ] Quickstart guide (5-minute setup)
  - [ ] Installation for each framework
  - [ ] Strategy guides (each auth method)
  - [ ] Component API reference
  - [ ] Security best practices
  - [ ] Deployment guides (Vercel, Railway, Fly.io)
- [ ] Interactive examples/playground
- [ ] Video tutorials (at least 3)
  - [ ] Getting started
  - [ ] Adding OAuth
  - [ ] Customizing UI components
- [ ] Migration guides
  - [ ] From Passport.js
  - [ ] From Clerk
  - [ ] From Auth0

#### Week 3-4: Final Polish & Launch Prep

- [ ] Complete example apps
  - [ ] Next.js + Prisma + PostgreSQL
  - [ ] Express + Mongoose + MongoDB (MERN)
  - [ ] Fastify + Drizzle + SQLite
- [ ] Performance optimization
- [ ] Bundle size optimization
- [ ] Final security review
- [ ] Open-source license (MIT)
- [ ] Contributing guidelines
- [ ] Code of conduct
- [ ] npm package publishing setup

#### Week 4: Launch 🚀

- [ ] v1.0.0 release on npm
- [ ] Launch blog post
- [ ] Reddit (r/webdev, r/reactjs, r/node)
- [ ] Hacker News
- [ ] Product Hunt
- [ ] Twitter/X announcement
- [ ] Dev.to article
- [ ] YouTube demo

**Deliverable**: v1.0.0 public release with complete documentation

---

## 🎯 MVP Scope (If timeline slips)

**Must-Have for v1.0**:

- ✅ Core backend SDK (`@cipher-auth/core`)
- ✅ Express adapter
- ✅ Local strategy (email/password)
- ✅ Google + GitHub OAuth
- ✅ Mongoose adapter (MongoDB)
- ✅ React components (`@cipher-auth/react`)
- ✅ Session management (Redis + in-memory)
- ✅ JWT support
- ✅ Basic documentation
- ✅ 1 complete example app

**Nice-to-Have (can be v1.1+)**:

- ⭕ Vue/Svelte components
- ⭕ SAML/LDAP strategies
- ⭕ Prisma/Drizzle adapters
- ⭕ WebAuthn/Passkeys
- ⭕ Advanced audit logging
- ⭕ CLI tool
- ⭕ Managed hosting service

---

## 👥 Role Distribution

### Cipher (You)

**Primary Focus**: Backend, strategies, architecture

- Core SDK architecture
- Authentication strategies
- Security implementation
- Database adapters
- OAuth integrations
- Example apps

### Jamal

**Primary Focus**: Frontend, UI/UX, client SDK

- Client SDK (`@cipher-auth/client`)
- React components
- UI/UX design
- Component theming
- Storybook setup
- Frontend documentation

### Shared Responsibilities

- Code reviews for each other
- Testing (unit + integration)
- Documentation writing
- Example app development
- Security auditing
- Launch preparation

---

## 🛠️ Tech Stack

### Package Management

- **pnpm** - Fast, efficient package manager with native monorepo support
- **Turborepo** - High-performance build system for monorepos
- **Changesets** - Version management and changelog generation

### Backend

- **Language**: TypeScript
- **Runtime**: Node.js 18+
- **Hashing**: argon2
- **Encryption**: node:crypto, libsodium
- **Validation**: Zod
- **Testing**: Vitest
- **Build**: tsup

### Frontend

- **Framework Support**: React (priority), Vue, Svelte
- **UI Primitives**: Radix UI
- **Styling**: Tailwind CSS + CSS variables
- **State Management**: React Context + hooks
- **Testing**: Vitest + Testing Library

### Infrastructure

- **Monorepo**: Turborepo + pnpm workspaces
- **Build Tool**: tsup
- **Docs**: Nextra or VitePress
- **CI/CD**: GitHub Actions

### Databases (via adapters)

- MongoDB (Mongoose) - Priority
- PostgreSQL (Prisma)
- MySQL (Prisma)
- SQLite (Drizzle)

---

## 📦 Monorepo Setup

### Initial Setup Commands

```bash
# 1. Install pnpm globally
npm install -g pnpm

# 2. Create project
mkdir cipher-auth
cd cipher-auth
pnpm init

# 3. Install Turborepo
pnpm add -D turbo

# 4. Create workspace config file
```

**File: `pnpm-workspace.yaml`**

```yaml
packages:
  - "packages/*"
  - "examples/*"
```

**File: `package.json`** (root)

```json
{
  "name": "cipher-auth",
  "version": "0.0.0",
  "private": true,
  "scripts": {
    "build": "turbo run build",
    "dev": "turbo run dev --parallel",
    "test": "turbo run test",
    "lint": "turbo run lint",
    "clean": "turbo run clean && rm -rf node_modules",
    "changeset": "changeset",
    "version": "changeset version",
    "publish": "turbo run build && changeset publish"
  },
  "devDependencies": {
    "@changesets/cli": "^2.27.1",
    "turbo": "^1.11.0",
    "typescript": "^5.3.0",
    "vitest": "^1.0.0",
    "eslint": "^8.56.0",
    "prettier": "^3.1.0"
  }
}
```

**File: `turbo.json`**

```json
{
  "$schema": "https://turbo.build/schema.json",
  "pipeline": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": ["dist/**"]
    },
    "test": {
      "dependsOn": ["build"],
      "cache": false
    },
    "lint": {
      "cache": false
    },
    "dev": {
      "cache": false,
      "persistent": true
    }
  }
}
```

### Creating Packages

```bash
# Core packages
mkdir -p packages/{core,client,react,mongoose,strategies,cli}

# For each package
cd packages/core
pnpm init
# Edit package.json with proper name: @cipher-auth/core

# Add shared dev dependencies
pnpm add -D typescript tsup vitest -w

# Install all dependencies
cd ../..
pnpm install
```

### Package Dependencies

**Core Package** (`packages/core/package.json`):

```json
{
  "name": "@cipher-auth/core",
  "version": "0.0.1",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "scripts": {
    "build": "tsup src/index.ts --format cjs,esm --dts",
    "dev": "tsup src/index.ts --format cjs,esm --dts --watch",
    "test": "vitest run"
  },
  "dependencies": {
    "argon2": "^0.31.2",
    "express": "^4.18.2",
    "ioredis": "^5.3.2"
  },
  "devDependencies": {
    "tsup": "^8.0.1",
    "typescript": "^5.3.3",
    "vitest": "^1.0.4"
  }
}
```

**React Package** (`packages/react/package.json`):

```json
{
  "name": "@cipher-auth/react",
  "version": "0.0.1",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "scripts": {
    "build": "tsup src/index.tsx --format cjs,esm --dts --external react",
    "dev": "tsup src/index.tsx --format cjs,esm --dts --watch --external react",
    "test": "vitest run"
  },
  "dependencies": {
    "@cipher-auth/client": "workspace:*",
    "@radix-ui/react-dialog": "^1.0.5",
    "class-variance-authority": "^0.7.0"
  },
  "peerDependencies": {
    "react": "^18.0.0",
    "react-dom": "^18.0.0"
  }
}
```

**Key Points:**

- Use `"workspace:*"` for internal dependencies
- Use `peerDependencies` for React/Vue/etc
- Use `--filter` flag to work on specific packages: `pnpm add lodash --filter @cipher-auth/core`

---

## 🛠️ Original Tech Stack

---

## 📊 Success Metrics

### Technical Metrics

- [ ] 90%+ test coverage
- [ ] <50kb gzipped bundle size (core)
- [ ] <100ms auth check latency
- [ ] Zero critical security vulnerabilities
- [ ] TypeScript strict mode throughout

### Adoption Metrics (Month 6+)

- [ ] 1,000+ npm downloads/week
- [ ] 500+ GitHub stars
- [ ] 10+ community contributions
- [ ] 5+ production deployments reported

---

## 🚨 Risk Management

### Potential Blockers

1. **Security vulnerabilities**: Mitigate with regular audits, use proven crypto libraries
2. **Scope creep**: Stick to MVP, defer non-critical features to v1.1+
3. **Performance issues**: Benchmark early and often
4. **Documentation lag**: Write docs as you code, not after

### Contingency Plans

- If Month 3 slips → Cut Vue/Svelte components to v1.1
- If Month 4 slips → Defer MFA to v1.1, keep RBAC
- If Month 5 slips → Launch with minimal docs, improve post-launch

---

## 📞 Communication & Workflow

### Daily Sync

- Quick standup (async or 15min call)
- What did you do yesterday?
- What are you doing today?
- Any blockers?

**Development Commands:**

```bash
# Install dependencies
pnpm install

# Start all packages in dev mode
pnpm dev

# Build all packages
pnpm build

# Run tests
pnpm test

# Work on specific package
pnpm --filter @cipher-auth/core dev
pnpm --filter @cipher-auth/react test
```

### Weekly Review

- Demo progress
- Code review session
- Plan next week's tasks
- Adjust timeline if needed

### Tools

- **Code**: GitHub (main repo)
- **Project Management**: GitHub Projects or Linear
- **Communication**: Discord/Slack
- **Documentation**: Notion or Markdown in repo

---

## 🎉 Post-Launch Roadmap (Month 6+)

### Community & Growth

- Build Discord community
- Accept community PRs
- Strategy marketplace/plugin system
- More framework adapters (SvelteKit, Solid, Astro)

### Enterprise Features

- SAML 2.0 support
- LDAP/Active Directory
- Advanced compliance (SOC 2 docs)
- On-premise deployment guides

### Managed Service (Optional Revenue)

- Hosted version (cipher-auth.com)
- Dashboard for user management
- Analytics & insights
- Generous free tier
- Pro/Enterprise pricing

---

## 🎉 Let's Build This!

**Next Steps**:

1. Review this roadmap together
2. Set up the monorepo structure
   ```bash
   npm install -g pnpm
   mkdir cipher-auth && cd cipher-auth
   pnpm init
   pnpm add -D turbo
   # Create pnpm-workspace.yaml
   ```
3. Divide Month 1 tasks
4. Start coding! 🚀

**Quick Start Commands:**

```bash
# Clone/create repo
git clone <repo> # or mkdir cipher-auth
cd cipher-auth

# Install pnpm if needed
npm install -g pnpm

# Initialize project
pnpm init
pnpm add -D turbo typescript vitest

# Create workspace structure
mkdir -p packages/{core,client,react,mongoose,strategies}

# Install all dependencies
pnpm install

# Start development
pnpm dev
```

**Remember**: Ship fast, iterate faster. v1.0 doesn't need to be perfect - it needs to work and solve real problems.

---

_Last Updated: [Date]_  
_Version: 1.0_
