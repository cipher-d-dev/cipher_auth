# Cipher Auth

> **Modern, TypeScript-first authentication for Node.js & React.**  
> Self-hostable. Framework agnostic. Developer friendly.

Cipher Auth is an open-source authentication SDK that combines:

- Passport flexibility (strategy-based auth)
- Clerk-style DX (simple hooks + optional UI)
- Fully self-hostable
- Modular packages

Built for teams who want full control without vendor lock-in.

---

# ✨ Goals

## v1 Focus
Ship a small, stable, production-ready core that solves most real-world needs:

- Email/password auth
- Google OAuth
- Sessions (Redis)
- MongoDB (Mongoose)
- PostgreSQL (Prisma)
- React hooks + minimal UI
- Clear documentation

Everything else comes later.

---

# 📦 Packages

```
@cipher-auth/
├── core        → Backend auth engine
├── client      → Framework-agnostic client SDK
├── react       → React hooks + minimal UI
├── mongoose    → MongoDB adapter
└── prisma      → PostgreSQL adapter
```

Each package has a single responsibility for maintainability and smaller installs.

---

# 🚀 Quick Start

## Backend

MongoDB:

```bash
pnpm add @cipher-auth/core @cipher-auth/mongoose ioredis
```

PostgreSQL:

```bash
pnpm add @cipher-auth/core @cipher-auth/prisma ioredis
```

## Frontend

```bash
pnpm add @cipher-auth/react
```

---

# 🏗 Architecture

Cipher Auth uses a strategy-based design:

Database Adapter → Core Engine → Client SDK → React Hooks/UI

This keeps every layer optional and independent.

---

# 🗓 Development Plan

## Phase 1 — Core (Weeks 1–3)
- Core engine
- Sessions (Redis)
- Password hashing (argon2)
- Express adapter
- Mongo + Postgres adapters

## Phase 2 — Strategies (Weeks 4–5)
- Local auth
- Registration/login
- Password reset
- Google OAuth

## Phase 3 — React (Weeks 6–7)
- Hooks: useAuth, useUser, useSession
- Minimal UI: SignIn, SignUp

## Phase 4 — Docs & Launch (Week 8)
- Docusaurus docs
- API reference
- Example apps
- npm publish

---

# 🔮 Post-v1 (Later)

- MFA
- RBAC
- CLI
- Vue/Svelte
- More OAuth providers
- Enterprise features

Added only after real demand.

---

# 🛠 Tech Stack

Backend:
- TypeScript
- Node 18+
- argon2
- ioredis
- Zod
- Vitest
- tsup

Frontend:
- React
- Radix UI
- Tailwind

Infra:
- pnpm workspaces
- Turborepo
- Docusaurus

---

# 🎯 Principles

- Simplicity over features
- Stability over hype
- DX over complexity
- Self-hosting first

Ship small → iterate fast → expand later.

---

# 📄 License

MIT

---

Cipher Auth aims to be the open-source alternative to Clerk/Auth0 — without lock-in.
