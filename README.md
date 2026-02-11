# 🔐 Cipher Auth

> Modern, TypeScript-first authentication for the next generation of web applications.

**Cipher Auth** combines the battle-tested reliability of Passport.js with a modern TypeScript-native API, pre-built UI components, and exceptional developer experience. Think Passport meets Clerk - fully open-source and self-hostable.

[![npm version](https://img.shields.io/npm/v/@cipher-auth/core.svg)](https://www.npmjs.com/package/@cipher-auth/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-100%25-blue)](https://www.typescriptlang.org/)

---

## ✨ Why Cipher Auth?

### 🎯 Built on Proven Foundations
Cipher Auth leverages battle-tested OAuth implementations from **Passport.js** - a library trusted in production by millions of applications for over a decade. We stand on the shoulders of giants, then add the modern DX you deserve.

### 🚀 What Makes Us Different

| Feature | Cipher Auth | Passport.js | Clerk |
|---------|-------------|-------------|-------|
| **TypeScript-First** | ✅ Full type safety | ⚠️ JS with types | ✅ Yes |
| **Modern Async/Await** | ✅ Native promises | ❌ Callbacks | ✅ Yes |
| **Pre-built UI Components** | ✅ Customizable | ❌ None | ⚠️ Limited customization |
| **Self-Hostable** | ✅ Fully | ✅ Yes | ❌ Managed only |
| **Database Agnostic** | ✅ Multiple adapters | ⚠️ DIY | ⚠️ Locked-in |
| **Framework Agnostic** | ✅ Express, Next.js, Fastify+ | ⚠️ Mostly Express | ✅ Yes |
| **No Vendor Lock-in** | ✅ Open source | ✅ Open source | ❌ Proprietary |
| **Pricing** | 🆓 Free forever | 🆓 Free | 💰 Usage-based |

---

## 🎨 Features

### 🔑 **Authentication Strategies**
- ✅ **Local** - Email/password with secure hashing (argon2)
- ✅ **Magic Link** - Passwordless email authentication
- ✅ **OAuth 2.0** - Google, GitHub, Facebook, Twitter, and more
- ✅ **Multi-Factor Auth** - TOTP, SMS, Email OTP, WebAuthn/Passkeys
- 🔜 **SAML 2.0** - Enterprise SSO
- 🔜 **LDAP/Active Directory** - On-premise integration

### 🎨 **Pre-built UI Components**
```tsx
import { SignInForm, AuthProvider } from '@cipher-auth/react';

function App() {
  return (
    <AuthProvider>
      <SignInForm 
        providers={['google', 'github']}
        onSuccess={(user) => console.log('Welcome!', user)}
      />
    </AuthProvider>
  );
}
```

- Fully customizable with Tailwind CSS or CSS variables
- Accessible (WCAG 2.1 AA compliant)
- Mobile-responsive out of the box
- Dark mode support

### 🛡️ **Enterprise-Grade Security**
- ✅ **CSRF Protection** - Built-in token validation
- ✅ **Rate Limiting** - Configurable brute-force protection
- ✅ **Session Management** - Redis, PostgreSQL, MongoDB, or in-memory
- ✅ **JWT Support** - Automatic token refresh and rotation
- ✅ **Audit Logging** - Complete authentication event trail
- ✅ **Device Tracking** - Monitor and manage active sessions

### 🗄️ **Database Agnostic**
```typescript
import { CipherAuth } from '@cipher-auth/core';
import { MongooseAdapter } from '@cipher-auth/mongoose';
import { PrismaAdapter } from '@cipher-auth/prisma';

// Use any database you want
const auth = new CipherAuth({
  adapter: new MongooseAdapter(/* ... */),
  // or: new PrismaAdapter(/* ... */)
  // or: new DrizzleAdapter(/* ... */)
});
```

### 🔧 **Framework Support**
- Express
- Next.js (App Router & Pages Router)
- Fastify
- Koa
- Hapi
- NestJS

---

## 🚀 Quick Start

### Installation

```bash
# Backend
npm install @cipher-auth/core @cipher-auth/mongoose

# Frontend (React)
npm install @cipher-auth/react @cipher-auth/client
```

### Backend Setup (Standalone Server)

```typescript
import { CipherAuth } from '@cipher-auth/core';
import { MongooseAdapter } from '@cipher-auth/mongoose';
import { LocalStrategy, GoogleStrategy } from '@cipher-auth/strategies';

// Initialize Cipher Auth - it manages the server for you
const auth = new CipherAuth({
  adapter: new MongooseAdapter({
    uri: process.env.MONGODB_URI
  }),
  session: {
    secret: process.env.SESSION_SECRET,
    store: 'redis' // or 'memory' for development
  },
  server: {
    port: 3000,
    cors: {
      origin: 'http://localhost:5173' // Your frontend URL
    }
  }
});

// Register strategies
auth.use(new LocalStrategy());
auth.use(new GoogleStrategy({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
}));

// Start the auth server
auth.listen();
```

**Or integrate with your existing Express app:**

```typescript
import express from 'express';
import { CipherAuth } from '@cipher-auth/core';

const app = express();

const auth = new CipherAuth({
  // ... config
});

auth.use(new LocalStrategy());
auth.use(new GoogleStrategy({ /* ... */ }));

// Mount Cipher Auth routes on your app
app.use('/auth', auth.router());

app.listen(3000);
```

### Frontend Setup (React)

```tsx
import { AuthProvider, SignInForm, useAuth } from '@cipher-auth/react';

function App() {
  return (
    <AuthProvider apiUrl="http://localhost:3000">
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={<ProtectedDashboard />} />
      </Routes>
    </AuthProvider>
  );
}

function LoginPage() {
  return (
    <SignInForm 
      providers={['google', 'github']}
      enableMagicLink
      onSuccess={(user) => window.location.href = '/dashboard'}
    />
  );
}

function ProtectedDashboard() {
  const { user, logout } = useAuth();
  
  if (!user) return <Navigate to="/login" />;
  
  return (
    <div>
      <h1>Welcome, {user.email}</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

---

## 📚 Documentation

- [**Getting Started**](https://cipher-auth.dev/docs/getting-started)
- [**Authentication Strategies**](https://cipher-auth.dev/docs/strategies)
- [**UI Components**](https://cipher-auth.dev/docs/components)
- [**API Reference**](https://cipher-auth.dev/docs/api)
- [**Migration Guides**](https://cipher-auth.dev/docs/migrations)
  - [From Passport.js](https://cipher-auth.dev/docs/migrations/passport)
  - [From Clerk](https://cipher-auth.dev/docs/migrations/clerk)
  - [From Auth0](https://cipher-auth.dev/docs/migrations/auth0)

---

## 🏗️ Architecture & Philosophy

### Standing on the Shoulders of Giants

Cipher Auth is built on proven authentication foundations:

- **OAuth flows** leverage Passport.js strategies that have been battle-tested in millions of production applications
- **Security primitives** use industry-standard libraries (argon2, node:crypto)
- **Session management** follows established patterns with modern improvements

### Our Value Proposition

We don't reinvent authentication - we make it **better**:

1. **Modern TypeScript API** - Full type safety, better autocomplete, fewer bugs
2. **Better Developer Experience** - Intuitive APIs, clear error messages, comprehensive docs
3. **Pre-built Components** - Ship faster with production-ready UI
4. **Unified Solution** - Backend + frontend in one cohesive package
5. **Self-Hostable** - Your data, your infrastructure, your control

### Transparency

We believe in being open about our approach:
- Built on Passport.js OAuth strategies (MIT licensed)
- Custom implementations for session management, user handling, and UI
- All source code available on [GitHub](https://github.com/yourusername/cipher-auth)

---

## 🛣️ Roadmap

### ✅ v1.0 (Current)
- [x] Core authentication SDK
- [x] Local, Magic Link, OAuth strategies
- [x] React components & hooks
- [x] MongoDB & Prisma adapters
- [x] Express & Next.js support

### 🚧 v1.1 (Next)
- [ ] Multi-factor authentication (TOTP, SMS, WebAuthn)
- [ ] Vue & Svelte components
- [ ] RBAC & permissions system
- [ ] Advanced audit logging
- [ ] CLI tool for scaffolding

### 🔮 v2.0 (Future)
- [ ] SAML 2.0 support
- [ ] LDAP/Active Directory
- [ ] Custom OAuth strategy builder
- [ ] Managed hosting option
- [ ] Admin dashboard

[View full roadmap →](https://github.com/yourusername/cipher-auth/blob/main/ROADMAP.md)

---

## 🤝 Contributing

We welcome contributions! Cipher Auth is built by developers, for developers.

```bash
# Clone the repo
git clone https://github.com/yourusername/cipher-auth.git

# Install dependencies
pnpm install

# Run tests
pnpm test

# Start development
pnpm dev
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed guidelines.

---

## 📦 Packages

| Package | Version | Description |
|---------|---------|-------------|
| `@cipher-auth/core` | ![npm](https://img.shields.io/npm/v/@cipher-auth/core) | Core authentication SDK |
| `@cipher-auth/client` | ![npm](https://img.shields.io/npm/v/@cipher-auth/client) | Framework-agnostic client |
| `@cipher-auth/react` | ![npm](https://img.shields.io/npm/v/@cipher-auth/react) | React components & hooks |
| `@cipher-auth/vue` | ![npm](https://img.shields.io/npm/v/@cipher-auth/vue) | Vue components (coming soon) |
| `@cipher-auth/mongoose` | ![npm](https://img.shields.io/npm/v/@cipher-auth/mongoose) | MongoDB/Mongoose adapter |
| `@cipher-auth/prisma` | ![npm](https://img.shields.io/npm/v/@cipher-auth/prisma) | Prisma adapter |
| `@cipher-auth/cli` | ![npm](https://img.shields.io/npm/v/@cipher-auth/cli) | CLI tool (coming soon) |

---

## 🙏 Acknowledgments

Cipher Auth wouldn't exist without:

- **[Passport.js](https://www.passportjs.org/)** - The foundation of our OAuth implementations
- **[Radix UI](https://www.radix-ui.com/)** - Accessible component primitives
- **[Clerk](https://clerk.com/)** - Inspiration for great auth DX
- **The open-source community** - For continuous feedback and contributions

---

## 📄 License

MIT © [Cipher & Jamal](./LICENSE)

---

## 💬 Community & Support

- 📖 [Documentation](https://cipher-auth.dev)
- 💬 [Discord Community](https://discord.gg/cipher-auth)
- 🐦 [Twitter](https://twitter.com/cipher_auth)
- 🐛 [Issue Tracker](https://github.com/yourusername/cipher-auth/issues)
- 📧 [Email Support](mailto:support@cipher-auth.dev)

---

<div align="center">

**Built with ❤️ by developers who were tired of complicated auth**

[Get Started](https://cipher-auth.dev/docs/getting-started) • [View Demo](https://demo.cipher-auth.dev) • [Star on GitHub](https://github.com/yourusername/cipher-auth)

</div>