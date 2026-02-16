# 🔐 Cipher Auth

> TypeScript-first authentication built on Passport.js. Better DX, same battle-tested reliability.

**Cipher Auth** wraps Passport.js with a modern TypeScript API and Mongoose integration. Get the reliability of Passport with the developer experience you deserve.

[![npm version](https://img.shields.io/npm/v/@cipher-d-dev/core.svg)](https://www.npmjs.com/package/@cipher-d-dev/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-100%25-blue)](https://www.typescriptlang.org/)

---

## ✨ Features

- 🎯 **Passport.js Foundation** - Battle-tested authentication, enhanced with TypeScript
- 🔒 **Type-Safe** - Full TypeScript support throughout
- 📦 **Mongoose Integration** - Pre-built local strategy with Mongoose
- ⚡ **Simple Setup** - One class, three methods, done
- 🎨 **Flexible** - Use our wrapper or drop down to raw Passport
- 🚀 **Production Ready** - Used by thousands via Passport.js

---

## 🚀 Quick Start

### Installation

```bash
pnpm add @cipher-d-dev/core @cipher-d-dev/cipher-local mongoose bcrypt
```

### Basic Setup (Mongoose + Express)

```typescript
import express from 'express';
import session from 'express-session';
import { MongooseCipherAuthLocalStrategy } from '@cipher-d-dev/cipher-local';
import cipher_auth from '@cipher-d-dev/core';
import UserModel from './models/User';

const app = express();

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

// Initialize Cipher Auth
const authStrategy = new MongooseCipherAuthLocalStrategy(
  UserModel,
  'email',      // unique field (email or username)
  'password'    // password field
);

authStrategy.initialize();
authStrategy.cipherSerialize();
authStrategy.cipherDeserialize();

// Apply Passport middleware
app.use(cipher_auth.initialize());
app.use(cipher_auth.session());

// Login route
app.post('/login',
  cipher_auth.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login'
  })
);

// Logout route
app.post('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// Protected route
app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  res.json({ user: req.user });
});

app.listen(3000);
```

---

## 📦 Packages

### `@cipher-d-dev/core`
Passport.js TypeScript wrapper with enhanced type safety.

```typescript
import cipher_auth from '@cipher-d-dev/core';

// cipher_auth is Passport with TypeScript types
cipher_auth.use(strategy);
cipher_auth.authenticate('local');
```

### `@cipher-d-dev/cipher-local`
Local authentication strategy with Mongoose integration.

**Pre-built Strategy:**
```typescript
import { MongooseCipherAuthLocalStrategy } from '@cipher-d-dev/cipher-local';

const authStrategy = new MongooseCipherAuthLocalStrategy(
  UserModel,
  'email',     // or 'username'
  'password'
);

authStrategy.initialize();
authStrategy.cipherSerialize();
authStrategy.cipherDeserialize();
```

**Custom Strategy:**
```typescript
import { CipherLocal } from '@cipher-d-dev/cipher-local';
import cipher_auth from '@cipher-d-dev/core';

cipher_auth.use(
  new CipherLocal(
    {
      usernameField: 'email',
      passwordField: 'password'
    },
    async (email, password, done) => {
      // Your custom logic
      const user = await findUserByEmail(email);
      const valid = await verifyPassword(password, user.passwordHash);
      
      if (valid) {
        done(null, user);
      } else {
        done(null, false, { message: 'Invalid credentials' });
      }
    }
  )
);
```

---

## 🗂️ User Model Example (Mongoose)

```typescript
import { Schema, model } from 'mongoose';
import bcrypt from 'bcrypt';

const UserSchema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  name: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

export default model('User', UserSchema);
```

---

## 🎯 API Reference

### MongooseCipherAuthLocalStrategy

```typescript
new MongooseCipherAuthLocalStrategy(
  userModel: Model<any>,      // Mongoose model
  uniqueField?: string,        // 'email' | 'username' (default: 'username')
  passwordField?: string       // default: 'password'
)
```

**Methods:**
- `initialize()` - Configures the local strategy
- `cipherSerialize()` - Sets up user serialization
- `cipherDeserialize()` - Sets up user deserialization

### CipherLocal (Custom Strategy)

```typescript
new CipherLocal(
  options: {
    usernameField: string;
    passwordField: string;
  },
  verify: (username, password, done) => void
)
```

---

## 🔒 Authentication Flow

```
1. User submits login form
   ↓
2. Express receives POST /login
   ↓
3. cipher_auth.authenticate('local') triggers
   ↓
4. CipherLocal strategy executes:
   - Finds user by email/username
   - Compares password with bcrypt
   ↓
5. On success:
   - User serialized to session (user.id)
   - Redirect to dashboard
   ↓
6. Subsequent requests:
   - User deserialized from session
   - Available as req.user
```

---

## 🛡️ Security Best Practices

### Password Hashing
```typescript
import bcrypt from 'bcrypt';

// Hash password (in pre-save hook)
const hash = await bcrypt.hash(password, 10);

// Verify password (in strategy)
const valid = await bcrypt.compare(password, user.password);
```

### Session Security
```typescript
app.use(session({
  secret: process.env.SESSION_SECRET,  // Strong secret!
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',  // HTTPS only in prod
    httpOnly: true,                                  // Prevent XSS
    maxAge: 24 * 60 * 60 * 1000                     // 24 hours
  }
}));
```

### Protected Routes
```typescript
// Middleware
function requireAuth(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// Usage
app.get('/api/profile', requireAuth, (req, res) => {
  res.json({ user: req.user });
});
```

---

## 🎨 Frontend Integration

### Login Form
```html
<form action="/login" method="POST">
  <input type="email" name="email" required />
  <input type="password" name="password" required />
  <button type="submit">Login</button>
</form>
```

### Fetch API (AJAX)
```typescript
async function login(email: string, password: string) {
  const response = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',  // Important for cookies!
    body: JSON.stringify({ email, password })
  });
  
  if (response.ok) {
    window.location.href = '/dashboard';
  } else {
    const error = await response.json();
    console.error(error);
  }
}
```

---

## 🗺️ Roadmap

### ✅ Available Now
- [x] TypeScript wrapper for Passport.js
- [x] Local strategy with Mongoose
- [x] Full type safety
- [x] Session management

### 🚧 Coming Soon
- [ ] React components & hooks (`@cipher-d-dev/react`)
- [ ] OAuth strategies (Google, GitHub, Facebook)
- [ ] Magic link authentication
- [ ] Two-factor authentication (TOTP)
- [ ] Prisma adapter
- [ ] Next.js integration helpers
- [ ] Pre-built UI components

### 🔮 Future
- [ ] WebAuthn/Passkeys
- [ ] SAML 2.0 for enterprise SSO
- [ ] Vue & Svelte components
- [ ] CLI for scaffolding
- [ ] Admin dashboard

---

## 🤝 Why Wrap Passport?

### Passport.js Strengths
- ✅ Battle-tested (10+ years in production)
- ✅ 500+ authentication strategies
- ✅ Trusted by millions of applications
- ✅ Active maintenance and security updates

### Cipher Auth Enhancements
- ✅ **TypeScript-first** - Passport's types aren't great
- ✅ **Mongoose integration** - No boilerplate needed
- ✅ **Modern patterns** - Async/await over callbacks
- ✅ **Better DX** - Simpler setup, clearer APIs
- ✅ **Extensible** - Drop down to Passport when needed

### The Best of Both Worlds
```typescript
// Use our wrapper
const auth = new MongooseCipherAuthLocalStrategy(UserModel);

// Or use Passport directly
cipher_auth.use(new PassportGoogleStrategy({...}));
```

---

## 📚 Documentation

- [Getting Started](https://cipher-d-dev.dev/docs/getting-started)
- [API Reference](https://cipher-d-dev.dev/docs/api)
- [Migration from Passport](https://cipher-d-dev.dev/docs/migrations/passport)
- [Recipes](https://cipher-d-dev.dev/docs/recipes)

---

## 🙏 Acknowledgments

Built on top of:
- **[Passport.js](https://www.passportjs.org/)** - The authentication foundation
- **[Mongoose](https://mongoosejs.com/)** - MongoDB object modeling
- **[bcrypt](https://github.com/kelektiv/node.bcrypt.js)** - Password hashing

---

## 📄 License

MIT © [cipher-d-dev](./LICENSE)

---

## 💬 Community & Support

- 📖 [Documentation](https://cipher-d-dev.dev)
- 🐛 [Issue Tracker](https://github.com/cipher-d-dev/cipher_auth/issues)
- 💬 [Discord Community](https://discord.gg/cipher-d-dev)
- 🐦 [Twitter](https://twitter.com/cipher_auth)

---

<div align="center">

**Built with ❤️ for developers who deserve better auth DX**

[Get Started](https://cipher-d-dev.dev/docs) • [View Examples](https://github.com/cipher-d-dev/cipher_auth/tree/main/examples) • [Star on GitHub](https://github.com/cipher-d-dev/cipher_auth)

</div>