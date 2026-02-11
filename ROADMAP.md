# Cipher Auth - Step-by-Step Implementation Guide
### For MERN Stack Developers

> **Goal**: Build a modern authentication SDK that works like Passport but with better TypeScript support and pre-built React components.

---

## 🎓 Understanding the Architecture First

### What Are We Building?

Think of Cipher Auth like this:

```
┌─────────────────────────────────────────────────────┐
│                    YOUR APP                          │
│  ┌──────────────┐              ┌─────────────────┐  │
│  │   React      │              │   Express API   │  │
│  │  Frontend    │◄────────────►│    Backend      │  │
│  │              │   HTTP/JSON  │                 │  │
│  └──────────────┘              └─────────────────┘  │
│         │                              │             │
│         │                              │             │
│    ┌────▼─────┐                  ┌────▼────────┐   │
│    │ Cipher   │                  │   Cipher    │   │
│    │ Auth     │                  │   Auth      │   │
│    │ React    │                  │   Core      │   │
│    │Components│                  │   (Backend) │   │
│    └──────────┘                  └─────────────┘   │
│                                         │           │
│                                   ┌─────▼──────┐   │
│                                   │  MongoDB   │   │
│                                   └────────────┘   │
└─────────────────────────────────────────────────────┘
```

**Cipher Auth Core** = Backend SDK (like Passport)
**Cipher Auth React** = Frontend components (like Clerk's UI)
**Cipher Auth Client** = Bridge between frontend and backend

---

## 📦 Month 1, Week 1: Project Setup

### Day 1: Understanding Monorepos

**What is a Monorepo?**
Instead of having separate GitHub repos for each package, we put everything in ONE repo:

```
cipher-auth/
├── packages/
│   ├── core/          ← Backend SDK
│   ├── client/        ← Frontend SDK
│   ├── react/         ← React components
│   └── mongoose/      ← MongoDB adapter
└── package.json
```

**Why?** 
- Share code easily between packages
- Test everything together
- Version all packages at once

**What You'll Do:**

```bash
# 1. Install pnpm (faster than npm)
npm install -g pnpm

# 2. Create project
mkdir cipher-auth
cd cipher-auth
pnpm init

# 3. Install Turborepo
pnpm add -D turbo

# 4. Create workspace config
```

**File: `pnpm-workspace.yaml`**
```yaml
packages:
  - 'packages/*'
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
      "dependsOn": ["build"]
    },
    "dev": {
      "cache": false
    }
  }
}
```

**File: `package.json`** (root)
```json
{
  "name": "cipher-auth",
  "private": true,
  "scripts": {
    "build": "turbo run build",
    "dev": "turbo run dev",
    "test": "turbo run test"
  },
  "devDependencies": {
    "turbo": "^1.11.0",
    "typescript": "^5.3.0",
    "@types/node": "^20.10.0"
  }
}
```

**Create each package:**

```bash
mkdir -p packages/core packages/client packages/react packages/mongoose

# For each package, create:
cd packages/core
pnpm init
```

**File: `packages/core/package.json`**
```json
{
  "name": "@cipher-auth/core",
  "version": "0.0.1",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "scripts": {
    "build": "tsup src/index.ts --format cjs,esm --dts",
    "dev": "tsup src/index.ts --format cjs,esm --dts --watch"
  },
  "devDependencies": {
    "tsup": "^8.0.0",
    "typescript": "^5.3.0"
  }
}
```

**File: `packages/core/tsconfig.json`**
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "lib": ["ES2020"],
    "moduleResolution": "node",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "declaration": true,
    "outDir": "./dist"
  },
  "include": ["src/**/*"]
}
```

Repeat similar setup for `client`, `react`, and `mongoose` packages.

---

## 📦 Month 1, Week 1-2: Core Backend - Strategy Pattern

### Understanding: What is the Strategy Pattern?

**In MERN terms:**
You know how in Express you have different routes? Strategy pattern is similar - it lets you have different authentication methods (strategies) that all work the same way.

**Example:**
```javascript
// Without strategy pattern (messy)
app.post('/login', (req, res) => {
  if (req.body.provider === 'local') {
    // Handle email/password
  } else if (req.body.provider === 'google') {
    // Handle Google OAuth
  } else if (req.body.provider === 'github') {
    // Handle GitHub OAuth
  }
  // Gets messy fast!
});

// With strategy pattern (clean)
auth.use(new LocalStrategy());
auth.use(new GoogleStrategy());
auth.use(new GitHubStrategy());

app.post('/login/:strategy', auth.authenticate());
// Much cleaner!
```

---

### Feature 1: Base Strategy Class

**File: `packages/core/src/strategies/Strategy.ts`**

```typescript
// This is like an abstract class in OOP
// All authentication strategies will extend this

export interface AuthResult {
  user: User;
  token?: string;
}

export interface User {
  id: string;
  email: string;
  name?: string;
  emailVerified: boolean;
}

export abstract class Strategy {
  // Every strategy must have a name (e.g., "local", "google")
  abstract name: string;
  
  // Every strategy must implement authenticate method
  // This is the main method that logs a user in
  abstract authenticate(
    req: any,      // Express request object
    options?: any  // Extra options (like redirect URLs)
  ): Promise<AuthResult>;
}
```

**Why?**
- Forces all strategies to have the same interface
- Makes it easy to swap strategies
- Like how Array methods (map, filter) all work the same way

**Real Example:**

```typescript
// LocalStrategy (email/password)
class LocalStrategy extends Strategy {
  name = 'local';
  
  async authenticate(req: any): Promise<AuthResult> {
    const { email, password } = req.body;
    // Check password, return user
  }
}

// GoogleStrategy (OAuth)
class GoogleStrategy extends Strategy {
  name = 'google';
  
  async authenticate(req: any): Promise<AuthResult> {
    const { code } = req.query;
    // Exchange code for token, get user info
  }
}
```

---

### Feature 2: Strategy Registry

**What is this?**
A registry is just a fancy word for a "list" or "collection". It stores all your strategies so you can use them later.

**Think of it like:**
```javascript
// In Express, you register routes:
app.use('/api', apiRouter);
app.use('/auth', authRouter);

// In Cipher Auth, you register strategies:
auth.use(new LocalStrategy());
auth.use(new GoogleStrategy());
```

**File: `packages/core/src/strategies/StrategyRegistry.ts`**

```typescript
import { Strategy, AuthResult } from './Strategy';

export class StrategyRegistry {
  // Store strategies in a Map (like an object but better)
  // Key = strategy name (e.g., "local"), Value = Strategy instance
  private strategies = new Map<string, Strategy>();
  
  /**
   * Register a new strategy
   * @example
   * registry.use(new LocalStrategy());
   */
  use(strategy: Strategy): void {
    // Check if strategy already exists
    if (this.strategies.has(strategy.name)) {
      throw new Error(`Strategy "${strategy.name}" already registered`);
    }
    
    this.strategies.set(strategy.name, strategy);
  }
  
  /**
   * Get a strategy by name
   * @example
   * const local = registry.get('local');
   */
  get(name: string): Strategy | undefined {
    return this.strategies.get(name);
  }
  
  /**
   * Authenticate using a specific strategy
   * @example
   * const result = await registry.authenticate('local', req);
   */
  async authenticate(
    name: string, 
    req: any, 
    options?: any
  ): Promise<AuthResult> {
    // Get the strategy
    const strategy = this.strategies.get(name);
    
    if (!strategy) {
      throw new Error(`Strategy "${name}" not found`);
    }
    
    // Run the strategy's authenticate method
    return strategy.authenticate(req, options);
  }
  
  /**
   * Get all registered strategy names
   */
  getNames(): string[] {
    return Array.from(this.strategies.keys());
  }
}
```

**Why use a Map instead of an object?**
```javascript
// Object (old way)
const strategies = {};
strategies['local'] = new LocalStrategy();

// Map (better way)
const strategies = new Map();
strategies.set('local', new LocalStrategy());

// Map is better because:
// 1. Keys can be any type (not just strings)
// 2. Has .size property
// 3. Preserves insertion order
// 4. Easier to iterate
```

---

### Feature 3: Session Management

**What are Sessions?**

In MERN, you probably use JWT tokens or cookies. Sessions are similar but stored on the server.

**How it works:**

```
1. User logs in
2. Server creates a session and stores it
3. Server sends session ID to browser (as cookie)
4. Browser sends session ID with each request
5. Server looks up session to know who you are
```

**Why use sessions instead of JWT?**
- More secure (can't be tampered with on client)
- Can invalidate immediately (logout works instantly)
- Can track active devices
- Better for sensitive apps

**But sessions need storage:**
- **Memory** - Fast but lost on restart (dev only)
- **Redis** - Fast and persistent (production)
- **MongoDB** - Slower but you already have it

---

### Understanding Session Stores

**File: `packages/core/src/session/SessionStore.ts`**

```typescript
// This defines what ALL session stores must do
// Think of it like a contract

export interface Session {
  id: string;           // Unique session ID
  userId: string;       // Who owns this session
  expiresAt: Date;      // When it expires
  createdAt: Date;      // When created
  data?: any;           // Extra data (like IP, device)
}

export interface SessionStore {
  // Get a session by ID
  get(sessionId: string): Promise<Session | null>;
  
  // Save or update a session
  set(sessionId: string, session: Session): Promise<void>;
  
  // Delete a session (logout)
  destroy(sessionId: string): Promise<void>;
  
  // Update expiry time (keep alive)
  touch(sessionId: string): Promise<void>;
}
```

---

### Memory Store (for Development)

**File: `packages/core/src/session/MemoryStore.ts`**

```typescript
import { SessionStore, Session } from './SessionStore';

export class MemoryStore implements SessionStore {
  // Store sessions in RAM (lost on restart)
  private sessions = new Map<string, Session>();
  
  async get(sessionId: string): Promise<Session | null> {
    const session = this.sessions.get(sessionId);
    
    // Check if expired
    if (session && session.expiresAt < new Date()) {
      // Session expired, delete it
      this.sessions.delete(sessionId);
      return null;
    }
    
    return session || null;
  }
  
  async set(sessionId: string, session: Session): Promise<void> {
    this.sessions.set(sessionId, session);
  }
  
  async destroy(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }
  
  async touch(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      // Extend expiry by 1 day
      session.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
      this.sessions.set(sessionId, session);
    }
  }
}
```

**Why Memory Store?**
- Super fast
- No setup needed
- Perfect for development
- **DON'T USE IN PRODUCTION** (lost on restart)

---

### Redis Store (for Production)

**What is Redis?**
Redis is like MongoDB but for temporary data. It's super fast because everything is in RAM.

**Install Redis:**
```bash
# Mac
brew install redis

# Ubuntu
sudo apt install redis-server

# Start Redis
redis-server
```

**File: `packages/core/src/session/RedisStore.ts`**

```typescript
import { SessionStore, Session } from './SessionStore';
import Redis from 'ioredis';

export class RedisStore implements SessionStore {
  private client: Redis;
  
  constructor(redisUrl: string = 'redis://localhost:6379') {
    // Connect to Redis
    this.client = new Redis(redisUrl);
  }
  
  async get(sessionId: string): Promise<Session | null> {
    // Get session from Redis
    const data = await this.client.get(`session:${sessionId}`);
    
    if (!data) return null;
    
    // Parse JSON back to object
    const session = JSON.parse(data);
    
    // Check expiry
    if (new Date(session.expiresAt) < new Date()) {
      await this.destroy(sessionId);
      return null;
    }
    
    return session;
  }
  
  async set(sessionId: string, session: Session): Promise<void> {
    const key = `session:${sessionId}`;
    const value = JSON.stringify(session);
    
    // Calculate TTL (time to live) in seconds
    const ttl = Math.floor(
      (session.expiresAt.getTime() - Date.now()) / 1000
    );
    
    // Save to Redis with auto-expiry
    await this.client.setex(key, ttl, value);
  }
  
  async destroy(sessionId: string): Promise<void> {
    await this.client.del(`session:${sessionId}`);
  }
  
  async touch(sessionId: string): Promise<void> {
    const session = await this.get(sessionId);
    if (session) {
      // Extend expiry
      session.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await this.set(sessionId, session);
    }
  }
}
```

**Install dependency:**
```bash
cd packages/core
pnpm add ioredis
pnpm add -D @types/ioredis
```

---

### Session Manager

**What does this do?**
This is the high-level API that uses the stores. It's like a controller in MVC.

**File: `packages/core/src/session/SessionManager.ts`**

```typescript
import { SessionStore, Session } from './SessionStore';
import { randomBytes } from 'crypto';

export class SessionManager {
  private store: SessionStore;
  
  constructor(store: SessionStore) {
    this.store = store;
  }
  
  /**
   * Create a new session for a user
   */
  async create(userId: string, data?: any): Promise<Session> {
    // Generate random session ID (32 bytes = 64 hex chars)
    const sessionId = randomBytes(32).toString('hex');
    
    const session: Session = {
      id: sessionId,
      userId,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      createdAt: new Date(),
      data
    };
    
    await this.store.set(sessionId, session);
    
    return session;
  }
  
  /**
   * Validate and get a session
   */
  async validate(sessionId: string): Promise<Session | null> {
    return this.store.get(sessionId);
  }
  
  /**
   * Refresh session expiry
   */
  async refresh(sessionId: string): Promise<Session> {
    const session = await this.store.get(sessionId);
    
    if (!session) {
      throw new Error('Session not found');
    }
    
    // Extend expiry
    session.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await this.store.set(sessionId, session);
    
    return session;
  }
  
  /**
   * Destroy a session (logout)
   */
  async destroy(sessionId: string): Promise<void> {
    await this.store.destroy(sessionId);
  }
  
  /**
   * Destroy all sessions for a user (logout everywhere)
   */
  async destroyAll(userId: string): Promise<void> {
    // This requires a different approach
    // We'll implement this later with Redis SCAN
    throw new Error('Not implemented yet');
  }
}
```

---

### Feature 4: Security Primitives

**What are these?**
These are the building blocks for security - password hashing, CSRF protection, etc.

---

### Password Hashing

**Why hash passwords?**
```javascript
// BAD - Never do this!
user.password = "mypassword123"; // Stored in plain text

// If database is hacked, attacker has everyone's passwords!
```

```javascript
// GOOD - Hash passwords
user.passwordHash = "$argon2id$v=19$m=65536..."; // One-way hash

// Even if database is hacked, attacker can't get original password
```

**What is Argon2?**
- The most secure password hashing algorithm (winner of password hashing competition)
- Better than bcrypt (the old standard)
- Used by big companies like Microsoft, Google

**File: `packages/core/src/security/password.ts`**

```typescript
import * as argon2 from 'argon2';

/**
 * Hash a password securely
 * @example
 * const hash = await hashPassword('mypassword123');
 * // Returns: $argon2id$v=19$m=65536,t=3,p=4$...
 */
export async function hashPassword(password: string): Promise<string> {
  // Argon2 automatically handles:
  // - Salt generation (random data added to password)
  // - Multiple rounds of hashing
  // - Memory-hard computation (prevents GPU attacks)
  
  return argon2.hash(password, {
    type: argon2.argon2id,  // Most secure variant
    memoryCost: 65536,       // 64 MB of RAM needed
    timeCost: 3,             // 3 iterations
    parallelism: 4           // Use 4 threads
  });
}

/**
 * Verify a password against a hash
 * @example
 * const valid = await verifyPassword('mypassword123', hash);
 * // Returns: true or false
 */
export async function verifyPassword(
  password: string, 
  hash: string
): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch (error) {
    // Invalid hash format
    return false;
  }
}
```

**Install dependency:**
```bash
cd packages/core
pnpm add argon2
```

**Test it:**
```typescript
// test.ts
import { hashPassword, verifyPassword } from './password';

async function test() {
  const password = 'mySecurePassword123';
  
  // Hash it
  const hash = await hashPassword(password);
  console.log('Hash:', hash);
  // Output: $argon2id$v=19$m=65536,t=3,p=4$somerandomsalt$actualhashedvalue
  
  // Verify correct password
  const valid = await verifyPassword(password, hash);
  console.log('Valid:', valid); // true
  
  // Verify wrong password
  const invalid = await verifyPassword('wrongPassword', hash);
  console.log('Invalid:', invalid); // false
}
```

---

### CSRF Protection

**What is CSRF?**
Cross-Site Request Forgery - when a malicious site makes requests to your API pretending to be you.

**Example attack:**
```html
<!-- Evil website -->
<img src="https://yourbank.com/transfer?to=hacker&amount=10000">
<!-- Your browser automatically sends your cookies! -->
```

**How CSRF tokens prevent this:**
1. Server generates a random token
2. Server stores token in session
3. Server sends token to frontend
4. Frontend includes token in forms/requests
5. Server verifies token matches

**File: `packages/core/src/security/csrf.ts`**

```typescript
import { randomBytes, createHmac } from 'crypto';

/**
 * Generate a CSRF token
 * @param secret - Server secret (from env)
 * @param sessionId - Current session ID
 */
export function generateCSRFToken(secret: string, sessionId: string): string {
  // Create random salt
  const salt = randomBytes(16).toString('hex');
  
  // Create HMAC (hash-based message authentication code)
  const hmac = createHmac('sha256', secret);
  hmac.update(`${sessionId}:${salt}`);
  const hash = hmac.digest('hex');
  
  // Combine salt and hash
  return `${salt}:${hash}`;
}

/**
 * Verify a CSRF token
 */
export function verifyCSRFToken(
  token: string, 
  secret: string, 
  sessionId: string
): boolean {
  try {
    // Split token
    const [salt, hash] = token.split(':');
    
    if (!salt || !hash) return false;
    
    // Recreate HMAC
    const hmac = createHmac('sha256', secret);
    hmac.update(`${sessionId}:${salt}`);
    const expectedHash = hmac.digest('hex');
    
    // Compare (timing-safe comparison)
    return timingSafeEqual(
      Buffer.from(hash, 'hex'),
      Buffer.from(expectedHash, 'hex')
    );
  } catch {
    return false;
  }
}

/**
 * Timing-safe comparison (prevents timing attacks)
 */
function timingSafeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  
  return result === 0;
}
```

**How to use it:**

```typescript
// In Express route
app.get('/form', (req, res) => {
  const csrfToken = generateCSRFToken(
    process.env.SECRET, 
    req.sessionID
  );
  
  res.json({ csrfToken });
});

app.post('/submit', (req, res) => {
  const { csrfToken } = req.body;
  
  const valid = verifyCSRFToken(
    csrfToken,
    process.env.SECRET,
    req.sessionID
  );
  
  if (!valid) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  // Process request...
});
```

---

### Rate Limiting

**What is Rate Limiting?**
Preventing users from making too many requests too quickly.

**Why?**
- Prevent brute-force attacks (trying many passwords)
- Prevent DDoS attacks
- Prevent API abuse

**Example:**
```
User tries login with wrong password:
- Attempt 1: Allowed
- Attempt 2: Allowed
- Attempt 3: Allowed
- Attempt 4: Allowed
- Attempt 5: Allowed
- Attempt 6: BLOCKED (too many attempts)
```

**File: `packages/core/src/security/ratelimit.ts`**

```typescript
interface RateLimitEntry {
  count: number;      // Number of requests
  resetAt: number;    // When counter resets (timestamp)
}

export interface RateLimitOptions {
  windowMs: number;   // Time window in milliseconds
  max: number;        // Max requests per window
}

export class RateLimiter {
  private store = new Map<string, RateLimitEntry>();
  private options: RateLimitOptions;
  
  constructor(options: RateLimitOptions) {
    this.options = options;
    
    // Clean up expired entries every minute
    setInterval(() => this.cleanup(), 60000);
  }
  
  /**
   * Check if request is allowed
   * @param identifier - Unique identifier (usually IP or user ID)
   * @returns true if allowed, false if rate limited
   */
  async check(identifier: string): Promise<boolean> {
    const now = Date.now();
    const entry = this.store.get(identifier);
    
    // No entry yet, create one
    if (!entry) {
      this.store.set(identifier, {
        count: 1,
        resetAt: now + this.options.windowMs
      });
      return true;
    }
    
    // Window expired, reset counter
    if (now > entry.resetAt) {
      this.store.set(identifier, {
        count: 1,
        resetAt: now + this.options.windowMs
      });
      return true;
    }
    
    // Within window, check count
    if (entry.count >= this.options.max) {
      return false; // Rate limited!
    }
    
    // Increment count
    entry.count++;
    this.store.set(identifier, entry);
    return true;
  }
  
  /**
   * Get remaining requests
   */
  async getRemaining(identifier: string): Promise<number> {
    const entry = this.store.get(identifier);
    if (!entry) return this.options.max;
    
    const now = Date.now();
    if (now > entry.resetAt) return this.options.max;
    
    return Math.max(0, this.options.max - entry.count);
  }
  
  /**
   * Reset rate limit for an identifier
   */
  async reset(identifier: string): Promise<void> {
    this.store.delete(identifier);
  }
  
  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const now = Date.now();
    
    for (const [identifier, entry] of this.store.entries()) {
      if (now > entry.resetAt) {
        this.store.delete(identifier);
      }
    }
  }
}
```

**How to use it:**

```typescript
// Create rate limiter - allow 5 login attempts per 15 minutes
const loginLimiter = new RateLimiter({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5                      // 5 attempts
});

// In login route
app.post('/login', async (req, res) => {
  const identifier = req.ip; // Use IP address
  
  // Check rate limit
  const allowed = await loginLimiter.check(identifier);
  
  if (!allowed) {
    return res.status(429).json({ 
      error: 'Too many login attempts. Try again in 15 minutes.' 
    });
  }
  
  // Process login...
});
```

---

## 📦 Month 1, Week 2: Database Layer

### Understanding Database Adapters

**What's an adapter?**
Think of adapters like power adapters for different countries. The plug (interface) is the same, but the implementation differs.

```
Your Code → Adapter Interface → [MongoDB Adapter]  → MongoDB
                              → [Prisma Adapter]   → PostgreSQL
                              → [Drizzle Adapter]  → MySQL
```

**Why adapters?**
- Users can choose their preferred database
- We write code once, it works with any database
- Easy to switch databases later

---

### Adapter Interface

**File: `packages/core/src/adapters/Adapter.ts`**

```typescript
// Define what a User looks like
export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  passwordHash?: string;  // Optional (not used for OAuth-only users)
  name?: string;
  image?: string;
  createdAt: Date;
  updatedAt: Date;
}

// Data needed to create a user
export interface CreateUserInput {
  email: string;
  emailVerified?: boolean;
  passwordHash?: string;
  name?: string;
  image?: string;
}

// Data that can be updated
export interface UpdateUserInput {
  email?: string;
  emailVerified?: boolean;
  passwordHash?: string;
  name?: string;
  image?: string;
}

// OAuth connection (e.g., "This user linked their Google account")
export interface OAuthConnection {
  provider: string;       // "google", "github", etc.
  providerId: string;     // User's ID at that provider
  accessToken: string;
  refreshToken?: string;
  expiresAt?: Date;
}

/**
 * Database adapter interface
 * All database adapters must implement these methods
 */
export interface Adapter {
  // User CRUD
  createUser(data: CreateUserInput): Promise<User>;
  getUserById(id: string): Promise<User | null>;
  getUserByEmail(email: string): Promise<User | null>;
  updateUser(id: string, data: UpdateUserInput): Promise<User>;
  deleteUser(id: string): Promise<void>;
  
  // OAuth
  linkOAuthAccount(
    userId: string, 
    provider: string, 
    data: OAuthConnection
  ): Promise<void>;
  
  getOAuthAccount(
    provider: string, 
    providerId: string
  ): Promise<User | null>;
  
  unlinkOAuthAccount(userId: string, provider: string): Promise<void>;
}
```

---

### Mongoose Adapter (MongoDB)

Since you're familiar with MERN, this will make sense!

**File: `packages/mongoose/src/models/User.ts`**

```typescript
import { Schema, model } from 'mongoose';

// User schema
const UserSchema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  passwordHash: {
    type: String,
    // Not required - OAuth users don't have passwords
  },
  name: String,
  image: String,
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update 'updatedAt' before saving
UserSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

export const UserModel = model('User', UserSchema);
```

**File: `packages/mongoose/src/models/OAuthConnection.ts`**

```typescript
import { Schema, model } from 'mongoose';

const OAuthConnectionSchema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  provider: {
    type: String,
    required: true
  },
  providerId: {
    type: String,
    required: true
  },
  accessToken: {
    type: String,
    required: true
  },
  refreshToken: String,
  expiresAt: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Compound index - one provider account per user
OAuthConnectionSchema.index({ userId: 1, provider: 1 }, { unique: true });
// Fast lookup by provider + providerId
OAuthConnectionSchema.index({ provider: 1, providerId: 1 }, { unique: true });

export const OAuthConnectionModel = model('OAuthConnection', OAuthConnectionSchema);
```

**File: `packages/mongoose/src/MongooseAdapter.ts`**

```typescript
import mongoose from 'mongoose';
import { Adapter, User, CreateUserInput, UpdateUserInput, OAuthConnection } from '@cipher-auth/core';
import { UserModel } from './models/User';
import { OAuthConnectionModel } from './models/OAuthConnection';

export interface MongooseAdapterOptions {
  uri: string;  // MongoDB connection string
}

export class MongooseAdapter implements Adapter {
  constructor(options: MongooseAdapterOptions) {
    // Connect to MongoDB
    mongoose.connect(options.uri);
  }
  
  async createUser(data: CreateUserInput): Promise<User> {
    const user = await UserModel.create(data);
    
    // Convert Mongoose document to plain object
    return {
      id: user._id.toString(),
      email: user.email,
      emailVerified: user.emailVerified,
      passwordHash: user.passwordHash,
      name: user.name,
      image: user.image,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  }
  
  async getUserById(id: string): Promise<User | null> {
    const user = await UserModel.findById(id);
    if (!user) return null;
    
    return {
      id: user._id.toString(),
      email: user.email,
      emailVerified: user.emailVerified,
      passwordHash: user.passwordHash,
      name: user.name,
      image: user.image,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  }
  
  async getUserByEmail(email: string): Promise<User | null> {
    const user = await UserModel.findOne({ email: email.toLowerCase() });
    if (!user) return null;
    
    return {
      id: user._id.toString(),
      email: user.email,
      emailVerified: user.emailVerified,
      passwordHash: user.passwordHash,
      name: user.name,
      image: user.image,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  }
  
  async updateUser(id: string, data: UpdateUserInput): Promise<User> {
    const user = await UserModel.findByIdAndUpdate(
      id,
      { ...data, updatedAt: new Date() },
      { new: true } // Return updated document
    );
    
    if (!user) {
      throw new Error('User not found');
    }
    
    return {
      id: user._id.toString(),
      email: user.email,
      emailVerified: user.emailVerified,
      passwordHash: user.passwordHash,
      name: user.name,
      image: user.image,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  }
  
  async deleteUser(id: string): Promise<void> {
    await UserModel.findByIdAndDelete(id);
    // Also delete OAuth connections
    await OAuthConnectionModel.deleteMany({ userId: id });
  }
  
  async linkOAuthAccount(
    userId: string,
    provider: string,
    data: OAuthConnection
  ): Promise<void> {
    await OAuthConnectionModel.create({
      userId,
      provider,
      providerId: data.providerId,
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
      expiresAt: data.expiresAt
    });
  }
  
  async getOAuthAccount(
    provider: string,
    providerId: string
  ): Promise<User | null> {
    // Find OAuth connection
    const connection = await OAuthConnectionModel.findOne({
      provider,
      providerId
    }).populate('userId');
    
    if (!connection) return null;
    
    // Get the user
    const user = await UserModel.findById(connection.userId);
    if (!user) return null;
    
    return {
      id: user._id.toString(),
      email: user.email,
      emailVerified: user.emailVerified,
      passwordHash: user.passwordHash,
      name: user.name,
      image: user.image,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  }
  
  async unlinkOAuthAccount(userId: string, provider: string): Promise<void> {
    await OAuthConnectionModel.deleteOne({ userId, provider });
  }
}
```

**Install dependencies:**
```bash
cd packages/mongoose
pnpm add mongoose
pnpm add -D @types/mongoose
```

---

## 📦 Putting It All Together: CipherAuth Main Class

Now we combine everything into one easy-to-use class!

**File: `packages/core/src/CipherAuth.ts`**

```typescript
import express, { Express, Router } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { StrategyRegistry } from './strategies/StrategyRegistry';
import { Strategy } from './strategies/Strategy';
import { SessionManager } from './session/SessionManager';
import { SessionStore } from './session/SessionStore';
import { MemoryStore } from './session/MemoryStore';
import { RedisStore } from './session/RedisStore';
import { Adapter } from './adapters/Adapter';

export interface CipherAuthConfig {
  // Database adapter
  adapter: Adapter;
  
  // Session config
  session: {
    secret: string;
    store: 'memory' | 'redis';
    redis?: {
      url: string;
    };
  };
  
  // Server config (optional - only if using standalone mode)
  server?: {
    port: number;
    cors?: {
      origin: string | string[];
    };
  };
}

export class CipherAuth {
  private strategies: StrategyRegistry;
  private sessionManager: SessionManager;
  private adapter: Adapter;
  private config: CipherAuthConfig;
  private app?: Express;
  
  constructor(config: CipherAuthConfig) {
    this.config = config;
    this.adapter = config.adapter;
    
    // Setup session store
    let sessionStore: SessionStore;
    if (config.session.store === 'redis') {
      sessionStore = new RedisStore(config.session.redis?.url);
    } else {
      sessionStore = new MemoryStore();
    }
    
    this.sessionManager = new SessionManager(sessionStore);
    this.strategies = new StrategyRegistry();
    
    // Setup server if configured
    if (config.server) {
      this.setupServer();
    }
  }
  
  /**
   * Register an authentication strategy
   * @example
   * auth.use(new LocalStrategy());
   */
  use(strategy: Strategy): void {
    this.strategies.use(strategy);
  }
  
  /**
   * Get Express router with auth routes
   * @example
   * app.use('/auth', auth.router());
   */
  router(): Router {
    const router = express.Router();
    
    // Attach auth instance to requests
    router.use((req, res, next) => {
      (req as any).auth = this;
      next();
    });
    
    // Load session from cookie
    router.use(async (req, res, next) => {
      const sessionId = req.cookies.sessionId;
      
      if (sessionId) {
        const session = await this.sessionManager.validate(sessionId);
        if (session) {
          (req as any).session = session;
          (req as any).user = await this.adapter.getUserById(session.userId);
        }
      }
      
      next();
    });
    
    // Auto-generate routes for each strategy
    const strategyNames = this.strategies.getNames();
    
    for (const name of strategyNames) {
      // GET /auth/:strategy - Initiate auth (for OAuth)
      router.get(`/${name}`, async (req, res, next) => {
        try {
          const result = await this.strategies.authenticate(name, req);
          
          // For OAuth, this returns a redirect URL
          if (result.redirectUrl) {
            return res.redirect(result.redirectUrl);
          }
          
          // For other strategies, create session and return token
          const session = await this.sessionManager.create(result.user.id);
          
          res.cookie('sessionId', session.id, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
          });
          
          res.json({ user: result.user });
        } catch (error) {
          next(error);
        }
      });
      
      // POST /auth/:strategy - Authenticate (for local, magic link, etc.)
      router.post(`/${name}`, async (req, res, next) => {
        try {
          const result = await this.strategies.authenticate(name, req);
          
          // Create session
          const session = await this.sessionManager.create(result.user.id);
          
          // Set cookie
          res.cookie('sessionId', session.id, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000
          });
          
          res.json({ user: result.user });
        } catch (error) {
          next(error);
        }
      });
      
      // GET /auth/:strategy/callback - OAuth callback
      router.get(`/${name}/callback`, async (req, res, next) => {
        try {
          const result = await this.strategies.authenticate(name, req);
          
          // Create session
          const session = await this.sessionManager.create(result.user.id);
          
          // Set cookie
          res.cookie('sessionId', session.id, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000
          });
          
          // Redirect to success URL
          const redirectUrl = req.query.redirect || '/dashboard';
          res.redirect(redirectUrl as string);
        } catch (error) {
          next(error);
        }
      });
    }
    
    // POST /auth/logout
    router.post('/logout', async (req, res) => {
      const sessionId = req.cookies.sessionId;
      
      if (sessionId) {
        await this.sessionManager.destroy(sessionId);
      }
      
      res.clearCookie('sessionId');
      res.json({ success: true });
    });
    
    // GET /auth/me - Get current user
    router.get('/me', async (req, res) => {
      const user = (req as any).user;
      
      if (!user) {
        return res.status(401).json({ error: 'Not authenticated' });
      }
      
      res.json({ user });
    });
    
    return router;
  }
  
  /**
   * Start standalone server
   * @example
   * auth.listen(3000);
   */
  listen(port?: number): void {
    if (!this.app) {
      throw new Error('Server not configured. Provide server config in constructor.');
    }
    
    const listenPort = port || this.config.server?.port || 3000;
    
    this.app.listen(listenPort, () => {
      console.log(`🔐 Cipher Auth server running on port ${listenPort}`);
    });
  }
  
  /**
   * Setup Express server
   */
  private setupServer(): void {
    this.app = express();
    
    // Middleware
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));
    this.app.use(cookieParser());
    
    if (this.config.server?.cors) {
      this.app.use(cors(this.config.server.cors));
    }
    
    // Mount auth routes
    this.app.use('/auth', this.router());
    
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'ok' });
    });
  }
}
```

**Install dependencies:**
```bash
cd packages/core
pnpm add express cors cookie-parser
pnpm add -D @types/express @types/cors @types/cookie-parser
```

---

## 🎉 Testing Everything Together

Let's create a simple example to test everything!

**File: `examples/basic-express/index.ts`**

```typescript
import { CipherAuth } from '@cipher-auth/core';
import { MongooseAdapter } from '@cipher-auth/mongoose';
import { LocalStrategy } from '@cipher-auth/strategies';

// Create Cipher Auth instance
const auth = new CipherAuth({
  // MongoDB adapter
  adapter: new MongooseAdapter({
    uri: 'mongodb://localhost:27017/cipher-auth-test'
  }),
  
  // Session config
  session: {
    secret: 'your-secret-key-change-this',
    store: 'memory'  // Use 'redis' in production
  },
  
  // Standalone server
  server: {
    port: 3000,
    cors: {
      origin: 'http://localhost:5173'  // Your React app
    }
  }
});

// Register strategies
auth.use(new LocalStrategy({
  // Options
}));

// Start server
auth.listen();
```

**Run it:**
```bash
# Terminal 1 - Start MongoDB
mongod

# Terminal 2 - Start auth server
cd examples/basic-express
npx tsx index.ts
```

**Test with curl:**
```bash
# Signup
curl -X POST http://localhost:3000/auth/local \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","name":"Test User"}'

# Login
curl -X POST http://localhost:3000/auth/local \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  -c cookies.txt  # Save cookies

# Get current user
curl http://localhost:3000/auth/me \
  -b cookies.txt  # Use saved cookies

# Logout
curl -X POST http://localhost:3000/auth/logout \
  -b cookies.txt
```

---

## 📋 Summary: What We Built in Month 1

1. **Monorepo Setup** - All packages in one place
2. **Strategy Pattern** - Easy to add new auth methods
3. **Strategy Registry** - Manages all strategies
4. **Session Management** - Memory and Redis stores
5. **Security Primitives** - Password hashing, CSRF, rate limiting
6. **Database Adapters** - MongoDB (Mongoose) support
7. **CipherAuth Class** - Main API that ties everything together

**Next Up: Month 2**
- Local Strategy (email/password)
- OAuth Strategies (Google, GitHub)
- Client SDK (JavaScript/TypeScript)
- React Hooks

This is a solid foundation! Everything else builds on these concepts. 🚀

---

Want me to continue with Month 2 in the same detailed, beginner-friendly style?