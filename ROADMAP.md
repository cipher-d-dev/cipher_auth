# Cipher Auth - Detailed Implementation Plan

**Start Date**: [Your Start Date]  
**Target Launch**: Month 5  
**Team**: Cipher (Backend Lead) + Jamal (Frontend Lead)

---

## 📋 Month 1: Foundation & Core Backend

### Week 1: Project Setup (Both - 3-4 days)

#### Features to Implement:
- [ ] **Monorepo Setup**
  - **Owner**: Cipher
  - **Time**: 1 day
  - **Tech**: Turborepo + pnpm workspaces
  - **Tasks**:
    - Initialize monorepo structure
    - Setup shared TypeScript configs
    - Configure ESLint + Prettier
    - Setup Vitest for testing
    - Configure Changesets for versioning
  
- [ ] **Package Scaffolding**
  - **Owner**: Both (split packages)
  - **Time**: 1 day
  - **Packages**:
    - `@cipher-auth/core` (Cipher)
    - `@cipher-auth/client` (Jamal)
    - `@cipher-auth/react` (Jamal)
    - `@cipher-auth/mongoose` (Cipher)
    - `@cipher-auth/strategies` (Cipher)
  - **Tasks**:
    - Create package.json for each
    - Setup tsconfig.json
    - Create basic exports
    - Setup build scripts (tsup)

- [ ] **CI/CD Pipeline**
  - **Owner**: Cipher
  - **Time**: 1 day
  - **Tasks**:
    - GitHub Actions for tests
    - Automated type checking
    - Build verification
    - npm publish workflow (manual trigger)

---

### Week 1-2: Core Authentication SDK (Cipher - 5-7 days)

#### Feature 1: Strategy Pattern System
- **Owner**: Cipher
- **Time**: 2 days
- **Location**: `packages/core/src/strategies/`

**Files to Create**:
```
core/src/
├── strategies/
│   ├── Strategy.ts           # Base abstract class
│   ├── StrategyRegistry.ts   # Strategy registration
│   └── types.ts              # Strategy interfaces
```

**What to Build**:
```typescript
// Strategy.ts
export abstract class Strategy {
  abstract name: string;
  abstract authenticate(
    req: Request, 
    options?: any
  ): Promise<AuthResult>;
}

// StrategyRegistry.ts
export class StrategyRegistry {
  use(strategy: Strategy): void;
  get(name: string): Strategy | undefined;
  authenticate(name: string, req: Request): Promise<AuthResult>;
}
```

**Tests**:
- [ ] Strategy registration works
- [ ] Multiple strategies can coexist
- [ ] Unknown strategy throws error
- [ ] Authentication flow executes

---

#### Feature 2: Session Management
- **Owner**: Cipher
- **Time**: 3 days
- **Location**: `packages/core/src/session/`

**Files to Create**:
```
core/src/session/
├── SessionStore.ts           # Abstract store interface
├── MemoryStore.ts           # In-memory implementation
├── RedisStore.ts            # Redis implementation
├── SessionManager.ts        # Session CRUD operations
└── types.ts
```

**What to Build**:
```typescript
// SessionStore.ts
export interface SessionStore {
  get(sessionId: string): Promise<Session | null>;
  set(sessionId: string, session: Session): Promise<void>;
  destroy(sessionId: string): Promise<void>;
  touch(sessionId: string): Promise<void>;
}

// SessionManager.ts
export class SessionManager {
  constructor(store: SessionStore);
  create(userId: string, data?: any): Promise<Session>;
  validate(sessionId: string): Promise<Session | null>;
  refresh(sessionId: string): Promise<Session>;
  destroy(sessionId: string): Promise<void>;
}
```

**Dependencies**:
- `ioredis` for RedisStore
- `uid-safe` for session ID generation

**Tests**:
- [ ] Memory store works
- [ ] Redis store works
- [ ] Session creation/validation
- [ ] Session expiry
- [ ] Session refresh

---

#### Feature 3: Security Primitives
- **Owner**: Cipher
- **Time**: 2 days
- **Location**: `packages/core/src/security/`

**Files to Create**:
```
core/src/security/
├── password.ts              # Password hashing/verification
├── csrf.ts                  # CSRF token generation
├── ratelimit.ts             # Rate limiting
└── crypto.ts                # General crypto utilities
```

**What to Build**:
```typescript
// password.ts
export async function hashPassword(password: string): Promise<string>;
export async function verifyPassword(
  password: string, 
  hash: string
): Promise<boolean>;

// csrf.ts
export function generateCSRFToken(): string;
export function verifyCSRFToken(token: string, secret: string): boolean;

// ratelimit.ts
export class RateLimiter {
  constructor(options: { 
    windowMs: number; 
    max: number 
  });
  check(identifier: string): Promise<boolean>;
}
```

**Dependencies**:
- `argon2` for password hashing
- `crypto` (Node.js built-in)

**Tests**:
- [ ] Password hashing is secure
- [ ] Password verification works
- [ ] CSRF tokens are unique
- [ ] Rate limiting blocks after threshold

---

### Week 2: Database Adapters (Cipher - 3-4 days)

#### Feature 4: Database Adapter Interface
- **Owner**: Cipher
- **Time**: 1 day
- **Location**: `packages/core/src/adapters/`

**Files to Create**:
```
core/src/adapters/
├── Adapter.ts               # Abstract adapter interface
└── types.ts                 # User, Session models
```

**What to Build**:
```typescript
// Adapter.ts
export interface Adapter {
  // User operations
  createUser(data: CreateUserInput): Promise<User>;
  getUserById(id: string): Promise<User | null>;
  getUserByEmail(email: string): Promise<User | null>;
  updateUser(id: string, data: UpdateUserInput): Promise<User>;
  deleteUser(id: string): Promise<void>;
  
  // OAuth connections
  linkOAuthAccount(userId: string, provider: string, data: any): Promise<void>;
  getOAuthAccount(provider: string, providerId: string): Promise<User | null>;
  
  // Session (if not using separate store)
  createSession?(userId: string): Promise<Session>;
  getSession?(sessionId: string): Promise<Session | null>;
  deleteSession?(sessionId: string): Promise<void>;
}
```

---

#### Feature 5: Mongoose Adapter
- **Owner**: Cipher
- **Time**: 2 days
- **Location**: `packages/mongoose/`

**Files to Create**:
```
mongoose/src/
├── MongooseAdapter.ts       # Adapter implementation
├── models/
│   ├── User.ts             # User schema
│   ├── Session.ts          # Session schema
│   └── OAuthConnection.ts  # OAuth schema
└── index.ts
```

**What to Build**:
```typescript
// MongooseAdapter.ts
export class MongooseAdapter implements Adapter {
  constructor(options: { uri: string });
  
  async createUser(data: CreateUserInput): Promise<User> {
    const user = await UserModel.create(data);
    return user.toObject();
  }
  
  // Implement all Adapter methods...
}

// models/User.ts
const UserSchema = new Schema({
  email: { type: String, required: true, unique: true },
  emailVerified: { type: Boolean, default: false },
  passwordHash: String,
  name: String,
  image: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
```

**Dependencies**:
- `mongoose`

**Tests**:
- [ ] User CRUD operations
- [ ] OAuth account linking
- [ ] Email uniqueness constraint
- [ ] Connection handling

---

### Week 2-3: Framework Adapters (Cipher - 3-4 days)

#### Feature 6: Express Adapter
- **Owner**: Cipher
- **Time**: 2 days
- **Location**: `packages/core/src/adapters/express/`

**Files to Create**:
```
core/src/adapters/express/
├── ExpressAdapter.ts        # Express middleware
├── router.ts                # Auth routes factory
└── types.ts
```

**What to Build**:
```typescript
// ExpressAdapter.ts
export class ExpressAdapter {
  constructor(auth: CipherAuth);
  
  middleware(): express.RequestHandler {
    return async (req, res, next) => {
      // Attach auth to req
      req.auth = this.auth;
      // Handle session
      await this.loadSession(req);
      next();
    };
  }
  
  router(): express.Router {
    const router = express.Router();
    
    // Auto-generate routes based on strategies
    router.post('/signup', this.handleSignup);
    router.post('/login', this.handleLogin);
    router.post('/logout', this.handleLogout);
    router.get('/:provider', this.handleOAuth);
    router.get('/:provider/callback', this.handleOAuthCallback);
    
    return router;
  }
}
```

**Tests**:
- [ ] Middleware attaches auth to request
- [ ] Routes are generated correctly
- [ ] OAuth redirects work
- [ ] Error handling

---

#### Feature 7: CipherAuth Main Class
- **Owner**: Cipher
- **Time**: 2 days
- **Location**: `packages/core/src/CipherAuth.ts`

**What to Build**:
```typescript
export class CipherAuth {
  private strategies: StrategyRegistry;
  private sessionManager: SessionManager;
  private adapter: Adapter;
  private server?: express.Application;
  
  constructor(config: CipherAuthConfig) {
    this.adapter = config.adapter;
    this.sessionManager = new SessionManager(
      config.session.store === 'redis' 
        ? new RedisStore(config.session.redis)
        : new MemoryStore()
    );
    this.strategies = new StrategyRegistry();
    
    if (config.server) {
      this.setupServer(config.server);
    }
  }
  
  use(strategy: Strategy): void {
    this.strategies.use(strategy);
  }
  
  router(): express.Router {
    const adapter = new ExpressAdapter(this);
    return adapter.router();
  }
  
  listen(port?: number): void {
    if (!this.server) {
      throw new Error('Server not configured');
    }
    this.server.listen(port || this.config.server.port);
  }
  
  private setupServer(config: ServerConfig): void {
    this.server = express();
    this.server.use(express.json());
    this.server.use(cors(config.cors));
    this.server.use(this.router());
  }
}
```

**Tests**:
- [ ] Standalone server mode works
- [ ] Router mode works
- [ ] Strategy registration
- [ ] Config validation

---

## 📋 Month 2: Strategies & Client SDK

### Week 1-2: Authentication Strategies (Cipher - 7-10 days)

#### Feature 8: Local Strategy (Email/Password)
- **Owner**: Cipher
- **Time**: 3 days
- **Location**: `packages/strategies/src/local/`

**Files to Create**:
```
strategies/src/local/
├── LocalStrategy.ts
├── validators.ts            # Email/password validation
├── handlers.ts              # Signup/login logic
└── types.ts
```

**What to Build**:
```typescript
export class LocalStrategy extends Strategy {
  name = 'local';
  
  constructor(options?: LocalStrategyOptions) {
    super();
    this.options = {
      usernameField: 'email',
      passwordField: 'password',
      requireEmailVerification: true,
      passwordMinLength: 8,
      ...options
    };
  }
  
  async authenticate(req: Request): Promise<AuthResult> {
    const { email, password } = req.body;
    
    // Validate
    if (!this.validateEmail(email)) {
      throw new AuthError('Invalid email');
    }
    
    // Find user
    const user = await this.adapter.getUserByEmail(email);
    if (!user) {
      throw new AuthError('Invalid credentials');
    }
    
    // Verify password
    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      throw new AuthError('Invalid credentials');
    }
    
    return { user };
  }
  
  async signup(req: Request): Promise<User> {
    const { email, password, name } = req.body;
    
    // Validate
    this.validatePassword(password);
    
    // Check if exists
    const exists = await this.adapter.getUserByEmail(email);
    if (exists) {
      throw new AuthError('Email already registered');
    }
    
    // Hash password
    const passwordHash = await hashPassword(password);
    
    // Create user
    const user = await this.adapter.createUser({
      email,
      passwordHash,
      name,
      emailVerified: false
    });
    
    // Send verification email
    if (this.options.requireEmailVerification) {
      await this.sendVerificationEmail(user);
    }
    
    return user;
  }
}
```

**Additional Features**:
- [ ] Email verification flow
- [ ] Password reset flow (generate token, send email, verify token)
- [ ] Account lockout after N failed attempts
- [ ] Password strength validation

**Tests**:
- [ ] Signup creates user
- [ ] Login with valid credentials
- [ ] Login fails with invalid credentials
- [ ] Email verification works
- [ ] Password reset works
- [ ] Account lockout works

---

#### Feature 9: Magic Link Strategy
- **Owner**: Cipher
- **Time**: 2 days
- **Location**: `packages/strategies/src/magic-link/`

**What to Build**:
```typescript
export class MagicLinkStrategy extends Strategy {
  name = 'magic-link';
  
  async sendMagicLink(email: string): Promise<void> {
    // Generate one-time token
    const token = await this.generateToken(email);
    
    // Store token with expiry (e.g., 15 minutes)
    await this.tokenStore.set(token, { email, expiresAt: Date.now() + 900000 });
    
    // Send email with link
    const link = `${this.baseUrl}/auth/magic-link/verify?token=${token}`;
    await this.emailService.send({
      to: email,
      subject: 'Your login link',
      html: `<a href="${link}">Click here to login</a>`
    });
  }
  
  async authenticate(req: Request): Promise<AuthResult> {
    const { token } = req.query;
    
    // Verify token
    const data = await this.tokenStore.get(token);
    if (!data || data.expiresAt < Date.now()) {
      throw new AuthError('Invalid or expired token');
    }
    
    // Delete token (one-time use)
    await this.tokenStore.delete(token);
    
    // Get or create user
    let user = await this.adapter.getUserByEmail(data.email);
    if (!user) {
      user = await this.adapter.createUser({
        email: data.email,
        emailVerified: true
      });
    }
    
    return { user };
  }
}
```

**Tests**:
- [ ] Token generation
- [ ] Email sending
- [ ] Token verification
- [ ] Token expiry
- [ ] One-time use

---

#### Feature 10: OAuth 2.0 Base + Google/GitHub
- **Owner**: Cipher
- **Time**: 4 days
- **Location**: `packages/strategies/src/oauth/`

**Files to Create**:
```
strategies/src/oauth/
├── OAuth2Strategy.ts        # Generic OAuth 2.0
├── GoogleStrategy.ts
├── GitHubStrategy.ts
└── utils/
    ├── pkce.ts             # PKCE helpers
    └── state.ts            # State parameter
```

**What to Build**:
```typescript
export class OAuth2Strategy extends Strategy {
  constructor(options: OAuth2Options) {
    super();
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.authorizationURL = options.authorizationURL;
    this.tokenURL = options.tokenURL;
    this.callbackURL = options.callbackURL;
  }
  
  async getAuthorizationURL(req: Request): Promise<string> {
    // Generate PKCE challenge
    const { verifier, challenge } = generatePKCE();
    
    // Generate state
    const state = generateState();
    
    // Store for verification
    await this.stateStore.set(state, { verifier });
    
    // Build URL
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.callbackURL,
      response_type: 'code',
      scope: this.scope.join(' '),
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256'
    });
    
    return `${this.authorizationURL}?${params}`;
  }
  
  async authenticate(req: Request): Promise<AuthResult> {
    const { code, state } = req.query;
    
    // Verify state
    const stored = await this.stateStore.get(state);
    if (!stored) {
      throw new AuthError('Invalid state');
    }
    
    // Exchange code for token
    const tokens = await this.exchangeCode(code, stored.verifier);
    
    // Get user profile
    const profile = await this.getUserProfile(tokens.access_token);
    
    // Find or create user
    let user = await this.adapter.getOAuthAccount(this.name, profile.id);
    if (!user) {
      user = await this.adapter.createUser({
        email: profile.email,
        name: profile.name,
        image: profile.picture,
        emailVerified: profile.email_verified
      });
      
      await this.adapter.linkOAuthAccount(user.id, this.name, {
        providerId: profile.id,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token
      });
    }
    
    return { user };
  }
}

// GoogleStrategy.ts - extends OAuth2Strategy with Google-specific config
export class GoogleStrategy extends OAuth2Strategy {
  constructor(options: GoogleStrategyOptions) {
    super({
      ...options,
      authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenURL: 'https://oauth2.googleapis.com/token',
      scope: ['openid', 'email', 'profile']
    });
    this.name = 'google';
  }
  
  async getUserProfile(accessToken: string) {
    const res = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    return res.json();
  }
}
```

**Tests**:
- [ ] Authorization URL generation
- [ ] PKCE flow
- [ ] State verification
- [ ] Code exchange
- [ ] Profile fetching
- [ ] User creation/linking

---

### Week 2-4: Client SDK (Jamal - 10-12 days)

#### Feature 11: Framework-Agnostic Client
- **Owner**: Jamal
- **Time**: 4 days
- **Location**: `packages/client/src/`

**Files to Create**:
```
client/src/
├── CipherAuthClient.ts      # Main client class
├── TokenManager.ts          # JWT handling
├── SessionManager.ts        # Session state
├── types.ts
└── utils/
    ├── fetch.ts            # Fetch wrapper with auth
    └── storage.ts          # localStorage/cookies
```

**What to Build**:
```typescript
export class CipherAuthClient {
  private apiUrl: string;
  private tokenManager: TokenManager;
  private sessionManager: SessionManager;
  
  constructor(config: ClientConfig) {
    this.apiUrl = config.apiUrl;
    this.tokenManager = new TokenManager(config.storage);
    this.sessionManager = new SessionManager();
  }
  
  async signup(data: SignupInput): Promise<User> {
    const res = await this.fetch('/auth/signup', {
      method: 'POST',
      body: JSON.stringify(data)
    });
    
    if (res.token) {
      await this.tokenManager.setToken(res.token);
    }
    
    return res.user;
  }
  
  async login(credentials: LoginInput): Promise<User> {
    const res = await this.fetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials)
    });
    
    await this.tokenManager.setToken(res.token);
    this.sessionManager.setUser(res.user);
    
    return res.user;
  }
  
  async logout(): Promise<void> {
    await this.fetch('/auth/logout', { method: 'POST' });
    await this.tokenManager.clearToken();
    this.sessionManager.clearUser();
  }
  
  async getUser(): Promise<User | null> {
    // Check cache first
    if (this.sessionManager.user) {
      return this.sessionManager.user;
    }
    
    // Fetch from server
    const res = await this.fetch('/auth/me');
    this.sessionManager.setUser(res.user);
    return res.user;
  }
  
  async loginWithOAuth(provider: string): Promise<void> {
    // Open OAuth popup/redirect
    const url = `${this.apiUrl}/auth/${provider}`;
    window.location.href = url;
  }
  
  private async fetch(path: string, options?: RequestInit) {
    const token = await this.tokenManager.getToken();
    
    const res = await fetch(`${this.apiUrl}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options?.headers
      }
    });
    
    if (res.status === 401) {
      // Token expired, try refresh
      await this.refreshToken();
      return this.fetch(path, options);
    }
    
    return res.json();
  }
  
  private async refreshToken(): Promise<void> {
    const res = await fetch(`${this.apiUrl}/auth/refresh`, {
      method: 'POST',
      credentials: 'include'
    });
    
    const { token } = await res.json();
    await this.tokenManager.setToken(token);
  }
}

// TokenManager.ts
export class TokenManager {
  private storage: Storage;
  private tokenKey = 'cipher_auth_token';
  
  async setToken(token: string): Promise<void> {
    this.storage.setItem(this.tokenKey, token);
  }
  
  async getToken(): Promise<string | null> {
    return this.storage.getItem(this.tokenKey);
  }
  
  async clearToken(): Promise<void> {
    this.storage.removeItem(this.tokenKey);
  }
}
```

**Tests**:
- [ ] Login flow
- [ ] Token storage
- [ ] Token refresh
- [ ] Logout
- [ ] OAuth redirect

---

#### Feature 12: React Hooks & Context
- **Owner**: Jamal
- **Time**: 3 days
- **Location**: `packages/react/src/hooks/`

**Files to Create**:
```
react/src/
├── AuthProvider.tsx
├── hooks/
│   ├── useAuth.ts
│   ├── useUser.ts
│   ├── useSession.ts
│   └── useOAuth.ts
└── types.ts
```

**What to Build**:
```typescript
// AuthProvider.tsx
export function AuthProvider({ 
  children, 
  apiUrl 
}: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const client = useMemo(() => new CipherAuthClient({ apiUrl }), [apiUrl]);
  
  useEffect(() => {
    // Load user on mount
    client.getUser()
      .then(setUser)
      .finally(() => setLoading(false));
  }, [client]);
  
  const login = useCallback(async (credentials: LoginInput) => {
    const user = await client.login(credentials);
    setUser(user);
    return user;
  }, [client]);
  
  const logout = useCallback(async () => {
    await client.logout();
    setUser(null);
  }, [client]);
  
  const signup = useCallback(async (data: SignupInput) => {
    const user = await client.signup(data);
    setUser(user);
    return user;
  }, [client]);
  
  return (
    <AuthContext.Provider value={{ 
      user, 
      loading, 
      login, 
      logout, 
      signup,
      client 
    }}>
      {children}
    </AuthContext.Provider>
  );
}

// hooks/useAuth.ts
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}

// hooks/useUser.ts
export function useUser() {
  const { user, loading } = useAuth();
  return { user, loading };
}

// hooks/useOAuth.ts
export function useOAuth(provider: string) {
  const { client } = useAuth();
  
  const login = useCallback(() => {
    client.loginWithOAuth(provider);
  }, [client, provider]);
  
  return { login };
}
```

**Tests**:
- [ ] Provider renders
- [ ] Hooks return correct data
- [ ] Login updates user state
- [ ] Logout clears user state
- [ ] Loading states

---

#### Feature 13: Basic UI Components
- **Owner**: Jamal
- **Time**: 4 days
- **Location**: `packages/react/src/components/`

**Files to Create**:
```
react/src/components/
├── SignInForm.tsx
├── SignUpForm.tsx
├── ForgotPasswordForm.tsx
├── OAuthButton.tsx
└── styles/
    └── default.css
```

**What to Build**:
```typescript
// SignInForm.tsx
export function SignInForm({
  providers = [],
  onSuccess,
  onError,
  className
}: SignInFormProps) {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      const user = await login({ email, password });
      onSuccess?.(user);
    } catch (err) {
      setError(err.message);
      onError?.(err);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className={cn('cipher-signin-form', className)}>
      <form onSubmit={handleSubmit}>
        <Input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Email"
          required
        />
        <Input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
          required
        />
        {error && <ErrorMessage>{error}</ErrorMessage>}
        <Button type="submit" loading={loading}>
          Sign In
        </Button>
      </form>
      
      {providers.length > 0 && (
        <>
          <Divider>or</Divider>
          {providers.map(provider => (
            <OAuthButton key={provider} provider={provider} />
          ))}
        </>
      )}
    </div>
  );
}

// OAuthButton.tsx
export function OAuthButton({ provider }: { provider: string }) {
  const { login } = useOAuth(provider);
  
  return (
    <Button
      variant="outline"
      onClick={login}
      icon={<ProviderIcon provider={provider} />}
    >
      Continue with {capitalize(provider)}
    </Button>
  );
}
```

**Components to Build**:
- [ ] SignInForm
- [ ] SignUpForm
- [ ] ForgotPasswordForm
- [ ] OAuthButton
- [ ] Input (styled)
- [ ] Button (styled)
- [ ] ErrorMessage
- [ ] Divider

**Tests**:
- [ ] Form submission
- [ ] Validation
- [ ] Error states
- [ ] OAuth buttons work

---

## 📋 Month 3: Advanced UI & Polish (Jamal lead)

### Week 1-2: Complete UI Component Library
- **Owner**: Jamal
- **Time**: 7 days

#### Feature 14: Remaining Components
```
react/src/components/
├── ProfileSettings.tsx      # Edit profile
├── PasswordChange.tsx       # Change password
├── EmailVerification.tsx    # Verify email UI
├── PasswordReset.tsx        # Reset password
├── SessionManager.tsx       # Active sessions list
└── ProtectedRoute.tsx       # Route guard
```

**Tests for each component**

---

#### Feature 15: Theming System
- **Owner**: Jamal
- **Time**: 3 days

**Files**:
```
react/src/
├── theme/
│   ├── ThemeProvider.tsx
│   ├── themes/
│   │   ├── default.ts
│   │   ├── dark.ts
│   │   └── custom.ts
│   └── useTheme.ts
└── styles/
    ├── variables.css         # CSS variables
    └── tailwind.css         # Tailwind utilities
```

**Tests**:
- [ ] Theme switching
- [ ] CSS variable application
- [ ] Dark mode

---

### Week 2-3: Example Apps (Both)
- **Owner**: Both (split apps)
- **Time**: 5 days

#### Create 2 Example Apps:
1. **Next.js + MongoDB** (Cipher)
2. **Express + React + MongoDB** (Jamal)

Each should have:
- [ ] Full auth flow
- [ ] Protected routes
- [ ] Profile management
- [ ] OAuth login

---

## 📋 Month 4: Advanced Features

### Week 1-2: Multi-Factor Authentication (Cipher - 7 days)

#### Feature 16: TOTP (Time-based OTP)
- **Owner**: Cipher
- **Time**: 3 days
- **Location**: `packages/strategies/src/mfa/totp/`

**What to Build**:
```typescript
export class TOTPStrategy {
  async setup(userId: string): Promise<TOTPSetup> {
    const secret = generateSecret();
    
    // Save secret
    await this.adapter.saveMFASecret(userId, 'totp', secret);
    
    // Generate QR code
    const qrCode = await generateQRCode(secret);
    
    // Generate backup codes
    const backupCodes = generateBackupCodes(10);
    await this.adapter.saveBackupCodes(userId, backupCodes);
    
    return { secret, qrCode, backupCodes };
  }
  
  async verify(userId: string, token: string): Promise<boolean> {
    const secret = await this.adapter.getMFASecret(userId, 'totp');
    return verifyTOTP(secret, token);
  }
}
```

**Dependencies**: `otplib`, `qrcode`

---

#### Feature 17: SMS OTP
- **Owner**: Cipher
- **Time**: 2 days

**Integration with Twilio**

---

#### Feature 18: MFA UI Components
- **Owner**: Jamal
- **Time**: 2 days

Components:
- [ ] TOTPSetup
- [ ] TOTPVerify
- [ ] BackupCodes
- [ ] SMSVerify

---

### Week 2-3: RBAC & Organizations (Jamal - 7 days)

#### Feature 19: RBAC System
- **Owner**: Jamal
- **Time**: 4 days

**Database Models**:
```typescript
// Role
{
  id, name, permissions: string[]
}

// UserRole
{
  userId, roleId, organizationId?
}

// Permission check middleware
```

---

#### Feature 20: Organizations/Teams
- **Owner**: Jamal
- **Time**: 3 days

**Models**:
```typescript
// Organization
{
  id, name, slug, ownerId
}

// OrganizationMember
{
  organizationId, userId, role
}

// Invitation
{
  organizationId, email, role, token, expiresAt
}
```

---

### Week 3-4: Security Hardening (Both)

#### Feature 21: Advanced Security
- **Owner**: Cipher
- **Time**: 3 days

- [ ] Device tracking
- [ ] Concurrent session limits
- [ ] Suspicious login detection
- [ ] Bot protection (hCaptcha)

---

#### Feature 22: Security Audit & Testing
- **Owner**: Both
- **Time**: 4 days

- [ ] Penetration testing
- [ ] OWASP Top 10 check
- [ ] Dependency audit
- [ ] Security headers
- [ ] Rate limiting refinement

---

## 📋 Month 5: Documentation & Launch

### Week 1-2: Documentation (Both - split topics)

#### Cipher:
- [ ] Backend setup guides
- [ ] Strategy documentation
- [ ] Database adapter guides
- [ ] Security best practices
- [ ] API reference

#### Jamal:
- [ ] Frontend setup guides
- [ ] Component documentation
- [ ] Theming guide
- [ ] Hook references
- [ ] Integration examples

---

### Week 2-3: CLI Tool (Cipher - 5 days)

```bash
cipher-auth init
cipher-auth add-strategy google
cipher-auth generate migration
```

---

### Week 3-4: Final Polish & Launch

- [ ] Performance optimization
- [ ] Bundle size optimization
- [ ] Final bug fixes
- [ ] npm publishing
- [ ] Launch marketing

---

## 📊 Quick Reference: Who Does What

### Cipher (Backend Lead)
- ✅ Core SDK architecture
- ✅ Strategy implementations
- ✅ Database adapters
- ✅ Security primitives
- ✅ Framework integrations
- ✅ MFA backend
- ✅ CLI tool
- ✅ Backend docs

### Jamal (Frontend Lead)
- ✅ Client SDK
- ✅ React components
- ✅ Theming system
- ✅ UI/UX design
- ✅ RBAC system
- ✅ Organizations
- ✅ Frontend docs
- ✅ Example apps (frontend)

### Shared
- ✅ Testing
- ✅ Code reviews
- ✅ Security audit
- ✅ Example apps
- ✅ Launch prep

---

## 🎯 Next Steps for Cipher

1. **Day 1**: Setup monorepo
2. **Day 2-3**: Build Strategy pattern
3. **Day 4-6**: Build Session management
4. **Day 7-8**: Build Security primitives
5. **Week 2**: Database adapters
6. **Week 2-3**: Express adapter & CipherAuth class
7. **Week 3-4+**: Start on strategies

---

## 🎯 Next Steps for Jamal

1. **Day 1**: Setup client package
2. **Day 2**: Wait for Cipher's core to be ready
3. **Week 2-3**: Build Client SDK
4. **Week 3-4**: Build React hooks
5. **Week 4+**: Build UI components

---

**Let's build this! 🚀**