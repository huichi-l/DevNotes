# 1. How JWT Authentication Works:

JWT (JSON Web Token) is a compact, URL-safe means of representing claims to be transferred between two parties. The claims in a JWT are encoded as a JSON object that is digitally signed using JSON Web Signature (JWS).

A typical JWT authentication flow:

a) User logs in with credentials (username/password).
b) Server verifies credentials and generates a JWT.
c) Server sends the JWT back to the client.
d) Client stores the JWT (typically in local storage or a cookie).
e) For subsequent requests, the client includes the JWT in the Authorization header.
f) Server validates the JWT for each request and grants access if valid.

# 2. Problems JWT Solves:

- Statelessness: Unlike session-based authentication, JWT doesn't require server-side storage of session information.
- Scalability: It's easier to scale applications as authentication can be handled by any server with the correct signing key.
- Cross-domain / CORS: Tokens can be used across multiple domains easily.
- Mobile-friendly: Works well for native mobile apps where cookie-based auth can be problematic.
- Decoupled / Microservices: Allows for decoupled authentication in microservices architectures.

# 3. Implementing JWT Authentication:

Here's a basic implementation using Node.js and Express:

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

const SECRET_KEY = 'your-secret-key';

app.use(express.json());

// Login route
app.post('/login', (req, res) => {
  // Verify user credentials (simplified)
  const { username, password } = req.body;
  if (username === 'admin' && password === 'password') {
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Authentication failed' });
  }
});

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Access granted to protected route' });
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.listen(3000, () => console.log('Server running on port 3000'));
```

# 4. Securing JWT Implementation:

a) Use strong secret keys: Use a strong, unique secret key for signing tokens.

b) Set appropriate expiration times: Short-lived tokens reduce the window of opportunity for attackers.

c) Use HTTPS: Always use HTTPS to prevent token interception.

d) Validate all inputs: Sanitize and validate all user inputs to prevent injection attacks.

e) Implement token revocation: Have a mechanism to invalidate tokens if needed (e.g., user logout or compromise).

f) Use appropriate token storage: Store tokens securely on the client-side (httpOnly cookies for web apps).

g) Implement refresh tokens: Use refresh tokens to obtain new access tokens without re-authentication.

h) Protect against XSS: Implement Content Security Policy and sanitize user inputs to prevent XSS attacks.

i) Use appropriate algorithms: Use strong algorithms like RS256 for token signing.

j) Validate token payload: Always validate the token's claims (issuer, audience, expiration) on the server.

k) Keep secrets safe: Never expose your secret key. Use environment variables or secure vaults.

l) Implement rate limiting: Prevent brute-force attacks on your authentication endpoints.

m) Use JWT best practices: Follow established JWT best practices and security recommendations.

Example of a more secure implementation:

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const app = express();

app.use(express.json());
app.use(helmet()); // Adds various HTTP headers for security

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

const SECRET_KEY = process.env.JWT_SECRET_KEY; // Store secret key in environment variable
const REFRESH_SECRET_KEY = process.env.JWT_REFRESH_SECRET_KEY;

// Login route
app.post('/login', (req, res) => {
  // Verify user credentials (simplified)
  const { username, password } = req.body;
  if (username === 'admin' && password === 'password') {
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ username }, REFRESH_SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, refreshToken });
  } else {
    res.status(401).json({ message: 'Authentication failed' });
  }
});

// Refresh token route
app.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.sendStatus(401);

  jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    const newToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '15m' });
    res.json({ token: newToken });
  });
});

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Access granted to protected route', user: req.user });
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

This implementation includes several additional security measures:

1. Using `helmet` to set various HTTP headers for security.
2. Implementing rate limiting to prevent brute-force attacks.
3. Storing secret keys in environment variables.
4. Using short-lived access tokens (15 minutes) and longer-lived refresh tokens (7 days).
5. Implementing a refresh token mechanism.
6. Adding basic error handling middleware.

Additional Security Considerations:

1. Token Storage: For web applications, store the access token in memory and the refresh token in an HttpOnly, secure cookie.

2. Token Revocation: Implement a token blacklist or a Redis cache to store revoked tokens.

3. CORS: If your API and frontend are on different domains, properly configure CORS:

```javascript
const cors = require('cors');
app.use(cors({
  origin: 'https://yourtrustedwebsite.com',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

4. Payload Security: Minimize sensitive data in the JWT payload. Remember, while the token is signed, its contents are base64 encoded and can be easily decoded.

5. Use Strong Algorithms: Consider using asymmetric algorithms like RS256 for token signing:

```javascript
const fs = require('fs');
const privateKey = fs.readFileSync('private.key');
const publicKey = fs.readFileSync('public.key');

// When signing the token
const token = jwt.sign({ username }, privateKey, { 
  algorithm: 'RS256',
  expiresIn: '15m'
});

// When verifying the token
jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err, decoded) => {
  // Handle verification
});
```

6. Implement Logout: Although JWTs are stateless, you can implement a logout mechanism:

```javascript
const tokenBlacklist = new Set();

app.post('/logout', authenticateToken, (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  tokenBlacklist.add(token);
  res.json({ message: 'Logged out successfully' });
});

// Update the authenticateToken middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);
  if (tokenBlacklist.has(token)) return res.sendStatus(403);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}
```

7. Implement Token Rotation: Regularly rotate your signing keys to limit the impact of a compromised key.

8. Validate Token Claims: Always validate the token's claims on the server side:

```javascript
function validateToken(token) {
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const currentTime = Math.floor(Date.now() / 1000);

    if (decoded.exp <= currentTime) {
      throw new Error('Token has expired');
    }

    if (decoded.iss !== 'your-trusted-issuer') {
      throw new Error('Invalid token issuer');
    }

    if (decoded.aud !== 'your-api-audience') {
      throw new Error('Invalid token audience');
    }

    return decoded;
  } catch (error) {
    console.error('Token validation failed:', error.message);
    return null;
  }
}
```

9. Implement Multi-Factor Authentication (MFA): For enhanced security, implement MFA in addition to JWT:

```javascript
app.post('/login', async (req, res) => {
  const { username, password, mfaCode } = req.body;
  
  // Verify username and password
  const user = await verifyCredentials(username, password);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Verify MFA code
  if (!verifyMFACode(user, mfaCode)) {
    return res.status(401).json({ message: 'Invalid MFA code' });
  }

  // If both checks pass, generate and send tokens
  const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ username: user.username }, REFRESH_SECRET_KEY, { expiresIn: '7d' });
  
  res.json({ token, refreshToken });
});
```

10. Use Secure Cookies for Refresh Tokens:

```javascript
app.use(require('cookie-parser')());

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ username }, REFRESH_SECRET_KEY, { expiresIn: '7d' });
  
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days in milliseconds
  });

  res.json({ token });
});

// Refresh token route using secure cookie
app.post('/refresh', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.sendStatus(401);

  jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    const newToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '15m' });
    res.json({ token: newToken });
  });
});
```

11. Implement Token Scopes: Use scopes to limit the permissions of a token:

```javascript
app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    { 
      username, 
      scope: ['read:profile', 'write:profile']
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

// Middleware to check token scope
function checkScope(requiredScope) {
  return function(req, res, next) {
    const { scope } = req.user;
    if (scope && scope.includes(requiredScope)) {
      next();
    } else {
      res.status(403).json({ message: 'Insufficient scope' });
    }
  }
}

// Usage
app.get('/profile', authenticateToken, checkScope('read:profile'), (req, res) => {
  // Handle request
});
```

12. Implement API Versioning: This allows you to make changes to your authentication system without breaking existing clients:

```javascript
const apiV1 = express.Router();
app.use('/api/v1', apiV1);

apiV1.post('/login', (req, res) => {
  // V1 login logic
});

const apiV2 = express.Router();
app.use('/api/v2', apiV2);

apiV2.post('/login', (req, res) => {
  // V2 login logic (maybe using a different token format or algorithm)
});
```

13. Use a Separate Service for Authentication: In larger applications, consider moving authentication to a separate microservice:

```javascript
// Auth Service
const authService = express();

authService.post('/login', (req, res) => {
  // Handle login and token generation
});

authService.post('/verify', (req, res) => {
  // Verify token and return user info
});

// Main API Service
const apiService = express();

apiService.use(async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const response = await axios.post('http://auth-service/verify', { token });
    req.user = response.data.user;
    next();
  } catch (error) {
    res.sendStatus(403);
  }
});
```

14. Implement Proper Logging: Log authentication events, but be careful not to log sensitive information:

```javascript
const winston = require('winston');
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'auth.log' })
  ]
});

app.post('/login', (req, res) => {
  // ... authentication logic ...

  logger.info('User logged in', { 
    username: req.body.username,
    timestamp: new Date().toISOString(),
    ip: req.ip
  });

  // ... generate and send token ...
});
```

15. Regular Security Audits: Regularly review and update your authentication system. Consider using automated tools and manual code reviews to identify potential vulnerabilities.

16. Education and Documentation: Ensure that all developers working on the project understand JWT best practices and security considerations. Maintain comprehensive documentation on your authentication system.

```markdown
# JWT Authentication Guide

## Overview
This document outlines our JWT authentication implementation and best practices.

## Token Structure
- Header: Algorithm and token type
- Payload: Claims (avoid sensitive data)
- Signature: Ensures token integrity

## Security Measures
- Use HTTPS for all communications
- Store tokens securely (HttpOnly cookies for refresh tokens)
- Implement token expiration and rotation
- Use strong, asymmetric algorithms (e.g., RS256)
- Validate all token claims on the server

## API Endpoints
- POST /login: Authenticate and receive tokens
- POST /refresh: Get a new access token using a refresh token
- POST /logout: Invalidate current tokens

## Usage in Requests
Include the access token in the Authorization header:
Authorization: Bearer <access_token>

## Error Handling
- 401: Unauthorized (missing or invalid token)
- 403: Forbidden (insufficient permissions)
```

17. Implement Proper Error Handling: Provide meaningful error messages without revealing sensitive information:

```javascript
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ message: 'Invalid token' });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ message: 'Token expired' });
  }
  
  res.status(500).json({ message: 'An unexpected error occurred' });
});
```

18. Use Environment-Specific Configurations: Adjust settings based on the environment (development, staging, production):

```javascript
const config = {
  development: {
    tokenExpiration: '1h',
    refreshTokenExpiration: '1d',
  },
  production: {
    tokenExpiration: '15m',
    refreshTokenExpiration: '7d',
  }
};

const env = process.env.NODE_ENV || 'development';
const { tokenExpiration, refreshTokenExpiration } = config[env];

// Use these values when creating tokens
const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: tokenExpiration });
```

19. Implement Token Introspection: For scenarios where you need to check token validity without decoding:

```javascript
app.post('/introspect', (req, res) => {
  const { token } = req.body;
  
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    res.json({
      active: true,
      exp: decoded.exp,
      username: decoded.username,
      // other non-sensitive claims
    });
  } catch (error) {
    res.json({ active: false });
  }
});
```

20. Consider Using a JWT Library: For complex implementations, consider using a comprehensive JWT library like `jsonwebtoken` or `node-jose` which handle many security concerns out of the box.

21. Implement Graceful Token Renewal: To prevent disruption of user experience, implement a mechanism to silently refresh tokens before they expire:

```javascript
// Client-side example (using axios)
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      const newToken = await refreshToken();
      axios.defaults.headers.common['Authorization'] = 'Bearer ' + newToken;
      return axios(originalRequest);
    }
    return Promise.reject(error);
  }
);
```

22. Protect Against Token Sidejacking: Use techniques like token binding to tie tokens to a specific client:

```javascript
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const clientId = req.headers['x-client-id']; // Unique identifier for the client

  // ... verify credentials ...

  const token = jwt.sign({ 
    username, 
    clientId 
  }, SECRET_KEY, { 
    expiresIn: '15m' 
  });

  res.json({ token });
});

// In the authentication middleware
function authenticateToken(req, res, next) {
  // ... existing token verification ...

  if (decoded.clientId !== req.headers['x-client-id']) {
    return res.status(403).json({ message: 'Token not bound to this client' });
  }

  next();
}
```

23. Implement Token Revocation Lists: For scenarios where you need to invalidate tokens before they expire:

```javascript
const redis = require('redis');
const client = redis.createClient();

// When logging out or revoking a token
app.post('/logout', authenticateToken, (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  client.sadd('revoked_tokens', token);
  res.json({ message: 'Logged out successfully' });
});

// Update authentication middleware
function authenticateToken(req, res, next) {
  const token = req.headers.authorization.split(' ')[1];

  client.sismember('revoked_tokens', token, (err, reply) => {
    if (reply === 1) {
      return res.status(401).json({ message: 'Token has been revoked' });
    }

    // Proceed with normal token verification
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
      // ... existing verification logic ...
    });
  });
}
```

24. Implement Rate Limiting on Token Generation: Prevent abuse of token generation endpoints:

```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login requests per windowMs
  message: 'Too many login attempts, please try again later'
});

app.post('/login', loginLimiter, (req, res) => {
  // Login logic
});
```

25. Use Separate Keys for Different Purposes: Use different keys for access tokens and refresh tokens:

```javascript
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

app.post('/login', (req, res) => {
  // ... authentication logic ...

  const accessToken = jwt.sign({ username }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ username }, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

  res.json({ accessToken, refreshToken });
});
```

26. Implement Token Rotation for Refresh Tokens: Enhance security by issuing a new refresh token with each use:

```javascript
app.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;

  jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    const newAccessToken = jwt.sign({ username: user.username }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    const newRefreshToken = jwt.sign({ username: user.username }, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

    // Invalidate old refresh token
    // This could involve adding it to a blacklist or removing it from a whitelist

    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  });
});
```

27. Implement Concurrent Login Management: Allow users to manage their active sessions:

```javascript
const activeSessions = new Map();

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // ... authentication logic ...

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '15m' });
  
  // Store session info
  if (!activeSessions.has(username)) {
    activeSessions.set(username, []);
  }
  activeSessions.get(username).push({
    token,
    device: req.headers['user-agent'],
    loginTime: new Date()
  });

  res.json({ token });
});

app.get('/active-sessions', authenticateToken, (req, res) => {
  const { username } = req.user;
  const sessions = activeSessions.get(username) || [];
  res.json(sessions.map(s => ({ device: s.device, loginTime: s.loginTime })));
});

app.post('/logout-all-sessions', authenticateToken, (req, res) => {
  const { username } = req.user;
  activeSessions.delete(username);
  res.json({ message: 'All sessions logged out' });
});
```

28. Implement JWT Claim Checks: Add custom claims to your tokens and verify them:

```javascript
app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign({
    username,
    role: user.role,
    permissions: user.permissions
  }, SECRET_KEY, { expiresIn: '15m' });

  res.json({ token });
});

function checkPermission(requiredPermission) {
  return (req, res, next) => {
    const { permissions } = req.user;
    if (permissions.includes(requiredPermission)) {
      next();
    } else {
      res.status(403).json({ message: 'Insufficient permissions' });
    }
  };
}

app.get('/admin-dashboard', authenticateToken, checkPermission('access_admin'), (req, res) => {
  res.json({ message: 'Welcome to admin dashboard' });
});
```

29. Implement Token Encryption: For additional security, you can encrypt the payload of your JWT:

```javascript
const jose = require('node-jose');

async function createEncryptedToken(payload) {
  const key = await jose.JWK.asKey(fs.readFileSync('public_key.pem'));
  
  const token = await jose.JWE.createEncrypt({ format: 'compact' }, key)
    .update(JSON.stringify(payload))
    .final();

  return token;
}

async function decryptToken(token) {
  const key = await jose.JWK.asKey(fs.readFileSync('private_key.pem'));
  
  const decrypted = await jose.JWE.createDecrypt(key).decrypt(token);
  
  return JSON.parse(decrypted.plaintext.toString());
}

app.post('/login', async (req, res) => {
  // ... authentication logic ...
  
  const payload = { username, exp: Math.floor(Date.now() / 1000) + (15 * 60) };
  const token = await createEncryptedToken(payload);

  res.json({ token });
});

app.use(async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const payload = await decryptToken(token);
    if (payload.exp <= Math.floor(Date.now() / 1000)) {
      return res.sendStatus(401);
    }
    req.user = payload;
    next();
  } catch (error) {
    res.sendStatus(403);
  }
});
```

30. Implement Federated Authentication: Allow users to authenticate using external providers:

```javascript
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "http://www.yourdomain.com/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    // Here you would find or create a user in your database
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/auth/google',
  passport.authenticate('Google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('Google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, create JWT
    const token = jwt.sign({ userId: req.user.id }, SECRET_KEY, { expiresIn: '15m' });
    res.json({ token });
  });
```

31. Implement Multi-Factor Authentication (MFA) with JWT:

```javascript
const speakeasy = require('speakeasy');

app.post('/login', async (req, res) => {
  const { username, password, mfaToken } = req.body;

  // Verify username and password
  const user = await verifyCredentials(username, password);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Verify MFA token
  const verified = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token: mfaToken
  });

  if (!verified) {
    return res.status(401).json({ message: 'Invalid MFA token' });
  }

  // If both checks pass, generate and send JWT
  const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '15m' });
  res.json({ token });
});
```

32. Implement Token Audience Validation:

```javascript
app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    { 
      userId: user.id,
      aud: 'https://api.yourdomain.com'
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, { audience: 'https://api.yourdomain.com' }, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}
```

33. Implement Token Fingerprinting:

```javascript
function generateTokenFingerprint(req) {
  const userAgent = req.headers['user-agent'];
  const ip = req.ip;
  return crypto.createHash('sha256').update(`${userAgent}${ip}`).digest('hex');
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const fingerprint = generateTokenFingerprint(req);
  const token = jwt.sign(
    { 
      userId: user.id,
      fingerprint
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  // ... existing token verification ...
  
  const currentFingerprint = generateTokenFingerprint(req);
  if (decoded.fingerprint !== currentFingerprint) {
    return res.status(403).json({ message: 'Token fingerprint mismatch' });
  }

  next();
}
```

34. Implement Token Binding to TLS:

This is a more advanced technique that binds the token to the TLS session, making it harder for tokens to be stolen and reused.

```javascript
const crypto = require('crypto');

function getTlsUnique(req) {
  // This is a simplified example. In practice, you'd need to access the TLS finished message,
  // which might require custom Node.js bindings or a specialized proxy.
  return req.connection.getPeerCertificate().raw.toString('base64');
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const tlsUnique = getTlsUnique(req);
  const token = jwt.sign(
    { 
      userId: user.id,
      tlsUnique
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  // ... existing token verification ...
  
  const currentTlsUnique = getTlsUnique(req);
  if (decoded.tlsUnique !== currentTlsUnique) {
    return res.status(403).json({ message: 'Token not bound to this TLS session' });
  }

  next();
}
```

35. Implement Dynamic Secret Keys:

Regularly rotating secret keys can enhance security. Here's a simplified example:

```javascript
const crypto = require('crypto');
let currentSecret = crypto.randomBytes(64).toString('hex');
const oldSecrets = new Set();

// Rotate secret every hour
setInterval(() => {
  oldSecrets.add(currentSecret);
  currentSecret = crypto.randomBytes(64).toString('hex');
  // Keep only the last 24 old secrets (1 day worth)
  if (oldSecrets.size > 24) {
    oldSecrets.delete(oldSecrets.values().next().value);
  }
}, 60 * 60 * 1000);

function sign(payload) {
  return jwt.sign(payload, currentSecret, { expiresIn: '15m' });
}

function verify(token) {
  try {
    return jwt.verify(token, currentSecret);
  } catch (error) {
    // If verification fails with current secret, try old secrets
    for (let secret of oldSecrets) {
      try {
        return jwt.verify(token, secret);
      } catch (error) {
        continue;
      }
    }
    throw new Error('Invalid token');
  }
}
```

36. Implement Stateful JWT (with Redis):

While JWTs are typically stateless, there might be scenarios where you want to maintain some state, like for logout functionality:

```javascript
const redis = require('redis');
const client = redis.createClient();

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const jti = uuid.v4(); // Generate a unique identifier for the token
  const token = jwt.sign(
    { 
      userId: user.id,
      jti
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  // Store the jti in Redis
  client.set(jti, 'valid', 'EX', 15 * 60);

  res.json({ token });
});

app.post('/logout', authenticateToken, (req, res) => {
  const { jti } = req.user;
  client.del(jti);
  res.json({ message: 'Logged out successfully' });
});

function authenticateToken(req, res, next) {
  // ... existing token verification ...

  client.get(decoded.jti, (err, reply) => {
    if (err || reply !== 'valid') {
      return res.status(401).json({ message: 'Invalid or logged out token' });
    }
    req.user = decoded;
    next();
  });
}
```

37. Implement Token Versioning:

This allows you to invalidate all tokens if a security breach occurs:

```javascript
let TOKEN_VERSION = 1;

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    { 
      userId: user.id,
      tokenVersion: TOKEN_VERSION
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  // ... existing token verification ...

  if (decoded.tokenVersion !== TOKEN_VERSION) {
    return res.status(401).json({ message: 'Token version is outdated. Please re-authenticate.' });
  }

  next();
}

// In case of a security breach:
app.post('/admin/invalidate-all-tokens', (req, res) => {
  TOKEN_VERSION++;
  res.json({ message: 'All tokens have been invalidated' });
});
```

38. Implement Sliding Session Expiration:

This technique extends the token's expiration time with each request:

```javascript
function authenticateToken(req, res, next) {
  // ... existing token verification ...

  const newExp = Math.floor(Date.now() / 1000) + (15 * 60); // 15 minutes from now
  if (newExp > decoded.exp) {
    const newToken = jwt.sign(
      { ...decoded, exp: newExp },
      SECRET_KEY
    );
    res.setHeader('X-New-Token', newToken);
  }

  next();
}
```

39. Implement Token Usage Tracking:

This can help detect potential token theft:

```javascript
const redis = require('redis');
const client = redis.createClient();

function authenticateToken(req, res, next) {
  // ... existing token verification ...

  const key = `token_usage:${decoded.jti}`;
  client.incr(key, (err, count) => {
    if (err) {
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (count === 1) {
      // Set expiration for the key
      client.expire(key, 15 * 60); // 15 minutes
    } else if (count > 100) { // Arbitrary threshold
      return res.status(401).json({ message: 'Suspicious token usage detected. Please re-authenticate.' });
    }

    next();
  });
}
```

40. Implement Token Permissions with Bitfields:

For more efficient permission checking:

```javascript
const Permissions = {
  READ: 1,      // 0001
  WRITE: 2,     // 0010
  DELETE: 4,    // 0100
  ADMIN: 8      // 1000
};

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const userPermissions = user.permissions; // e.g., 7 for READ, WRITE, DELETE

  const token = jwt.sign(
    { 
      userId: user.id,
      permissions: userPermissions
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function checkPermission(requiredPermission) {
  return (req, res, next) => {
    if (req.user.permissions & requiredPermission) {
      next();
    } else {
      res.status(403).json({ message: 'Insufficient permissions' });
    }
  };
}

app.delete('/resource/:id', authenticateToken, checkPermission(Permissions.DELETE), (req, res) => {
  // Delete the resource
});
```

41. Implement Token Encryption with JWE (JSON Web Encryption):

For scenarios where you need to encrypt the entire token:

```javascript
const jose = require('node-jose');

async function createEncryptedToken(payload) {
  const key = await jose.JWK.asKey(fs.readFileSync('public_key.pem'));
  
  const token = await jose.JWE.createEncrypt({ format: 'compact' }, key)
    .update(JSON.stringify(payload))
    .final();

  return token;
}

async function decryptToken(token) {
  const key = await jose.JWK.asKey(fs.readFileSync('private_key.pem'));
  
  const decrypted = await jose.JWE.createDecrypt(key).decrypt(token);
  
  return JSON.parse(decrypted.plaintext.toString());
}

app.post('/login', async (req, res) => {
  // ... authentication logic ...
  
  const payload = { 
    userId: user.id, 
    exp: Math.floor(Date.now() / 1000) + (15 * 60) // 15 minutes from now
  };
  
  const token = await createEncryptedToken(payload);

  res.json({ token });
});

app.use(async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const payload = await decryptToken(token);
    if (payload.exp <= Math.floor(Date.now() / 1000)) {
      return res.sendStatus(401);
    }
    req.user = payload;
    next();
  } catch (error) {
    res.sendStatus(403);
  }
});
```

42. Implement Token Pinning:

This technique associates a token with a specific device or browser instance:

```javascript
const crypto = require('crypto');

function generateDeviceId(req) {
  const userAgent = req.headers['user-agent'];
  const ip = req.ip;
  return crypto.createHash('sha256').update(`${userAgent}${ip}`).digest('hex');
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const deviceId = generateDeviceId(req);
  
  const token = jwt.sign(
    { 
      userId: user.id,
      deviceId
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  // ... existing token verification ...

  const currentDeviceId = generateDeviceId(req);
  if (decoded.deviceId !== currentDeviceId) {
    return res.status(403).json({ message: 'Token not associated with this device' });
  }

  next();
}
```

43. Implement Proof Key for Code Exchange (PKCE):

This is typically used with OAuth 2.0 but can be adapted for JWT-based systems:

```javascript
const crypto = require('crypto');

app.post('/login', (req, res) => {
  const { username, password, codeVerifier } = req.body;
  
  // ... authentication logic ...

  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  const token = jwt.sign(
    { 
      userId: user.id,
      codeChallenge
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

app.post('/token', (req, res) => {
  const { token, codeVerifier } = req.body;

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    
  const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    if (codeChallenge !== decoded.codeChallenge) {
      return res.status(400).json({ message: 'Invalid code verifier' });
    }

    // Issue a new token or refresh token
    const newToken = jwt.sign({ userId: decoded.userId }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token: newToken });
  } catch (error) {
    res.status(400).json({ message: 'Invalid token' });
  }
});
```

44. Implement Token Binding with HTTP Token Binding:

This is a more advanced technique that binds the token to the TLS layer:

```javascript
const crypto = require('crypto');

function getTokenBindingId(req) {
  // In a real implementation, this would come from the TLS layer
  // This is a simplified example
  return req.get('Sec-Token-Binding');
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const tokenBindingId = getTokenBindingId(req);
  
  const token = jwt.sign(
    { 
      userId: user.id,
      tbh: crypto.createHash('sha256').update(tokenBindingId).digest('base64')
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  // ... existing token verification ...

  const currentTokenBindingId = getTokenBindingId(req);
  const currentTbh = crypto.createHash('sha256').update(currentTokenBindingId).digest('base64');

  if (decoded.tbh !== currentTbh) {
    return res.status(403).json({ message: 'Token binding mismatch' });
  }

  next();
}
```

45. Implement Continuous Authentication:

This technique involves constantly re-evaluating the user's authenticity:

```javascript
const riskScore = require('./riskAssessment'); // Hypothetical risk assessment module

function authenticateToken(req, res, next) {
  // ... existing token verification ...

  const userRiskScore = riskScore(req);

  if (userRiskScore > 0.7) { // High risk
    return res.status(401).json({ message: 'Please re-authenticate' });
  } else if (userRiskScore > 0.4) { // Medium risk
    // Issue a new token with shorter expiration
    const newToken = jwt.sign(
      { ...decoded, exp: Math.floor(Date.now() / 1000) + (5 * 60) }, // 5 minutes
      SECRET_KEY
    );
    res.setHeader('X-New-Token', newToken);
  }

  next();
}
```

46. Implement Distributed JWT Verification:

For large-scale applications, you might want to distribute the JWT verification:

```javascript
const Redis = require('ioredis');
const redis = new Redis();

async function verifyToken(token) {
  try {
    // Try to get the decoded token from cache
    const cachedToken = await redis.get(`token:${token}`);
    if (cachedToken) {
      return JSON.parse(cachedToken);
    }

    // If not in cache, verify and cache it
    const decoded = jwt.verify(token, SECRET_KEY);
    await redis.set(`token:${token}`, JSON.stringify(decoded), 'EX', 60); // Cache for 1 minute
    return decoded;
  } catch (error) {
    throw new Error('Invalid token');
  }
}

async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  try {
    const decoded = await verifyToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    return res.sendStatus(403);
  }
}
```

47. Implement JWT with Public Key Rotation:

Regularly rotating public keys can enhance security:

```javascript
const NodeRSA = require('node-rsa');
const keyPairs = new Map();

function generateNewKeyPair() {
  const key = new NodeRSA({b: 2048});
  const keyId = Date.now().toString();
  keyPairs.set(keyId, key);
  return keyId;
}

// Generate a new key pair every hour
setInterval(generateNewKeyPair, 60 * 60 * 1000);

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const currentKeyId = Array.from(keyPairs.keys()).pop();
  const currentKey = keyPairs.get(currentKeyId);
  
  const token = jwt.sign(
    { 
      userId: user.id,
      keyId: currentKeyId
    }, 
    currentKey.exportKey('private'), 
    { algorithm: 'RS256', expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.decode(token, { complete: true });
    const key = keyPairs.get(decoded.payload.keyId);
    
    if (!key) {
      return res.status(401).json({ message: 'Token was signed with an unknown key' });
    }

    const verified = jwt.verify(token, key.exportKey('public'), { algorithms: ['RS256'] });
    req.user = verified;
    next();
  } catch (error) {
    return res.sendStatus(403);
  }
}
```

48. Implement Cross-Domain JWT:

For scenarios where you need to share authentication across multiple domains:

```javascript
const cors = require('cors');

app.use(cors({
  origin: ['https://domain1.com', 'https://domain2.com'],
  credentials: true
}));

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '15m' });

  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: '.parentdomain.com' // Shared parent domain
  });

  res.json({ message: 'Logged in successfully' });
});

app.post('/logout', (req, res) => {
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: '.parentdomain.com'
  });

  res.json({ message: 'Logged out successfully' });
});
```

49. Implement JWT with Cryptographic Agility:

This allows for easy algorithm changes in the future:

```javascript
const algorithms = {
  'HS256': { sign: (payload, secret) => jwt.sign(payload, secret, { algorithm: 'HS256' }),
             verify: (token, secret) => jwt.verify(token, secret, { algorithms: ['HS256'] }) },
  'RS256': { sign: (payload, privateKey) => jwt.sign(payload, privateKey, { algorithm: 'RS256' }),
             verify: (token, publicKey) => jwt.verify(token, publicKey, { algorithms: ['RS256'] }) }
};

const CURRENT_ALG = 'RS256';

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = algorithms[CURRENT_ALG].sign(
    { userId: user.id },
    PRIVATE_KEY // Assume this is defined elsewhere
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = algorithms[CURRENT_ALG].verify(token, PUBLIC_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    return res.sendStatus(403);
  }
}
```

50. Implement JWT with Custom Claims Validation:

This allows for more complex validation rules:

```javascript
const Ajv = require('ajv');
const ajv = new Ajv();

const tokenSchema = {
  type: 'object',
  properties: {
    userId: { type: 'string' },
    role: { type: 'string', enum: ['user', 'admin'] },
    permissions: { 
      type: 'array',
      items: { type: 'string' },
      minItems: 1
    }
  },
  required: ['userId', 'role', 'permissions']
};

const validateToken = ajv.compile(tokenSchema);

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    
    if (!validateToken(decoded)) {
      return res.status(403).json({ message: 'Token payload does not match required schema' });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.sendStatus(403);
  }
}
```

51. Implement JWT with Audience Validation:

This ensures the token is being used by the intended recipient:

```javascript
app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    { 
      userId: user.id,
      aud: 'https://api.yourdomain.com'
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY, {
      audience: 'https://api.yourdomain.com'
    });
    req.user = decoded;
    next();
  } catch (error) {
    return res.sendStatus(403);
  }
}
```

52. Implement JWT with Nested Signing:

This can be useful for adding additional layers of security or for implementing delegation:

```javascript
function createNestedToken(innerPayload, outerPayload) {
  const innerToken = jwt.sign(innerPayload, INNER_SECRET_KEY);
  
  return jwt.sign(
    { ...outerPayload, innerToken },
    OUTER_SECRET_KEY
  );
}

function verifyNestedToken(token) {
  const outerDecoded = jwt.verify(token, OUTER_SECRET_KEY);
  const innerDecoded = jwt.verify(outerDecoded.innerToken, INNER_SECRET_KEY);
  
  return { ...outerDecoded, ...innerDecoded };
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const innerPayload = { userId: user.id };
  const outerPayload = { iss: 'https://auth.yourdomain.com', aud: 'https://api.yourdomain.com' };
  
  const token = createNestedToken(innerPayload, outerPayload);

  res.json({ token });
});

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = verifyNestedToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    return res.sendStatus(403);
  }
}
```

53. Implement JWT with Dynamic Scopes:

This allows for more flexible permission management:

```javascript
const SCOPE_SECRET = 'your-scope-secret-key';

function generateScopeToken(scopes) {
  return jwt.sign({ scopes }, SCOPE_SECRET, { expiresIn: '1h' });
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const userScopes = getUserScopes(user); // Function to get user's allowed scopes
  const scopeToken = generateScopeToken(userScopes);
  
  const token = jwt.sign(
    { 
      userId: user.id,
      scopeToken
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function checkScope(requiredScope) {
  return (req, res, next) => {
    const { scopeToken } = req.user;
    
    try {
      const { scopes } = jwt.verify(scopeToken, SCOPE_SECRET);
      if (scopes.includes(requiredScope)) {
        next();
      } else {
        res.status(403).json({ message: 'Insufficient scope' });
      }
    } catch (error) {
      res.status(403).json({ message: 'Invalid scope token' });
    }
  };
}

app.get('/protected-resource', authenticateToken, checkScope('read:resource'), (req, res) => {
  res.json({ message: 'Access granted to protected resource' });
});
```

54. Implement JWT with Proof of Possession:

This technique ensures that the client possesses a certain key, adding an extra layer of security:

```javascript
const crypto = require('crypto');

function generateKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const { publicKey, privateKey } = generateKeyPair();
  
  const token = jwt.sign(
    { 
      userId: user.id,
      publicKey
    }, 
    SECRET_KEY, 
    { expiresIn: '15m' }
  );

  res.json({ token, privateKey });
});

app.post('/verify-possession', authenticateToken, (req, res) => {
  const { signature } = req.body;
  const challenge = 'random-challenge-string';

  const verify = crypto.createVerify('SHA256');
  verify.update(challenge);
  
  if (verify.verify(req.user.publicKey, signature, 'base64')) {
    res.json({ message: 'Proof of possession verified' });
  } else {
    res.status(403).json({ message: 'Failed to verify proof of possession' });
  }
});
```

55. Implement JWT with Mutual TLS (mTLS):

This technique uses client certificates for additional authentication:

```javascript
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('server-key.pem'),
  cert: fs.readFileSync('server-cert.pem'),
  ca: [fs.readFileSync('client-ca-cert.pem')],
  requestCert: true,
  rejectUnauthorized: true
};

const server = https.createServer(options, app);

app.post('/login', (req, res) => {
  const cert = req.connection.getPeerCertificate();
  
  if (req.client.authorized) {
    // Client certificate is valid
    const token = jwt.sign(
      { 
        userId: getUserIdFromCert(cert),
        certFingerprint: cert.fingerprint
      }, 
      SECRET_KEY, 
      { expiresIn: '15m' }
    );

    res.json({ token });
  } else {
    res.status(403).json({ message: 'Invalid client certificate' });
  }
});

function authenticateToken(req, res, next) {
  // ... existing token verification ...

  const cert = req.connection.getPeerCertificate();
  if (decoded.certFingerprint !== cert.fingerprint) {
    return res.status(403).json({ message: 'Certificate mismatch' });
  }

  next();
}
```

56. Implement JWT with Token Binding to HTTP/2 Connection:

This technique binds the token to a specific HTTP/2 connection:

```javascript
const http2 = require('http2');
const server = http2.createSecureServer({ key: serverKey, cert: serverCert });

server.on('stream', (stream, headers) => {
  const connectionId = stream.session.socket.getSessionID().toString('hex');

  if (headers[':method'] === 'POST' && headers[':path'] === '/login') {
    // ... authentication logic ...
    
    const token = jwt.sign(
      { 
        userId: user.id,
        connectionId
      }, 
      SECRET_KEY, 
      { expiresIn: '15m' }
    );

    stream.respond({
      'content-type': 'application/json',
      ':status': 200
    });
    stream.end(JSON.stringify({ token }));
  } else if (headers[':method'] === 'GET' && headers[':path'].startsWith('/protected')) {
    const token = headers['authorization']?.split(' ')[1];
    if (!token) {
      stream.respond({ ':status': 401 });
      stream.end();
      return;
    }

    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      if (decoded.connectionId !== connectionId) {
        stream.respond({ ':status': 403 });
        stream.end('Token not bound to this connection');
        return;
      }

      // ... handle protected resource ...
    } catch (error) {
      stream.respond({ ':status': 403 });
      stream.end('Invalid token');
    }
  }
});
```

57. Implement JWT with Distributed Key Management:

This technique uses a key management service for handling JWT signing keys:

```javascript
const AWS = require('aws-sdk');
const kms = new AWS.KMS({ region: 'us-west-2' });

async function signJWT(payload) {
  const params = {
    KeyId: 'alias/your-kms-key-alias',
    Message: JSON.stringify(payload),
    SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256'
  };

  const { Signature } = await kms.sign(params).promise();
  
  const token = Buffer.from(JSON.stringify({
    header: { alg: 'RS256', typ: 'JWT' },
    payload,
    signature: Signature.toString('base64')
  })).toString('base64');

  return token;
}

async function verifyJWT(token) {
  const { header, payload, signature } = JSON.parse(Buffer.from(token, 'base64').toString());

  const params = {
    KeyId: 'alias/your-kms-key-alias',
    Message: JSON.stringify(payload),
    Signature: Buffer.from(signature, 'base64'),
    SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256'
  };

  try {
    await kms.verify(params).promise();
    return payload;
  } catch (error) {
    throw new Error('Invalid signature');
  }
}

app.post('/login', async (req, res) => {
  // ... authentication logic ...
  
  const payload = { userId: user.id, exp: Math.floor(Date.now() / 1000) + (15 * 60) };
  const token = await signJWT(payload);

  res.json({ token });
});

async function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const payload = await verifyJWT(token);
    if (payload.exp <= Math.floor(Date.now() / 1000)) {
      return res.sendStatus(401);
    }
    req.user = payload;
    next();
  } catch (error) {
    return res.sendStatus(403);
  }
}
```

58. Implement JWT with Dynamic Token Structure:

This technique allows for flexible token structures based on user roles or other factors:

```javascript
function getTokenStructure(user) {
  const baseStructure = {
    userId: user.id,
    exp: Math.floor(Date.now() / 1000) + (15 * 60)
  };

  switch (user.role) {
    case 'admin':
      return {
        ...baseStructure,
        adminPrivileges: true,
        accessLevel: 'full'
      };
    case 'manager':
      return {
        ...baseStructure,
        managedDepartments: user.departments,
        accessLevel: 'elevated'
      };
    default:
      return {
        ...baseStructure,
        accessLevel: 'standard'
      };
  }
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const tokenPayload = getTokenStructure(user);
  const token = jwt.sign(tokenPayload, SECRET_KEY);

  res.json({ token });
});
```

59. Implement JWT with Claim Transformation:

This technique allows for transforming claims during token verification:

```javascript
const claimTransformers = {
  'role': (role) => role.toUpperCase(),
  'permissions': (permissions) => permissions.filter(p => p.startsWith('api:')),
  'exp': (exp) => new Date(exp * 1000)
};

function transformClaims(payload) {
  const transformedPayload = { ...payload };
  for (const [claim, transformer] of Object.entries(claimTransformers)) {
    if (transformedPayload.hasOwnProperty(claim)) {
      transformedPayload[claim] = transformer(transformedPayload[claim]);
    }
  }
  return transformedPayload;
}

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = transformClaims(decoded);
    next();
  } catch (error) {
    return res.sendStatus(403);
  }
}
```

60. Implement JWT with Adaptive Token Expiration:

This technique adjusts token expiration based on user behavior or risk factors:

```javascript
const riskAssessor = require('./riskAssessor'); // Hypothetical risk assessment module

function getTokenExpiration(user) {
  const baseExpiration = 15 * 60; // 15 minutes
  const riskScore = riskAssessor.assessRisk(user);

  if (riskScore < 0.2) {
    return baseExpiration * 2; // 30 minutes for low-risk users
  } else if (riskScore > 0.8) {
    return baseExpiration / 2; // 7.5 minutes for high-risk users
  } else {
    return baseExpiration;
  }
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const expiration = getTokenExpiration(user);
  const token = jwt.sign(
    { userId: user.id },
    SECRET_KEY,
    { expiresIn: expiration }
  );

  res.json({ token });
});
```

61. Implement JWT with Claim Caching:

This technique caches certain claims to reduce database lookups:

```javascript
const NodeCache = require('node-cache');
const claimCache = new NodeCache({ stdTTL: 600 }); // 10 minutes

async function getCachedClaims(userId) {
  const cachedClaims = claimCache.get(userId);
  if (cachedClaims) {
    return cachedClaims;
  }

  const claims = await fetchUserClaims(userId); // Fetch from database
  claimCache.set(userId, claims);
  return claims;
}

app.post('/login', async (req, res) => {
  // ... authentication logic ...
  
  const claims = await getCachedClaims(user.id);
  const token = jwt.sign(
    { userId: user.id, ...claims },
    SECRET_KEY,
    { expiresIn: '15m' }
  );

  res.json({ token });
});
```

62. Implement JWT with Incremental Authorization:

This technique allows for incrementally adding permissions to a token:

```javascript
app.post('/elevate', authenticateToken, async (req, res) => {
  const { userId } = req.user;
  const { additionalPermission } = req.body;

  // Check if user is allowed to gain this permission
  if (await canUserGainPermission(userId, additionalPermission)) {
    const newToken = jwt.sign(
      { 
        ...req.user,
        permissions: [...req.user.permissions, additionalPermission]
      },
      SECRET_KEY,
      { expiresIn: '15m' }
    );

    res.json({ token: newToken });
  } else {
    res.status(403).json({ message: 'Permission elevation denied' });
  }
});
```

63. Implement JWT with Delegated Authentication:

This technique allows for delegating authentication to another service:

```javascript
const axios = require('axios');

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Delegate authentication to another service
    const authResponse = await axios.post('https://auth-service.example.com/authenticate', {
      username,
      password
    });

    if (authResponse.data.authenticated) {
      const token = jwt.sign(
        { 
          userId: authResponse.data.userId,
          authProviderId: 'auth-service.example.com'
        },
        SECRET_KEY,
        { expiresIn: '15m' }
      );

      res.json({ token });
    } else {
      res.status(401).json({ message: 'Authentication failed' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Authentication service unavailable' });
  }
});

async function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    
    // Verify with the auth provider
    const verifyResponse = await axios.post(`https://${decoded.authProviderId}/verify`, {
      userId: decoded.userId
    });

    if (verifyResponse.data.valid) {
      req.user = decoded;
      next();
    } else {
      res.sendStatus(403);
    }
  } catch (error) {
    res.sendStatus(403);
  }
}
```

64. Implement JWT with Dynamic Signing Algorithm:

This technique allows for changing the signing algorithm based on certain conditions:

```javascript
const algorithms = {
  'HS256': { sign: (payload, secret) => jwt.sign(payload, secret, { algorithm: 'HS256' }),
             verify: (token, secret) => jwt.verify(token, secret, { algorithms: ['HS256'] }) },
  'RS256': { sign: (payload, privateKey) => jwt.sign(payload, privateKey, { algorithm: 'RS256' }),
             verify: (token, publicKey) => jwt.verify(token, publicKey, { algorithms: ['RS256'] }) }
};

function getAlgorithm(user) {
  return user.highSecurity ? 'RS256' : 'HS256';
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const alg = getAlgorithm(user);
  const secret = alg === 'RS256' ? PRIVATE_KEY : SECRET_KEY;
  
  const token = algorithms[alg].sign(
    { userId: user.id, alg },
    secret
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const { alg } = jwt.decode(token, { complete: true }).header;
    const secret = alg === 'RS256' ? PUBLIC_KEY : SECRET_KEY;
    
    const decoded = algorithms[alg].verify(token, secret);
    req.user = decoded;
    next();
  } catch (error) {
    res.sendStatus(403);
  }
}
```

65. Implement JWT with Partial Token Invalidation:

This technique allows for invalidating specific claims within a token without completely revoking it:

```javascript
const Redis = require('ioredis');
const redis = new Redis();

app.post('/invalidate-claim', authenticateToken, async (req, res) => {
  const { claimToInvalidate } = req.body;
  const { userId } = req.user;

  await redis.sadd(`invalidated:${userId}`, claimToInvalidate);
  res.json({ message: 'Claim invalidated' });
});

async function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const { userId } = decoded;

    // Check for invalidated claims
    const invalidatedClaims = await redis.smembers(`invalidated:${userId}`);
    
    for (const claim of invalidatedClaims) {
      if (decoded.hasOwnProperty(claim)) {
        delete decoded[claim];
      }
    }

    req.user = decoded;
    next();
  } catch (error) {
    res.sendStatus(403);
  }
}
```

66. Implement JWT with Claim Versioning:

This technique allows for versioning of claims to handle updates to claim structures:

```javascript
const claimVersions = {
  'v1': {
    transform: (claims) => claims,
    validate: (claims) => true
  },
  'v2': {
    transform: (claims) => ({
      ...claims,
      permissions: claims.permissions.map(p => `v2.${p}`)
    }),
    validate: (claims) => Array.isArray(claims.permissions)
  }
};

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    { 
      userId: user.id,
      permissions: user.permissions,
      claimVersion: 'v2'
    },
    SECRET_KEY,
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const { claimVersion } = decoded;

    if (!claimVersions[claimVersion]) {
      return res.status(400).json({ message: 'Unsupported claim version' });
    }

    const transformedClaims = claimVersions[claimVersion].transform(decoded);
    if (!claimVersions[claimVersion].validate(transformedClaims)) {
      return res.status(400).json({ message: 'Invalid claim structure' });
    }

    req.user = transformedClaims;
    next();
  } catch (error) {
    res.sendStatus(403);
  }
}
```

67. Implement JWT with Claim Dependency Injection:

This technique allows for dynamic injection of claims based on external dependencies:

```javascript
const claimProviders = {
  'userMetadata': async (userId) => {
    // Fetch user metadata from a service
    const response = await axios.get(`https://metadata-service.example.com/user/${userId}`);
    return response.data;
  },
  'realtimePermissions': async (userId) => {
    // Fetch real-time permissions from a service
    const response = await axios.get(`https://permissions-service.example.com/user/${userId}`);
    return response.data.permissions;
  }
};

app.post('/login', async (req, res) => {
  // ... authentication logic ...
  
  const baseToken = jwt.sign(
    { userId: user.id },
    SECRET_KEY,
    { expiresIn: '15m' }
  );

  res.json({ token: baseToken });
});

async function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const { userId } = decoded;

    // Inject dynamic claims
    decoded.metadata = await claimProviders.userMetadata(userId);
    decoded.permissions = await claimProviders.realtimePermissions(userId);

    req.user = decoded;
    next();
  } catch (error) {
    res.sendStatus(403);
  }
}
```

68. Implement JWT with Claim Aggregation:

This technique allows for aggregating claims from multiple sources:

```javascript
const claimSources = [
  async (userId) => {
    const response = await axios.get(`https://profile-service.example.com/user/${userId}`);
    return { profile: response.data };
  },
  async (userId) => {
    const response = await axios.get(`https://billing-service.example.com/user/${userId}`);
    return { billingStatus: response.data.status };
  },
  async (userId) => {
    const response = await axios.get(`https://preferences-service.example.com/user/${userId}`);
    return { preferences: response.data };
  }
];

app.post('/login', async (req, res) => {
  // ... authentication logic ...
  
  const baseToken = jwt.sign(
    { userId: user.id },
    SECRET_KEY,
    { expiresIn: '15m' }
  );

  res.json({ token: baseToken });
});

async function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const { userId } = decoded;

    // Aggregate claims from multiple sources
    const aggregatedClaims = await Promise.all(claimSources.map(source => source(userId)));
    req.user = Object.assign({}, decoded, ...aggregatedClaims);

    next();
  } catch (error) {
    res.sendStatus(403);
  }
}
```

69. Implement JWT with Claim Transformation Pipeline:

This technique allows for a series of transformations to be applied to claims:

```javascript
const transformationPipeline = [
  (claims) => ({
    ...claims,
    username: claims.username.toLowerCase()
  }),
  (claims) => ({
    ...claims,
    isAdmin: claims.roles.includes('admin')
  }),
  (claims) => ({
    ...claims,
    permissions: claims.permissions.filter(p => !p.startsWith('deprecated:'))
  })
];

function applyTransformations(claims) {
  return transformationPipeline.reduce((acc, transform) => transform(acc), claims);
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    applyTransformations({
      userId: user.id,
      username: user.username,
      roles: user.roles,
      permissions: user.permissions
    }),
    SECRET_KEY,
    { expiresIn: '15m' }
  );

  res.json({ token });
});
```

70. Implement JWT with Claim Validation Rules:

This technique allows for defining and applying complex validation rules to claims:

```javascript
const validationRules = {
  username: (value) => typeof value === 'string' && value.length >= 3,
  roles: (value) => Array.isArray(value) && value.every(role => typeof role === 'string'),
  permissions: (value) => Array.isArray(value) && value.length > 0,
  exp: (value) => typeof value === 'number' && value > Math.floor(Date.now() / 1000)
};

function validateClaims(claims) {
  for (const [key, validator] of Object.entries(validationRules)) {
    if (claims.hasOwnProperty(key) && !validator(claims[key])) {
      throw new Error(`Invalid claim: ${key}`);
    }
  }
  return true;
}

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    if (validateClaims(decoded)) {
      req.user = decoded;
      next();
    } else {
      res.sendStatus(403);
    }
  } catch (error) {
    res.status(403).json({ message: error.message });
  }
}
```

71. Implement JWT with Hierarchical Claims:

This technique allows for structuring claims in a hierarchical manner:

```javascript
function buildHierarchicalClaims(user) {
  return {
    sub: user.id,
    profile: {
      name: user.name,
      email: user.email
    },
    access: {
      roles: user.roles,
      permissions: user.permissions
    },
    security: {
      mfaEnabled: user.mfaEnabled,
      lastPasswordChange: user.lastPasswordChange
    }
  };
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    buildHierarchicalClaims(user),
    SECRET_KEY,
    { expiresIn: '15m' }
  );

  res.json({ token });
});
```

72. Implement JWT with Claim Inheritance:

This technique allows for inheriting claims based on user roles:

```javascript
const roleBasedClaims = {
  user: {
    canReadPosts: true,
    canCommentPosts: true
  },
  moderator: {
    canEditPosts: true,
    canDeleteComments: true
  },
  admin: {
    canManageUsers: true,
    canConfigureSystem: true
  }
};

function buildInheritedClaims(user) {
  let claims = { ...roleBasedClaims.user }; // Everyone gets basic user claims

  if (user.roles.includes('moderator')) {
    claims = { ...claims, ...roleBasedClaims.moderator };
  }

  if (user.roles.includes('admin')) {
    claims = { ...claims, ...roleBasedClaims.admin };
  }

  return {
    sub: user.id,
    roles: user.roles,
    ...claims
  };
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    buildInheritedClaims(user),
    SECRET_KEY,
    { expiresIn: '15m' }
  );

  res.json({ token });
});
```

73. Implement JWT with Claim Namespacing:

This technique allows for organizing claims into namespaces to prevent conflicts:

```javascript
function namespaceClaims(claims) {
  return {
    'urn:example:identity': {
      sub: claims.sub,
      name: claims.name,
      email: claims.email
    },
    'urn:example:access': {
      roles: claims.roles,
      permissions: claims.permissions
    },
    'urn:example:app': {
      preferences: claims.preferences,
      settings: claims.settings
    }
  };
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    namespaceClaims({
      sub: user.id,
      name: user.name,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
      preferences: user.preferences

Certainly! Let's continue with the implementation of JWT with Claim Namespacing and more advanced techniques:

```javascript
app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    namespaceClaims({
      sub: user.id,
      name: user.name,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
      preferences: user.preferences,
      settings: user.settings
    }),
    SECRET_KEY,
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    res.sendStatus(403);
  }
}
```

74. Implement JWT with Dynamic Claim Resolution:

This technique allows for resolving claims dynamically at runtime:

```javascript
const claimResolvers = {
  'dynamicPermissions': async (userId) => {
    const response = await axios.get(`https://permissions-service.example.com/user/${userId}`);
    return response.data.permissions;
  },
  'realtimeRoles': async (userId) => {
    const response = await axios.get(`https://roles-service.example.com/user/${userId}`);
    return response.data.roles;
  }
};

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    { 
      sub: user.id,
      name: user.name,
      email: user.email
    },
    SECRET_KEY,
    { expiresIn: '15m' }
  );

  res.json({ token });
});

async function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    
    // Resolve dynamic claims
    for (const [claimKey, resolver] of Object.entries(claimResolvers)) {
      decoded[claimKey] = await resolver(decoded.sub);
    }

    req.user = decoded;
    next();
  } catch (error) {
    res.sendStatus(403);
  }
}
```

75. Implement JWT with Claim Expiration Policies:

This technique allows for setting different expiration policies for different claims:

```javascript
const claimExpirationPolicies = {
  'permissions': 5 * 60, // 5 minutes
  'roles': 60 * 60, // 1 hour
  'preferences': 24 * 60 * 60 // 24 hours
};

function setClaimExpirations(claims) {
  const now = Math.floor(Date.now() / 1000);
  const claimsWithExpiration = { ...claims };

  for (const [claim, expiration] of Object.entries(claimExpirationPolicies)) {
    if (claims.hasOwnProperty(claim)) {
      claimsWithExpiration[`${claim}Exp`] = now + expiration;
    }
  }

  return claimsWithExpiration;
}

app.post('/login', (req, res) => {
  // ... authentication logic ...
  
  const token = jwt.sign(
    setClaimExpirations({
      sub: user.id,
      name: user.name,
      email: user.email,
      permissions: user.permissions,
      roles: user.roles,
      preferences: user.preferences
    }),
    SECRET_KEY,
    { expiresIn: '15m' }
  );

  res.json({ token });
});

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
