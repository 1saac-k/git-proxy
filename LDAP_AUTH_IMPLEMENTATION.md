# LDAP Authentication Implementation Plan

## Commit Guidelines

- **Author**: Kwangjin Ko
- **Email**: kwangjin.ko@sk.com
- **Signed-off-by**: `Signed-off-by: Kwangjin Ko <kwangjin.ko@sk.com>`
- Commits should be small, atomic units for easy review
- No Claude Code links or co-author tags

---

## Background

### Problem
git-proxy currently supports Active Directory authentication via:
- `activedirectory2` - AD-specific wrapper (deprecated, AD-only)
- `ldapjs` - underlying LDAP library (deprecated)
- `passport-activedirectory` - Passport strategy for AD (deprecated)

These libraries are deprecated and `activedirectory2` only supports Active Directory, not generic LDAP servers.

### Solution
Add a new authentication type `ldap` using:
- **ldapts** - Modern, Promise-based LDAP client (replaces ldapjs/activedirectory2)
- **passport-custom** - Generic Passport strategy that accepts custom verify logic

Existing authentication methods (`local`, `ActiveDirectory`, `openidconnect`) remain unchanged.

---

## Library Research

### ldapts
- GitHub: https://github.com/ldapts/ldapts
- Modern, TypeScript-native LDAP client
- Promise-based API (no callbacks)
- Supports LDAP and LDAPS (SSL/TLS)
- Supports STARTTLS upgrade
- Key API:
  ```ts
  import { Client } from 'ldapts';

  const client = new Client({
    url: 'ldaps://ldap.example.com',
    timeout: 0,
    connectTimeout: 0,
    tlsOptions: { minVersion: 'TLSv1.2' },
    strictDN: true,
  });

  // Bind (authenticate)
  await client.bind(bindDN, password);

  // Search
  const { searchEntries } = await client.search(baseDN, {
    scope: 'sub',
    filter: '(uid=username)',
    attributes: ['cn', 'mail', 'uid', 'memberOf'],
  });

  // Unbind
  await client.unbind();
  ```

### passport-custom
- GitHub: https://github.com/mbell8903/passport-custom
- Allows creating Passport strategies with custom verification logic
- Verify callback receives the Express `req` object directly
- Key API:
  ```ts
  import { Strategy as CustomStrategy } from 'passport-custom';

  passport.use('ldap', new CustomStrategy(async (req, done) => {
    // Custom auth logic using req.body.username, req.body.password
    // done(null, user) on success
    // done(null, false) on failure
    // done(error) on error
  }));
  ```

---

## Current Architecture Analysis

### Auth Strategy Registration Pattern
File: `src/service/passport/index.ts`

```ts
type StrategyModule = {
  configure: (passport: PassportStatic) => Promise<PassportStatic>;
  createDefaultAdmin?: () => Promise<void>;
  type: string;
};

export const authStrategies: Record<string, StrategyModule> = {
  local,
  activedirectory: activeDirectory,
  openidconnect: oidc,
};
```

Each strategy module exports:
1. `type: string` - identifier (used in config and passport.use)
2. `configure(passport)` - registers the Passport strategy, sets up serialize/deserialize
3. `createDefaultAdmin?()` - optional default user creation

### Login Route Pattern
File: `src/service/routes/auth.ts`

- `appropriateLoginStrategies` array determines which strategies support username/password login
- `getLoginStrategy()` returns the first enabled username/password strategy
- POST `/api/auth/login` uses `passport.authenticate(strategyType)`

### Config Schema
File: `config.schema.json`

- `authenticationElement` uses `oneOf` to define different auth type configs
- Each type has a `const` type field and type-specific config object
- Generated types in `src/config/generated/config.ts` include `AuthenticationElementType` enum

### Existing AD Auth Flow
File: `src/service/passport/activeDirectory.ts`

1. Service account binds to LDAP (via adConfig credentials)
2. `passport-activedirectory` authenticates user and returns profile
3. Profile is checked for group membership (userGroup, adminGroup)
4. User is created/updated in DB
5. User object is serialized to session

---

## Configuration Design for New LDAP Type

```json
{
  "type": "ldap",
  "enabled": false,
  "ldapConfig": {
    "url": "ldaps://ldap.example.com",
    "bindDN": "cn=admin,dc=example,dc=com",
    "bindPassword": "password",
    "searchBase": "ou=users,dc=example,dc=com",
    "searchFilter": "(uid={{username}})",
    "adminGroupDN": "",
    "userGroupDN": "",
    "groupSearchBase": "",
    "groupSearchFilter": "(member={{dn}})",
    "usernameAttribute": "uid",
    "emailAttribute": "mail",
    "displayNameAttribute": "cn",
    "titleAttribute": "title",
    "tlsOptions": {}
  }
}
```

### Key Fields
- `url` - LDAP server URL (ldap:// or ldaps://)
- `bindDN` / `bindPassword` - Service account for searching
- `searchBase` - Base DN for user search
- `searchFilter` - Filter template (`{{username}}` replaced with login username)
- `usernameAttribute` - LDAP attribute for username (default: `uid`)
- `emailAttribute` - LDAP attribute for email (default: `mail`)
- `displayNameAttribute` - LDAP attribute for display name (default: `cn`)
- `titleAttribute` - LDAP attribute for title (default: `title`)
- `adminGroupDN` - DN of admin group (empty = no admin check)
- `userGroupDN` - DN of user group (empty = no user group check, all authenticated users allowed)
- `groupSearchBase` - Base DN for group membership search
- `groupSearchFilter` - Filter for group membership (`{{dn}}` replaced with user DN)
- `tlsOptions` - Node.js TLS options (e.g., `rejectUnauthorized`, `ca`)

### Authentication Flow
1. Create ldapts Client with `url` and `tlsOptions`
2. Bind with service account (`bindDN` / `bindPassword`)
3. Search for user with `searchFilter` under `searchBase`
4. If user not found, fail authentication
5. Unbind service account, re-bind with user's DN + provided password (user bind verification)
6. If userGroupDN set, check group membership
7. If adminGroupDN set, check admin group membership
8. Extract profile attributes from LDAP entry
9. Create/update user in DB
10. Return user to Passport

---

## Task List

### 1. Add dependencies
- `npm install ldapts passport-custom`
- `npm install -D @types/passport-custom` (if needed)

### 2. Update config schema (`config.schema.json`)
- Add `ldap` type to `authenticationElement.oneOf`
- Define `ldapConfig` schema with all fields
- Add to `AuthenticationElementType` const list

### 3. Regenerate config types
- Run quicktype or manual update of `src/config/generated/config.ts`
- Add `Ldap` to `AuthenticationElementType` enum
- Add `LdapConfig` interface
- Add `ldapConfig` optional field to `AuthenticationElement`

### 4. Update default config (`proxy.config.json`)
- Add `ldap` entry to `authentication` array (disabled by default)

### 5. Create LDAP strategy module (`src/service/passport/ldap.ts`)
- Export `type = 'ldap'`
- Export `configure(passport)` function
- Use `ldapts.Client` for LDAP operations
- Use `passport-custom` Strategy for Passport integration
- Implement: service bind -> user search -> user bind -> group check -> DB sync
- Set up serialize/deserialize

### 6. Register strategy in passport index (`src/service/passport/index.ts`)
- Import ldap module
- Add to `authStrategies` registry

### 7. Update auth routes (`src/service/routes/auth.ts`)
- Add ldap type to `appropriateLoginStrategies` array

### 8. Write tests (`test/services/passport/testLdapAuth.test.ts`)
- Test successful authentication
- Test user not found
- Test invalid password (bind failure)
- Test group membership check
- Test admin group check
- Test LDAP connection error handling

### 9. Run existing tests and lint
- Ensure no regressions
- Fix any lint issues
