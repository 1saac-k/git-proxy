/**
 * Copyright 2026 GitProxy Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { describe, it, beforeEach, expect, vi, type Mock, afterEach } from 'vitest';

let dbStub: { updateUser: Mock; findUser: Mock };
let passportStub: {
  use: Mock;
  serializeUser: Mock;
  deserializeUser: Mock;
};

// The callback captured from passport.use(type, new CustomStrategy(callback))
let strategyCallback: (req: any, done: (err: unknown, user?: unknown) => void) => Promise<void>;

// Mock ldapts Client instances
let serviceClientMock: {
  bind: Mock;
  unbind: Mock;
  search: Mock;
  startTLS: Mock;
};
let userClientMock: {
  bind: Mock;
  unbind: Mock;
  startTLS: Mock;
};
let clientInstances: any[];

const ldapConfig = {
  url: 'ldap://test-ldap:389',
  bindDN: 'cn=admin,dc=test,dc=com',
  bindPassword: 'admin-password',
  searchBase: 'ou=people,dc=test,dc=com',
  searchFilter: '(uid={{username}})',
  userGroupDN: 'cn=users,ou=groups,dc=test,dc=com',
  adminGroupDN: 'cn=admins,ou=groups,dc=test,dc=com',
  groupSearchBase: 'ou=groups,dc=test,dc=com',
  groupSearchFilter: '(member={{dn}})',
  usernameAttribute: 'uid',
  emailAttribute: 'mail',
  displayNameAttribute: 'cn',
  titleAttribute: 'title',
  starttls: false,
  tlsOptions: {},
};

const newConfig = JSON.stringify({
  authentication: [
    {
      type: 'ldap',
      enabled: true,
      ldapConfig,
    },
  ],
});

const createClientMock = () => ({
  bind: vi.fn().mockResolvedValue(undefined),
  unbind: vi.fn().mockResolvedValue(undefined),
  search: vi.fn().mockResolvedValue({ searchEntries: [], searchReferences: [] }),
  startTLS: vi.fn().mockResolvedValue(undefined),
});

describe('LDAP auth method', () => {
  beforeEach(async () => {
    dbStub = {
      updateUser: vi.fn().mockResolvedValue(undefined),
      findUser: vi.fn().mockResolvedValue(null),
    };

    passportStub = {
      use: vi.fn(),
      serializeUser: vi.fn(),
      deserializeUser: vi.fn(),
    };

    clientInstances = [];
    serviceClientMock = createClientMock();
    userClientMock = createClientMock();

    // Track which instance is created
    let callCount = 0;

    // mock fs for config
    vi.doMock('fs', (importOriginal) => {
      const actual = importOriginal();
      return {
        ...actual,
        existsSync: vi.fn().mockReturnValue(true),
        readFileSync: vi.fn().mockReturnValue(newConfig),
      };
    });

    vi.doMock('../../../src/db', () => dbStub);

    vi.doMock('ldapts', () => ({
      Client: function (opts: any) {
        const mock = callCount === 0 ? serviceClientMock : userClientMock;
        callCount++;
        clientInstances.push(mock);
        return mock;
      },
    }));

    vi.doMock('passport-custom', () => ({
      Strategy: function (callback: any) {
        strategyCallback = callback;
        return { name: 'ldap', authenticate: () => {} };
      },
    }));

    // First import config
    const config = await import('../../../src/config/index.js');
    config.initUserConfig();
    vi.doMock('../../../src/config', () => config);

    // then configure ldap
    const { configure } = await import('../../../src/service/passport/ldap.js');
    await configure(passportStub as any);
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
  });

  it('should authenticate a valid user and mark them as admin', async () => {
    // Service account search returns a user entry
    serviceClientMock.search
      .mockResolvedValueOnce({
        searchEntries: [
          {
            dn: 'uid=testuser,ou=people,dc=test,dc=com',
            uid: 'testuser',
            mail: 'test@test.com',
            cn: 'Test User',
            title: 'Engineer',
          },
        ],
      })
      // userGroup membership check
      .mockResolvedValueOnce({
        searchEntries: [{ dn: 'cn=users,ou=groups,dc=test,dc=com' }],
      })
      // adminGroup membership check
      .mockResolvedValueOnce({
        searchEntries: [{ dn: 'cn=admins,ou=groups,dc=test,dc=com' }],
      });

    // User bind succeeds (valid password)
    userClientMock.bind.mockResolvedValueOnce(undefined);

    const req = { body: { username: 'testuser', password: 'secret' } };
    const done = vi.fn();

    await strategyCallback(req, done);

    expect(done).toHaveBeenCalledOnce();
    const [err, user] = done.mock.calls[0];
    expect(err).toBeNull();
    expect(user).toMatchObject({
      username: 'testuser',
      email: 'test@test.com',
      displayName: 'Test User',
      admin: true,
      title: 'Engineer',
    });

    expect(dbStub.updateUser).toHaveBeenCalledOnce();
  });

  it('should authenticate a non-admin user', async () => {
    serviceClientMock.search
      .mockResolvedValueOnce({
        searchEntries: [
          {
            dn: 'uid=regular,ou=people,dc=test,dc=com',
            uid: 'regular',
            mail: 'regular@test.com',
            cn: 'Regular User',
            title: 'Developer',
          },
        ],
      })
      // userGroup membership check - is member
      .mockResolvedValueOnce({
        searchEntries: [{ dn: 'cn=users,ou=groups,dc=test,dc=com' }],
      })
      // adminGroup membership check - not member
      .mockResolvedValueOnce({
        searchEntries: [],
      });

    userClientMock.bind.mockResolvedValueOnce(undefined);

    const req = { body: { username: 'regular', password: 'pass' } };
    const done = vi.fn();

    await strategyCallback(req, done);

    expect(done).toHaveBeenCalledOnce();
    const [err, user] = done.mock.calls[0];
    expect(err).toBeNull();
    expect(user).toMatchObject({
      username: 'regular',
      admin: false,
    });
  });

  it('should fail if user is not found in LDAP', async () => {
    serviceClientMock.search.mockResolvedValueOnce({
      searchEntries: [],
    });

    const req = { body: { username: 'nouser', password: 'pass' } };
    const done = vi.fn();

    await strategyCallback(req, done);

    expect(done).toHaveBeenCalledOnce();
    const [err, user] = done.mock.calls[0];
    expect(err).toBeNull();
    expect(user).toBe(false);
    expect(dbStub.updateUser).not.toHaveBeenCalled();
  });

  it('should fail if user is not in user group', async () => {
    serviceClientMock.search
      .mockResolvedValueOnce({
        searchEntries: [
          {
            dn: 'uid=outsider,ou=people,dc=test,dc=com',
            uid: 'outsider',
            mail: 'out@test.com',
            cn: 'Outsider',
            title: '',
          },
        ],
      })
      // userGroup membership check - not a member
      .mockResolvedValueOnce({
        searchEntries: [],
      });

    const req = { body: { username: 'outsider', password: 'pass' } };
    const done = vi.fn();

    await strategyCallback(req, done);

    expect(done).toHaveBeenCalledOnce();
    const [err, user] = done.mock.calls[0];
    expect(err).toBeNull();
    expect(user).toBe(false);
    expect(dbStub.updateUser).not.toHaveBeenCalled();
  });

  it('should fail if user password is incorrect (user bind fails)', async () => {
    serviceClientMock.search
      .mockResolvedValueOnce({
        searchEntries: [
          {
            dn: 'uid=testuser,ou=people,dc=test,dc=com',
            uid: 'testuser',
            mail: 'test@test.com',
            cn: 'Test User',
            title: '',
          },
        ],
      })
      // userGroup membership check
      .mockResolvedValueOnce({
        searchEntries: [{ dn: 'cn=users,ou=groups,dc=test,dc=com' }],
      })
      // adminGroup membership check
      .mockResolvedValueOnce({
        searchEntries: [],
      });

    // User bind fails - wrong password
    userClientMock.bind.mockRejectedValueOnce(new Error('Invalid credentials'));

    const req = { body: { username: 'testuser', password: 'wrong' } };
    const done = vi.fn();

    await strategyCallback(req, done);

    expect(done).toHaveBeenCalledOnce();
    const [err, user] = done.mock.calls[0];
    expect(err).toBeNull();
    expect(user).toBe(false);
    expect(dbStub.updateUser).not.toHaveBeenCalled();
  });

  it('should handle LDAP connection errors gracefully', async () => {
    serviceClientMock.bind.mockRejectedValueOnce(new Error('Connection refused'));

    const req = { body: { username: 'testuser', password: 'pass' } };
    const done = vi.fn();

    await strategyCallback(req, done);

    expect(done).toHaveBeenCalledOnce();
    const [err] = done.mock.calls[0];
    expect(err).toBeTruthy();
    expect(dbStub.updateUser).not.toHaveBeenCalled();
  });

  it('should fail if search returns multiple entries', async () => {
    serviceClientMock.search.mockResolvedValueOnce({
      searchEntries: [
        { dn: 'uid=user1,ou=people,dc=test,dc=com', uid: 'user1' },
        { dn: 'uid=user2,ou=people,dc=test,dc=com', uid: 'user2' },
      ],
    });

    const req = { body: { username: 'user1', password: 'pass' } };
    const done = vi.fn();

    await strategyCallback(req, done);

    expect(done).toHaveBeenCalledOnce();
    const [err, user] = done.mock.calls[0];
    expect(err).toBeNull();
    expect(user).toBe(false);
    expect(dbStub.updateUser).not.toHaveBeenCalled();
  });

  it('should fail when username or password is missing', async () => {
    const done = vi.fn();

    await strategyCallback({ body: { username: '', password: 'pass' } }, done);
    expect(done).toHaveBeenCalledWith(null, false);

    done.mockClear();

    await strategyCallback({ body: { username: 'user', password: '' } }, done);
    expect(done).toHaveBeenCalledWith(null, false);
  });
});
