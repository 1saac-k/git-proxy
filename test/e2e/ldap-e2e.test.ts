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

/**
 * E2E test for LDAP authentication against a real LLDAP server.
 *
 * Prerequisites:
 *   docker compose -f docker-compose.ldap-test.yml up -d
 *
 * Run:
 *   npx vitest run test/e2e/ldap-e2e.test.ts
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from 'ldapts';
import axios from 'axios';

const LLDAP_HTTP = 'http://localhost:17170';
const LLDAP_LDAP = 'ldap://localhost:3890';
const BASE_DN = 'dc=example,dc=com';
const ADMIN_DN = `cn=admin,ou=people,${BASE_DN}`;
const ADMIN_PASS = 'admin_password';

// LLDAP GraphQL API helper
let authToken: string;

const lldapApi = async (query: string, variables: Record<string, unknown> = {}) => {
  const res = await axios.post(
    `${LLDAP_HTTP}/api/graphql`,
    { query, variables },
    {
      headers: {
        Authorization: `Bearer ${authToken}`,
        'Content-Type': 'application/json',
      },
    },
  );
  if (res.data.errors) {
    throw new Error(`GraphQL error: ${JSON.stringify(res.data.errors)}`);
  }
  return res.data.data;
};

const getAuthToken = async (): Promise<string> => {
  const res = await axios.post(`${LLDAP_HTTP}/auth/simple/login`, {
    username: 'admin',
    password: ADMIN_PASS,
  });
  return res.data.token;
};

const createUser = async (userId: string, email: string, displayName: string, password: string) => {
  await lldapApi(
    `mutation CreateUser($user: CreateUserInput!) {
      createUser(user: $user) { id }
    }`,
    {
      user: {
        id: userId,
        email,
        displayName,
      },
    },
  );

  // Set password via LDAP bind as admin, then modify
  // LLDAP does not expose password setting via GraphQL, so use the REST API
  // Actually, we need to use the LDAP protocol to set password
  // Let's use the LLDAP HTTP API for password setting
  // LLDAP does not have a direct REST endpoint for password, but we can use
  // the admin password reset endpoint
  // Note: LLDAP does not have a public API to set user passwords directly.
  // We use the LDAP protocol to set the password via admin bind.
  const client = new Client({ url: LLDAP_LDAP });
  try {
    await client.bind(ADMIN_DN, ADMIN_PASS);
    const userDN = `uid=${userId},ou=people,${BASE_DN}`;
    await client.modify(userDN, [
      {
        operation: 'replace',
        modification: {
          userPassword: password,
        },
      },
    ]);
  } finally {
    await client.unbind();
  }
};

const createGroup = async (groupName: string) => {
  await lldapApi(
    `mutation CreateGroup($name: String!) {
      createGroup(name: $name) { id }
    }`,
    { name: groupName },
  );
};

const addUserToGroup = async (userId: string, groupId: number) => {
  await lldapApi(
    `mutation AddUserToGroup($userId: String!, $groupId: Int!) {
      addUserToGroup(userId: $userId, groupId: $groupId) { ok }
    }`,
    { userId, groupId },
  );
};

const getGroupId = async (groupName: string): Promise<number> => {
  const data = await lldapApi(`{ groups { id displayName } }`);
  const group = data.groups.find((g: { displayName: string }) => g.displayName === groupName);
  if (!group) throw new Error(`Group ${groupName} not found`);
  return group.id;
};

const runE2E = process.env.RUN_LDAP_E2E === '1';
const describeOrSkip = runE2E ? describe : describe.skip;

describeOrSkip('LDAP E2E with LLDAP', () => {
  beforeAll(async () => {
    // Get auth token
    authToken = await getAuthToken();

    // Seed test data: create users and groups
    try {
      await createUser('testuser', 'testuser@example.com', 'Test User', 'testpassword');
    } catch {
      // user may already exist from previous run
    }
    try {
      await createUser('nongroupuser', 'nogroup@example.com', 'No Group User', 'nogroup123');
    } catch {
      // user may already exist
    }

    try {
      await createGroup('git-users');
    } catch {
      // group may already exist
    }
    try {
      await createGroup('git-admins');
    } catch {
      // group may already exist
    }

    // Add testuser to both groups
    const usersGroupId = await getGroupId('git-users');
    const adminsGroupId = await getGroupId('git-admins');

    try {
      await addUserToGroup('testuser', usersGroupId);
    } catch {
      // may already be member
    }
    try {
      await addUserToGroup('testuser', adminsGroupId);
    } catch {
      // may already be member
    }
    // nongroupuser is intentionally NOT added to any group
  });

  afterAll(async () => {
    // Cleanup is left to docker compose down
  });

  it('should bind and search with service account', async () => {
    const client = new Client({ url: LLDAP_LDAP });
    try {
      await client.bind(ADMIN_DN, ADMIN_PASS);

      const { searchEntries } = await client.search(`ou=people,${BASE_DN}`, {
        scope: 'sub',
        filter: '(uid=testuser)',
      });

      expect(searchEntries.length).toBe(1);
      expect(searchEntries[0].uid).toBe('testuser');
      expect(searchEntries[0].mail).toBe('testuser@example.com');
    } finally {
      await client.unbind();
    }
  });

  it('should authenticate user with valid credentials via user bind', async () => {
    const client = new Client({ url: LLDAP_LDAP });
    try {
      // First search for user DN
      await client.bind(ADMIN_DN, ADMIN_PASS);
      const { searchEntries } = await client.search(`ou=people,${BASE_DN}`, {
        scope: 'sub',
        filter: '(uid=testuser)',
      });
      expect(searchEntries.length).toBe(1);
      const userDN = searchEntries[0].dn as string;
      await client.unbind();

      // Then bind as user to verify password
      const userClient = new Client({ url: LLDAP_LDAP });
      try {
        await userClient.bind(userDN, 'testpassword');
        // If we get here, auth succeeded
        expect(true).toBe(true);
      } finally {
        await userClient.unbind();
      }
    } finally {
      try {
        await client.unbind();
      } catch {
        // already unbound
      }
    }
  });

  it('should reject user with invalid password', async () => {
    const client = new Client({ url: LLDAP_LDAP });
    try {
      await client.bind(ADMIN_DN, ADMIN_PASS);
      const { searchEntries } = await client.search(`ou=people,${BASE_DN}`, {
        scope: 'sub',
        filter: '(uid=testuser)',
      });
      const userDN = searchEntries[0].dn as string;
      await client.unbind();

      const userClient = new Client({ url: LLDAP_LDAP });
      try {
        await userClient.bind(userDN, 'wrongpassword');
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message || err.toString()).toContain('Invalid');
      } finally {
        try {
          await userClient.unbind();
        } catch {
          // may fail if bind failed
        }
      }
    } finally {
      try {
        await client.unbind();
      } catch {
        // already unbound
      }
    }
  });

  it('should verify group membership via LDAP search', async () => {
    const client = new Client({ url: LLDAP_LDAP });
    try {
      await client.bind(ADMIN_DN, ADMIN_PASS);

      // Search for user DN
      const { searchEntries: userEntries } = await client.search(`ou=people,${BASE_DN}`, {
        scope: 'sub',
        filter: '(uid=testuser)',
      });
      const userDN = userEntries[0].dn as string;

      // Check group membership - search for groups containing this user
      const { searchEntries: groupEntries } = await client.search(`ou=groups,${BASE_DN}`, {
        scope: 'sub',
        filter: `(member=${userDN})`,
      });

      const groupNames = groupEntries.map((e) => e.cn);
      expect(groupNames).toContain('git-users');
      expect(groupNames).toContain('git-admins');
    } finally {
      await client.unbind();
    }
  });

  it('should confirm nongroupuser is not in git-users group', async () => {
    const client = new Client({ url: LLDAP_LDAP });
    try {
      await client.bind(ADMIN_DN, ADMIN_PASS);

      const { searchEntries: userEntries } = await client.search(`ou=people,${BASE_DN}`, {
        scope: 'sub',
        filter: '(uid=nongroupuser)',
      });
      const userDN = userEntries[0].dn as string;

      const { searchEntries: groupEntries } = await client.search(`ou=groups,${BASE_DN}`, {
        scope: 'sub',
        filter: `(member=${userDN})`,
      });

      const groupNames = groupEntries.map((e) => e.cn);
      expect(groupNames).not.toContain('git-users');
      expect(groupNames).not.toContain('git-admins');
    } finally {
      await client.unbind();
    }
  });
});
