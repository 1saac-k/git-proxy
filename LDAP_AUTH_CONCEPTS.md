# LDAP Authentication - 개념 설명서

이 문서는 LDAP 인증 구현과 관련된 핵심 개념을 설명합니다.

---

## 1. LDAP란?

**LDAP** (Lightweight Directory Access Protocol)은 디렉터리 서비스에 접근하기 위한 프로토콜입니다.
디렉터리 서비스란 사용자, 그룹, 장치 등의 정보를 계층적 트리 구조로 저장하는 데이터베이스입니다.

- **Active Directory (AD)**: Microsoft가 만든 디렉터리 서비스. LDAP 프로토콜을 사용하지만 AD 전용 확장 기능이 많음
- **LDAP 서버**: AD 외에도 OpenLDAP, 389 Directory Server, LLDAP 등 다양한 구현이 있음
- **핵심 차이**: AD는 LDAP의 상위집합(superset). 순수 LDAP 클라이언트로 AD에 접근 가능하지만, AD 전용 기능(Kerberos, GPO 등)은 사용 불가

### DN (Distinguished Name)

LDAP에서 모든 항목(entry)은 고유한 DN으로 식별됩니다. 파일 시스템의 절대 경로와 비슷합니다.

```
uid=testuser,ou=people,dc=example,dc=com
│           │          └─ 도메인 컴포넌트 (example.com)
│           └─ 조직 단위 (people)
└─ 사용자 ID (testuser)
```

### Base DN

검색의 시작점이 되는 DN입니다. `dc=example,dc=com`은 `example.com` 도메인의 루트를 의미합니다.

---

## 2. LDAP 인증 흐름 (Bind 방식)

LDAP에서 인증은 **bind** 연산으로 수행됩니다. bind는 "이 DN과 비밀번호로 접속하겠다"는 의미입니다.

### git-proxy의 LDAP 인증 순서

```
1. Service Account Bind
   └─ 관리용 계정(bindDN)으로 LDAP 서버에 접속
   └─ 목적: 사용자를 검색할 권한 확보

2. User Search
   └─ 로그인한 username으로 LDAP 검색
   └─ 예: (uid=testuser) 필터로 ou=people,dc=example,dc=com 에서 검색
   └─ 결과: 사용자의 DN과 속성(email, 이름 등) 획득

3. Group Membership Check (서비스 계정으로)
   └─ userGroupDN에 사용자가 속하는지 확인 (필수 그룹)
   └─ adminGroupDN에 사용자가 속하는지 확인 (관리자 권한)

4. User Bind (비밀번호 검증)
   └─ 새 LDAP 연결 생성
   └─ 찾은 사용자 DN + 입력된 비밀번호로 bind 시도
   └─ 성공 = 비밀번호 맞음, 실패 = 틀림

5. DB 동기화
   └─ 인증된 사용자 정보를 git-proxy DB에 저장/업데이트
```

### 왜 두 번 bind하는가?

- **첫 번째 bind (서비스 계정)**: 사용자의 DN을 모르기 때문. `testuser`라는 이름만으로는 `uid=testuser,ou=people,dc=example,dc=com`이라는 전체 DN을 알 수 없음
- **두 번째 bind (사용자 계정)**: 실제 비밀번호 검증. LDAP은 비밀번호를 직접 읽을 수 없고, bind 성공 여부로만 검증 가능

---

## 3. Passport.js 인증 프레임워크

**Passport.js**는 Node.js/Express에서 인증을 처리하는 미들웨어 프레임워크입니다.

### 핵심 개념

- **Strategy (전략)**: 인증 방법을 정의하는 플러그인. 각 인증 방식(로컬, LDAP, OAuth 등)마다 별도 Strategy
- **passport.use(name, strategy)**: Strategy를 이름으로 등록
- **passport.authenticate(name)**: 등록된 Strategy로 인증 수행하는 Express 미들웨어 반환
- **Serialize/Deserialize**: 세션에 사용자 정보를 저장/복원하는 방법 정의

### passport-custom

일반적인 Passport Strategy는 특정 인증 방식에 맞춘 고정된 인터페이스를 가집니다.
`passport-custom`은 이런 제약 없이 Express의 `req` 객체를 직접 받아 자유롭게 인증 로직을 구현할 수 있게 해줍니다.

```typescript
// passport-local: username, password가 고정 파라미터
new LocalStrategy((username, password, done) => { ... });

// passport-custom: req 전체를 받아 자유롭게 처리
new CustomStrategy((req, done) => {
  const { username, password } = req.body;
  // 원하는 인증 로직 구현
});
```

### Serialize / Deserialize

```
로그인 성공 → serializeUser → 세션에 저장할 데이터 결정 (보통 username)
                                    ↓
                              세션 쿠키 발급
                                    ↓
다음 요청 → deserializeUser → 세션에서 username 읽기 → DB에서 사용자 조회 → req.user에 할당
```

---

## 4. ldapts 라이브러리

`ldapts`는 TypeScript로 작성된 모던 LDAP 클라이언트입니다.

### 기존 라이브러리와의 차이

| 특성        | ldapjs (deprecated) | activedirectory2 (deprecated) | ldapts              |
| ----------- | ------------------- | ----------------------------- | ------------------- |
| API 스타일  | 콜백 기반           | 콜백 기반                     | Promise/async-await |
| TypeScript  | 별도 @types 필요    | 별도 @types 필요              | 내장                |
| LDAP 범용성 | 범용                | AD 전용 wrapper               | 범용                |
| 유지보수    | deprecated          | deprecated                    | 활발                |

### 주요 API

```typescript
import { Client } from 'ldapts';

// 연결 생성
const client = new Client({ url: 'ldap://server:389' });

// 인증 (bind)
await client.bind('cn=admin,dc=example,dc=com', 'password');

// 검색
const { searchEntries } = await client.search('ou=people,dc=example,dc=com', {
  scope: 'sub', // sub = 하위 트리 전체 검색
  filter: '(uid=user)', // LDAP 검색 필터
});

// 연결 종료
await client.unbind();
```

### TLS 지원

- **LDAPS**: `ldaps://` URL 사용 → 연결 시점부터 TLS 암호화
- **STARTTLS**: `ldap://`로 연결 후 `client.startTLS()`로 TLS 업그레이드
- `tlsOptions`로 인증서 검증 설정 가능 (`rejectUnauthorized`, `ca` 등)

---

## 5. 그룹 멤버십 검사

LDAP에서 그룹 멤버십을 확인하는 방법은 여러 가지입니다:

### 방법 1: 그룹 엔트리에서 member 속성 검색 (이 구현에서 사용)

```
검색 대상: ou=groups,dc=example,dc=com
필터: (member=uid=testuser,ou=people,dc=example,dc=com)
→ 이 사용자를 member로 가진 그룹들이 반환됨
```

### 방법 2: 사용자 엔트리의 memberOf 속성 확인

```
사용자 엔트리의 memberOf 속성에 그룹 DN 목록이 있음
→ AD에서는 잘 동작하지만, 모든 LDAP 서버가 지원하지는 않음
```

이 구현에서는 방법 1을 사용합니다. LLDAP 등 경량 LDAP 서버에서도 동작하기 때문입니다.

---

## 6. git-proxy 인증 아키텍처

### Strategy 등록 흐름

```
src/service/passport/index.ts
├── authStrategies 레지스트리에 모든 전략 등록
│   ├── local (passport-local)
│   ├── activedirectory (passport-activedirectory)
│   ├── ldap (passport-custom + ldapts)  ← 새로 추가
│   └── openidconnect (openid-client)
│
├── configure() 함수
│   └── proxy.config.json에서 enabled된 인증 방법만 활성화
│
└── Express 앱 초기화 시 호출됨
```

### 로그인 라우트

```
POST /api/auth/login
    ↓
auth.ts: getLoginStrategy()
    ↓ enabled된 username/password 전략 중 첫 번째 선택
    ↓ (local, activedirectory, ldap 중 하나)
passport.authenticate(strategyType)
    ↓
해당 전략의 verify 콜백 실행
    ↓
성공 시 세션 생성 + 사용자 정보 반환
```

### 설정 예시 (proxy.config.json)

```json
{
  "authentication": [
    { "type": "local", "enabled": false },
    {
      "type": "ldap",
      "enabled": true,
      "ldapConfig": {
        "url": "ldap://ldap.example.com:389",
        "bindDN": "cn=admin,dc=example,dc=com",
        "bindPassword": "admin_password",
        "searchBase": "ou=people,dc=example,dc=com",
        "searchFilter": "(uid={{username}})",
        "userGroupDN": "cn=git-users,ou=groups,dc=example,dc=com",
        "adminGroupDN": "cn=git-admins,ou=groups,dc=example,dc=com",
        "groupSearchBase": "ou=groups,dc=example,dc=com",
        "groupSearchFilter": "(member={{dn}})"
      }
    }
  ]
}
```

---

## 7. LLDAP (E2E 테스트용 경량 LDAP 서버)

**LLDAP**은 인증에 특화된 경량 LDAP 서버입니다.

- 웹 관리 UI 제공 (포트 17170)
- LDAP 프로토콜 지원 (포트 3890)
- Docker로 간편하게 실행
- GraphQL API로 사용자/그룹 관리

### E2E 테스트 실행 방법

```bash
# 1. LLDAP 컨테이너 시작
docker compose -f docker-compose.ldap-test.yml up -d

# 2. E2E 테스트 실행 (LLDAP가 없으면 자동 skip)
npx vitest run test/e2e/ldap-e2e.test.ts

# 3. 정리
docker compose -f docker-compose.ldap-test.yml down
```

### LLDAP의 LDAP 구조

```
dc=example,dc=com (Base DN)
├── ou=people
│   ├── uid=admin (기본 관리자)
│   └── uid=testuser (테스트 사용자)
└── ou=groups
    ├── cn=git-users
    └── cn=git-admins
```

---

## 8. 파일별 역할 요약

| 파일                                          | 역할                                           |
| --------------------------------------------- | ---------------------------------------------- |
| `src/service/passport/ldap.ts`                | LDAP 인증 전략 구현 (ldapts + passport-custom) |
| `src/service/passport/index.ts`               | 전략 레지스트리, 초기화                        |
| `src/service/routes/auth.ts`                  | 로그인/로그아웃 API 엔드포인트                 |
| `src/config/generated/config.ts`              | 설정 타입 정의 (LdapConfig 인터페이스)         |
| `config.schema.json`                          | JSON Schema (설정 유효성 검사)                 |
| `proxy.config.json`                           | 기본 설정 파일                                 |
| `test/services/passport/testLdapAuth.test.ts` | 단위 테스트 (mock 사용)                        |
| `test/e2e/ldap-e2e.test.ts`                   | E2E 테스트 (실제 LLDAP 서버)                   |
| `docker-compose.ldap-test.yml`                | LLDAP 테스트 환경 구성                         |
