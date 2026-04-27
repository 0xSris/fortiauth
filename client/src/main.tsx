import React, { FormEvent, ReactNode, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Check,
  Command,
  Fingerprint,
  KeyRound,
  Lock,
  LogOut,
  Monitor,
  Radar,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  Terminal,
  UserRound,
  X,
} from 'lucide-react';
import './styles.css';

type User = {
  id: number;
  username: string;
  email: string;
  role: 'user' | 'admin';
  last_login?: number;
  created_at?: number;
  mfa_enabled?: number;
};

type PostureItem = { key: string; label: string; status: 'pass' | 'warn' | 'fail'; detail: string };
type Overview = {
  risk: number;
  riskLevel: string;
  posture: PostureItem[];
  mfa: { enabled: boolean; backupCodesRemaining: number };
  sessions: unknown[];
  threatSignals: { failures24h: number; uniqueIps: number; activeSessions: number };
};
type Session = { id: string; user_agent?: string; ip_address?: string; created_at: number; current?: boolean };
type AuditEvent = { id: number; event_type: string; user_id?: number; ip_address?: string; metadata?: string; created_at: number };
type AdminStats = {
  totalUsers: number;
  mfaAdoption: number;
  failures24h: number;
  privilegeAttempts: number;
  refreshRotations: number;
  postureScore: number;
  activeSessions: number;
};
type AiAnswer = { answer: string; model: string; usage?: { total_tokens?: number; prompt_tokens?: number; completion_tokens?: number } | null };
type DemoScenario = { id: string; title: string; severity: string; result: string };
type DemoSimulation = { id: string; title: string; severity: string; auditEvent: string; result: string; steps: { order: number; status: string; text: string }[] };
type SecurityReport = {
  generatedAt: number;
  executiveSummary: string;
  risk: { score: number; level: string };
  controls: { name: string; status: string; evidence: string }[];
  recommendations: { control: string; action: string }[];
  demoScript: string[];
};
type SecurityIntelligence = {
  grade: { grade: string; score: number; risk: number; level: string };
  timeline: { at: number; event: string; score: number }[];
  checklist: { key: string; label: string; done: boolean; impact: string }[];
  recoveryVault: { mfaEnabled: boolean; backupCodesRemaining: number; status: string; lastRotatedAt: number | null };
  devices: { sessionId: string; trust: string; score: number; device: { browser: string; os: string }; ipAddress: string; ageHours: number }[];
};
type AdminPolicy = { requireMfaForAdmins: boolean; lockoutThreshold: number; sessionMaxHours: number; staleSessionHours: number; emailOtpTtlMinutes: number; riskAlertThreshold: number };
type Incident = { id: number; type: string; title: string; severity: string; count: number; lastEventAt: number; status: string };

const fmt = (ts?: number) => (ts ? new Date(ts * 1000).toLocaleString() : 'never');
const currentRoute = () => (window.location.pathname === '/' ? '/login' : window.location.pathname);
const auditEvents = ['LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGOUT', 'REGISTER', 'MFA_ENABLED', 'MFA_DISABLED', 'MFA_SUCCESS', 'MFA_FAILURE', 'PASSWORD_CHANGED', 'PASSWORD_RESET_REQUEST', 'PASSWORD_RESET_SUCCESS', 'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'PRIVILEGE_ESCALATION_ATTEMPT', 'ADMIN_ACTION', 'TOKEN_REFRESH', 'SESSION_REVOKED', 'INVALID_TOKEN_ATTEMPT'];
const deployedApiBaseUrl = window.location.hostname.endsWith('.vercel.app') ? 'https://secureos-api.onrender.com' : '';
const apiBaseUrl = String((import.meta as any).env?.VITE_API_BASE_URL || deployedApiBaseUrl).replace(/\/$/, '');
const apiUrl = (path: string) => `${apiBaseUrl}${path}`;

const API = {
  token: localStorage.getItem('accessToken') || '',
  user: JSON.parse(localStorage.getItem('user') || 'null') as User | null,
  async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) } as Record<string, string>;
    if (API.token) headers.Authorization = `Bearer ${API.token}`;
    const response = await fetch(apiUrl(path), { credentials: 'include', ...options, headers });
    const body = await response.json().catch(() => ({}));
    if (response.status === 401 && path !== '/api/auth/refresh') {
      const refreshed = await API.refresh();
      if (refreshed) return API.request<T>(path, options);
    }
    if (!response.ok) throw Object.assign(new Error(body.error || 'Request failed'), { body, status: response.status });
    return body as T;
  },
  async refresh() {
    try {
      const response = await fetch(apiUrl('/api/auth/refresh'), { method: 'POST', credentials: 'include' });
      if (!response.ok) throw new Error('refresh failed');
      const body = await response.json();
      API.setToken(body.accessToken);
      return true;
    } catch {
      API.setToken('', null);
      return false;
    }
  },
  setToken(token: string, user?: User | null) {
    API.token = token || '';
    if (token) localStorage.setItem('accessToken', token);
    else localStorage.removeItem('accessToken');
    if (user) {
      API.user = user;
      localStorage.setItem('user', JSON.stringify(user));
    }
    if (!token && user === null) {
      API.user = null;
      localStorage.removeItem('user');
    }
  },
};

function App() {
  const [path, setPath] = useState(currentRoute());
  const [user, setUser] = useState<User | null>(API.user);
  const [toast, setToast] = useState('');

  useEffect(() => {
    const onPop = () => setPath(currentRoute());
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const nav = (next: string) => {
    history.pushState({}, '', next);
    setPath(next);
  };
  const notify = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(''), 2800);
  };
  const syncUser = (next: User | null) => {
    setUser(next);
    API.user = next;
    if (next) localStorage.setItem('user', JSON.stringify(next));
  };
  const logout = async () => {
    await API.request('/api/auth/logout', { method: 'POST' }).catch(() => undefined);
    API.setToken('', null);
    syncUser(null);
    nav('/login');
  };

  return (
    <div className="product-shell">
      <Topbar user={user} nav={nav} logout={logout} />
      <AnimatePresence mode="wait">
        <motion.main key={path} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.28, ease: 'easeOut' }}>
          {path === '/register' && <Register nav={nav} notify={notify} />}
          {path === '/forgot' && <Forgot notify={notify} />}
          {path === '/reset' && <Reset nav={nav} notify={notify} />}
          {path === '/dashboard' && <Protected nav={nav} setUser={syncUser}><SecurityConsole user={user} setUser={syncUser} notify={notify} /></Protected>}
          {path === '/admin' && <Protected nav={nav} setUser={syncUser}><AdminConsole user={user} nav={nav} notify={notify} /></Protected>}
          {!['/register', '/forgot', '/reset', '/dashboard', '/admin'].includes(path) && <Login nav={nav} setUser={syncUser} notify={notify} />}
        </motion.main>
      </AnimatePresence>
      <AnimatePresence>{toast && <motion.div className="toast" initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>{toast}</motion.div>}</AnimatePresence>
    </div>
  );
}

function Topbar({ user, nav, logout }: { user: User | null; nav: (path: string) => void; logout: () => void }) {
  return (
    <header className="topbar">
      <button className="wordmark" onClick={() => nav(user ? '/dashboard' : '/login')}>
        <ShieldCheck size={22} />
        <span>SecureOS</span>
        <em>{user ? 'Identity plane' : 'Authentication framework'}</em>
      </button>
      <nav className="top-actions">
        {user && <button onClick={() => nav('/dashboard')}>Console</button>}
        {user?.role === 'admin' && <button onClick={() => nav('/admin')}>Governance</button>}
        {user && <span className="system-pill">Live - protected</span>}
        {user && <button className="avatar" title={user.email}>{user.username.slice(0, 2).toUpperCase()}</button>}
        {user && <button className="quiet-action" onClick={logout}><LogOut size={16} /> Logout</button>}
      </nav>
    </header>
  );
}

function Protected({ children, nav, setUser }: { children: ReactNode; nav: (path: string) => void; setUser: (user: User | null) => void }) {
  const [ready, setReady] = useState(Boolean(API.token));
  useEffect(() => {
    (async () => {
      if (!API.token && !(await API.refresh())) return nav('/login');
      const me = await API.request<{ user: User }>('/api/user/me').catch(() => null);
      if (!me) return nav('/login');
      setUser(me.user);
      setReady(true);
    })();
  }, []);
  return ready ? <>{children}</> : <SystemTrace title="Restoring secure session" steps={['validating refresh cookie', 'rotating token material', 'hydrating identity plane']} />;
}

function AuthSurface({ mode, title, subtitle, children }: { mode: string; title: string; subtitle: string; children: ReactNode }) {
  return (
    <section className="auth-surface">
      <div className="hero-copy">
        <span className="context-pill"><Sparkles size={14} /> Real-time - hardened - audited</span>
        <h1>{title}</h1>
        <p>{subtitle}</p>
        <div className="inline-metrics">
          <span>Argon2id <b>active</b></span>
          <span>JWT TTL <b>15m</b></span>
          <span>Refresh rotation <b>strict</b></span>
        </div>
        <InsightStream items={[
          ['00:01', 'Body limit enforced at 10kb'],
          ['00:02', 'Role resolved from database only'],
          ['00:03', `${mode} flow audit hooks armed`],
        ]} />
      </div>
      <div className="command-stage">{children}</div>
    </section>
  );
}

function Login({ nav, setUser, notify }: { nav: (path: string) => void; setUser: (user: User | null) => void; notify: (message: string) => void }) {
  const [tempToken, setTempToken] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const form = new FormData(event.currentTarget);
      const response = tempToken
        ? await API.request<{ accessToken: string; user: User }>('/api/auth/mfa/login', { method: 'POST', body: JSON.stringify({ tempToken, code: mfaCode }) })
        : await API.request<{ accessToken?: string; user?: User; requiresMfa?: boolean; tempToken?: string }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: form.get('username'), password: form.get('password') }) });
      if ('requiresMfa' in response && response.requiresMfa && response.tempToken) {
        setTempToken(response.tempToken);
        return;
      }
      if (response.accessToken && response.user) {
        API.setToken(response.accessToken, response.user);
        setUser(response.user);
        notify('Secure session established');
        nav('/dashboard');
      }
    } catch (err: any) {
      setError(err.body?.error || err.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <AuthSurface mode="access" title="Access security that feels invisible until it matters." subtitle="A calm authentication plane for OS-level identity, MFA enforcement, refresh rotation, and session revocation.">
      <form className="command-form" onSubmit={submit}>
        <label>
          <span>{tempToken ? 'MFA challenge' : 'Identity'}</span>
          {tempToken ? <input value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} maxLength={8} placeholder="6-digit TOTP or backup code" /> : <input name="username" maxLength={254} placeholder="username or email" />}
        </label>
        {!tempToken && <label><span>Credential</span><input name="password" type="password" maxLength={128} placeholder="password" /></label>}
        <FormError text={error} />
        <button className="primary-command" disabled={busy}>{busy ? 'Securing...' : tempToken ? 'Verify second factor' : 'Continue'} <ArrowRight size={18} /></button>
        <div className="suggestions"><button type="button" onClick={() => nav('/register')}>Create identity</button><button type="button" onClick={() => nav('/forgot')}>Recover access</button></div>
      </form>
    </AuthSurface>
  );
}

function Register({ nav, notify }: { nav: (path: string) => void; notify: (message: string) => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const score = useMemo(() => [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((rule) => rule.test(password)).length + (password.length >= 12 ? 1 : 0), [password]);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    try {
      const form = new FormData(event.currentTarget);
      if (form.get('password') !== form.get('confirmPassword')) throw new Error('Passwords do not match');
      await API.request('/api/auth/register', { method: 'POST', body: JSON.stringify(Object.fromEntries(form)) });
      notify('Identity provisioned');
      nav('/login');
    } catch (err: any) {
      setError(err.body?.error || err.message);
    }
  };
  return (
    <AuthSurface mode="provisioning" title="Provision a hardened identity without the noise." subtitle="Strict validation, Argon2id hashing, common-password screening, and audit logging by default.">
      <form className="command-form" onSubmit={submit}>
        <label><span>Username</span><input name="username" maxLength={32} placeholder="srishti" /></label>
        <label><span>Email</span><input name="email" type="email" maxLength={254} placeholder="name@example.com" /></label>
        <label><span>Password</span><input name="password" type="password" maxLength={128} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="strong password" /></label>
        <div className="strength-line"><span style={{ width: `${Math.min(score, 5) * 20}%` }} /></div>
        <p className="microcopy">{['weak', 'basic', 'fair', 'strong', 'fortified', 'fortified'][score]} policy posture</p>
        <label><span>Confirm</span><input name="confirmPassword" type="password" maxLength={128} placeholder="repeat password" /></label>
        <FormError text={error} />
        <button className="primary-command">Create identity <ArrowRight size={18} /></button>
      </form>
    </AuthSurface>
  );
}

function Forgot({ notify }: { notify: (message: string) => void }) {
  const [token, setToken] = useState('');
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const response = await API.request<{ resetToken?: string }>('/api/auth/password-reset/request', { method: 'POST', body: JSON.stringify({ email: form.get('email') }) });
    setToken(response.resetToken || '');
    notify('Reset request recorded');
  };
  return (
    <AuthSurface mode="recovery" title="Recover access with single-use reset material." subtitle="Reset tokens are hashed before storage, expire in one hour, and revoke sessions after use.">
      <form className="command-form" onSubmit={submit}>
        <label><span>Email</span><input name="email" type="email" maxLength={254} placeholder="name@example.com" /></label>
        <button className="primary-command">Request reset <RefreshCw size={18} /></button>
        {token && <p className="microcopy">Development token: <code>{token}</code></p>}
      </form>
    </AuthSurface>
  );
}

function Reset({ nav, notify }: { nav: (path: string) => void; notify: (message: string) => void }) {
  const [error, setError] = useState('');
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    try {
      const form = new FormData(event.currentTarget);
      if (form.get('password') !== form.get('confirmPassword')) throw new Error('Passwords do not match');
      await API.request('/api/auth/password-reset/confirm', { method: 'POST', body: JSON.stringify({ token: new URLSearchParams(location.search).get('token') || '', password: form.get('password') }) });
      notify('Credential replaced');
      nav('/login');
    } catch (err: any) {
      setError(err.body?.error || err.message);
    }
  };
  return (
    <AuthSurface mode="reset" title="Replace the credential and close every session." subtitle="A successful reset invalidates active sessions and clears lockout state.">
      <form className="command-form" onSubmit={submit}>
        <label><span>New password</span><input name="password" type="password" maxLength={128} /></label>
        <label><span>Confirm password</span><input name="confirmPassword" type="password" maxLength={128} /></label>
        <FormError text={error} />
        <button className="primary-command">Reset password <Lock size={18} /></button>
      </form>
    </AuthSurface>
  );
}

function SecurityConsole({ user, setUser, notify }: { user: User | null; setUser: (user: User | null) => void; notify: (message: string) => void }) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [setup, setSetup] = useState<{ qrCodeDataUrl?: string; backupCodes?: string[]; secret?: string } | null>(null);
  const [code, setCode] = useState('');
  const [command, setCommand] = useState('');
  const [output, setOutput] = useState('Ask anything about your authentication posture.');
  const [aiMeta, setAiMeta] = useState('');
  const [asking, setAsking] = useState(false);
  const [scenarios, setScenarios] = useState<DemoScenario[]>([]);
  const [simulation, setSimulation] = useState<DemoSimulation | null>(null);
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [intel, setIntel] = useState<SecurityIntelligence | null>(null);
  const [emailOtp, setEmailOtp] = useState('');
  const [emailOtpStatus, setEmailOtpStatus] = useState('');

  const reload = async () => {
    const [me, security, sessionBody, intelligence] = await Promise.all([
      API.request<{ user: User }>('/api/user/me'),
      API.request<{ overview: Overview }>('/api/user/security-overview'),
      API.request<{ sessions: Session[]; currentSessionId: string }>('/api/user/sessions'),
      API.request<{ grade: SecurityIntelligence['grade']; timeline: SecurityIntelligence['timeline']; checklist: SecurityIntelligence['checklist']; recoveryVault: SecurityIntelligence['recoveryVault']; devices: SecurityIntelligence['devices'] }>('/api/user/security-intelligence'),
    ]);
    setUser(me.user);
    setOverview(security.overview);
    setSessions(sessionBody.sessions.map((session) => ({ ...session, current: session.id === sessionBody.currentSessionId })));
    setIntel(intelligence);
    const showcase = await API.request<{ scenarios: DemoScenario[] }>('/api/user/demo/showcase');
    setScenarios(showcase.scenarios);
  };
  useEffect(() => { reload(); }, []);

  const ask = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const question = command.trim();
    if (!question) return;
    setAsking(true);
    setAiMeta('thinking');
    setOutput('SecureOS AI is analyzing your security context...');
    try {
      const response = await API.request<AiAnswer>('/api/user/ai/ask', { method: 'POST', body: JSON.stringify({ question }) });
      setOutput(response.answer || 'No answer returned.');
      setAiMeta(`${response.model}${response.usage?.total_tokens ? ` - ${response.usage.total_tokens} tokens` : ''}`);
    } catch (err: any) {
      let message = err.body?.error || err.message;
      if (err.body?.code === 'GROQ_NOT_CONFIGURED') {
        message = 'Groq is not configured yet. Add GROQ_API_KEY to your .env and restart the server.';
      }
      if (err.body?.code === 'NOT_FOUND') {
        message = 'The AI route is not loaded in the running server. Stop the current Node process, run npm run build, then restart with npm start.';
      }
      setOutput(message);
      setAiMeta('request failed');
    } finally {
      setAsking(false);
    }
  };
  const mfaAction = async () => {
    if (!user?.mfa_enabled && !setup) {
      setSetup(await API.request('/api/auth/mfa/setup', { method: 'POST' }));
      return;
    }
    await API.request(user?.mfa_enabled ? '/api/auth/mfa/disable' : '/api/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ code }) });
    setSetup(null); setCode(''); notify(user?.mfa_enabled ? 'MFA disabled' : 'MFA enabled'); reload();
  };
  const rotate = async () => {
    const response = await API.request<{ backupCodes: string[] }>('/api/auth/mfa/backup-codes/rotate', { method: 'POST', body: JSON.stringify({ code }) });
    setSetup({ backupCodes: response.backupCodes }); setCode(''); notify('Backup codes rotated');
  };
  const revoke = async (id: string) => { await API.request(`/api/user/sessions/${id}`, { method: 'DELETE' }); notify('Session revoked'); reload(); };
  const runDemo = async (scenario: string) => {
    const response = await API.request<{ simulation: DemoSimulation }>('/api/user/demo/simulate', { method: 'POST', body: JSON.stringify({ scenario }) });
    setSimulation(response.simulation);
    notify(`${response.simulation.auditEvent} written to audit log`);
  };
  const loadReport = async () => {
    const response = await API.request<{ report: SecurityReport }>('/api/user/security-report');
    setReport(response.report);
    notify('Security report generated');
  };
  const sendEmailOtp = async () => {
    const response = await API.request<{ sent: boolean; reason?: string; developmentOtp?: string; expiresInMinutes: number }>('/api/user/email-otp/send', { method: 'POST', body: JSON.stringify({ purpose: 'demo_verification' }) });
    setEmailOtpStatus(response.sent ? `OTP sent. Expires in ${response.expiresInMinutes} minutes.` : `SMTP not configured. Development OTP: ${response.developmentOtp}`);
  };
  const verifyEmailOtp = async () => {
    await API.request('/api/user/email-otp/verify', { method: 'POST', body: JSON.stringify({ otp: emailOtp, purpose: 'demo_verification' }) });
    setEmailOtp('');
    setEmailOtpStatus('Email OTP verified and audited.');
  };

  if (!overview || !user) return <SystemTrace title="Loading identity plane" steps={['reading session table', 'scoring posture', 'assembling live stream']} />;
  return (
    <section className="flow-page">
      <HeroFirst eyebrow="Real-time - AI-assisted - Live system" title="Authentication security command center" subtitle="A quiet command layer for MFA, session trust, password hygiene, and vulnerability-resistant authentication." action="Review next control" />
      <InlineMetrics items={[['Risk', `${overview.risk}/100`, overview.riskLevel], ['MFA', overview.mfa.enabled ? 'Enforced' : 'Open', overview.mfa.enabled ? 'good' : 'warn'], ['Sessions', String(overview.threatSignals.activeSessions), 'neutral'], ['Threats 24h', String(overview.threatSignals.failures24h), overview.threatSignals.failures24h ? 'warn' : 'good']]} />
      <section className="dominant-area">
        <div className="radar-field">
          <div className="radar-caption"><span>Posture map</span><b>{overview.posture.filter((item) => item.status === 'pass').length}/{overview.posture.length} controls healthy</b></div>
          <div className={`radar-core ${overview.riskLevel}`}><span>{overview.risk}</span><small>{overview.riskLevel}</small></div>
          {overview.posture.map((item, index) => <div key={item.key} className={`orbit-dot ${item.status}`} style={{ '--i': index } as React.CSSProperties}><span>{item.label}</span></div>)}
        </div>
        <div className="flow-rail">
          <CommandLayer command={command} setCommand={setCommand} ask={ask} output={output} aiMeta={aiMeta} asking={asking} />
          <InsightStream items={overview.posture.map((item, index) => [`0${index}:0${index + 1}`, `${item.status.toUpperCase()} - ${item.detail}`])} />
        </div>
      </section>
      <section className="flow-columns">
        <MfaFlow user={user} setup={setup} code={code} setCode={setCode} mfaAction={mfaAction} rotate={rotate} />
        <SessionFlow sessions={sessions} revoke={revoke} />
        <PasswordFlow notify={notify} />
      </section>
      {intel && <IntelligenceLayer intel={intel} emailOtp={emailOtp} setEmailOtp={setEmailOtp} emailOtpStatus={emailOtpStatus} sendEmailOtp={sendEmailOtp} verifyEmailOtp={verifyEmailOtp} />}
      <section className="demo-layer">
        <DemoLab scenarios={scenarios} simulation={simulation} runDemo={runDemo} />
        <ReportBrief report={report} loadReport={loadReport} />
      </section>
    </section>
  );
}

function AdminConsole({ user, nav, notify }: { user: User | null; nav: (path: string) => void; notify: (message: string) => void }) {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [filter, setFilter] = useState('');
  const [search, setSearch] = useState('');
  const [policy, setPolicy] = useState<AdminPolicy | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [incidentAnswer, setIncidentAnswer] = useState('');
  const load = async () => {
    if (user?.role !== 'admin') return nav('/dashboard');
    const [posture, userBody, auditBody, policyBody, incidentBody] = await Promise.all([
      API.request<{ stats: AdminStats }>('/api/admin/security-posture'),
      API.request<{ users: any[] }>(`/api/admin/users?search=${encodeURIComponent(search)}`),
      API.request<{ events: AuditEvent[] }>(`/api/admin/audit-log?event_type=${encodeURIComponent(filter)}`),
      API.request<{ policy: AdminPolicy }>('/api/admin/policy'),
      API.request<{ incidents: Incident[] }>('/api/admin/incidents'),
    ]);
    setStats(posture.stats); setUsers(userBody.users); setAudit(auditBody.events);
    setPolicy(policyBody.policy); setIncidents(incidentBody.incidents);
  };
  useEffect(() => { load(); }, [search, filter]);
  const unlock = async (id: number) => { await API.request(`/api/admin/users/${id}/unlock`, { method: 'POST' }); notify('Account unlocked'); load(); };
  const updatePolicy = async (key: keyof AdminPolicy, value: boolean | number) => {
    const response = await API.request<{ policy: AdminPolicy }>('/api/admin/policy', { method: 'PUT', body: JSON.stringify({ [key]: value }) });
    setPolicy(response.policy); notify('Policy updated');
  };
  const explainIncident = async (incidentId: number) => {
    const response = await API.request<AiAnswer>('/api/admin/incidents/explain', { method: 'POST', body: JSON.stringify({ incidentId }) });
    setIncidentAnswer(response.answer);
  };
  if (!stats) return <SystemTrace title="Loading governance plane" steps={['querying audit stream', 'calculating adoption', 'checking escalation attempts']} />;
  return (
    <section className="flow-page">
      <HeroFirst eyebrow="Governance - audit-backed - live" title="Security posture without dashboard noise." subtitle="One continuous view for identity inventory, MFA adoption, lockouts, token rotations, and escalation attempts." action="Investigate signal" />
      <InlineMetrics items={[['Posture', `${stats.postureScore}%`, 'good'], ['MFA adoption', `${stats.mfaAdoption}%`, 'good'], ['Failures 24h', String(stats.failures24h), stats.failures24h ? 'warn' : 'good'], ['Privilege attempts', String(stats.privilegeAttempts), stats.privilegeAttempts ? 'warn' : 'good']]} />
      <section className="dominant-area admin-flow">
        <div className="governance-feed">
          <div className="stream-header"><span>Audit stream</span><select value={filter} onChange={(e) => setFilter(e.target.value)}><option value="">All events</option>{auditEvents.map((event) => <option key={event}>{event}</option>)}</select></div>
          <InsightStream items={audit.map((event) => [fmt(event.created_at), `${event.event_type} - user ${event.user_id || 'anonymous'} - ${event.ip_address || 'unknown IP'}`])} />
        </div>
        <div className="identity-list">
          <label className="search-line"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search identity inventory" /></label>
          {users.map((row) => <div className="identity-row" key={row.id}><div><strong>{row.username}</strong><span>{row.email}</span></div><em>{row.role}</em><span>{row.mfa_enabled ? 'MFA on' : 'MFA off'}</span><button disabled={!row.is_locked} onClick={() => unlock(row.id)}>{row.is_locked ? 'Unlock' : 'Active'}</button></div>)}
        </div>
      </section>
      {policy && <AdminIntelligence policy={policy} updatePolicy={updatePolicy} incidents={incidents} explainIncident={explainIncident} incidentAnswer={incidentAnswer} />}
    </section>
  );
}

function HeroFirst({ eyebrow, title, subtitle, action }: { eyebrow: string; title: string; subtitle: string; action: string }) {
  return (
    <section className="hero-first">
      <span className="context-pill"><Sparkles size={14} /> {eyebrow}</span>
      <h1>{title}</h1>
      <p>{subtitle}</p>
      <button className="primary-command">{action} <ArrowRight size={18} /></button>
    </section>
  );
}

function InlineMetrics({ items }: { items: [string, string, string][] }) {
  return <div className="inline-data">{items.map(([label, value, tone]) => <span key={label}>{label}: <b className={tone}>{value}</b></span>)}</div>;
}

function CommandLayer({ command, setCommand, ask, output, aiMeta, asking }: { command: string; setCommand: (value: string) => void; ask: (event: FormEvent<HTMLFormElement>) => void | Promise<void>; output: string; aiMeta: string; asking: boolean }) {
  return (
    <form className="ask-layer" onSubmit={ask}>
      <label><Command size={17} /><input value={command} onChange={(event) => setCommand(event.target.value)} placeholder="Ask anything..." /></label>
      <div className="suggestions"><button type="button" onClick={() => setCommand('explain my MFA posture')}>MFA posture</button><button type="button" onClick={() => setCommand('summarize session risk')}>Session risk</button><button type="button" onClick={() => setCommand('what is my risk score')}>Risk score</button></div>
      <button className="ask-submit" disabled={asking}>{asking ? 'Asking Groq...' : 'Ask AI'}</button>
      {aiMeta && <span className="ai-meta">{aiMeta}</span>}
      <div className="system-output"><Terminal size={15} /><AIResponse text={output} /></div>
    </form>
  );
}

function MfaFlow({ user, setup, code, setCode, mfaAction, rotate }: { user: User; setup: { qrCodeDataUrl?: string; backupCodes?: string[]; secret?: string } | null; code: string; setCode: (value: string) => void; mfaAction: () => void; rotate: () => void }) {
  return <FlowSection icon={<Fingerprint />} label="MFA enforcement"><p>{user.mfa_enabled ? 'Second factor is enforced for this identity.' : 'Enroll TOTP to remove password-only access.'}</p>{setup?.qrCodeDataUrl && <img className="qr" src={setup.qrCodeDataUrl} alt="TOTP QR" />}{setup?.backupCodes && <div className="code-strip">{setup.backupCodes.map((item) => <code key={item}>{item}</code>)}</div>}<input value={code} onChange={(event) => setCode(event.target.value)} placeholder="TOTP code" maxLength={6} /><button onClick={mfaAction}>{user.mfa_enabled ? 'Disable MFA' : setup ? 'Verify and enable' : 'Start enrollment'}</button>{user.mfa_enabled && <button onClick={rotate}>Rotate backup codes</button>}</FlowSection>;
}

function SessionFlow({ sessions, revoke }: { sessions: Session[]; revoke: (id: string) => void }) {
  return <FlowSection icon={<Radar />} label="Session trust">{sessions.map((session) => <div className="line-item" key={session.id}><div><strong>{session.user_agent || 'Unknown device'}</strong><span>{session.ip_address} - {fmt(session.created_at)}</span></div><button disabled={session.current} onClick={() => revoke(session.id)}>{session.current ? 'Current' : 'Revoke'}</button></div>)}</FlowSection>;
}

function PasswordFlow({ notify }: { notify: (message: string) => void }) {
  const [error, setError] = useState('');
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('');
    try { await API.request('/api/user/me/password', { method: 'PUT', body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget))) }); event.currentTarget.reset(); notify('Password updated'); }
    catch (err: any) { setError(err.body?.error || err.message); }
  };
  return <FlowSection icon={<KeyRound />} label="Credential hygiene"><form className="inline-form" onSubmit={submit}><input name="currentPassword" type="password" placeholder="Current password" /><input name="password" type="password" placeholder="New password" /><FormError text={error} /><button>Update hash</button></form></FlowSection>;
}

function IntelligenceLayer({ intel, emailOtp, setEmailOtp, emailOtpStatus, sendEmailOtp, verifyEmailOtp }: { intel: SecurityIntelligence; emailOtp: string; setEmailOtp: (value: string) => void; emailOtpStatus: string; sendEmailOtp: () => void; verifyEmailOtp: () => void }) {
  const currentTimeline = intel.timeline.length ? intel.timeline[intel.timeline.length - 1] : null;
  return (
    <section className="intelligence-layer">
      <FlowSection icon={<ShieldCheck />} label="Security grade"><div className="grade-mark">{intel.grade.grade}<span>{intel.grade.score}/100</span></div><InsightStream items={intel.checklist.map((item) => [item.done ? 'done' : 'open', `${item.label} - ${item.impact}`])} /></FlowSection>
      <FlowSection icon={<Activity />} label="Risk timeline"><div className="timeline-line">{intel.timeline.slice(-8).map((point) => <span key={`${point.at}-${point.event}`} style={{ height: `${Math.max(12, point.score)}%` }} title={`${point.event}: ${point.score}`} />)}</div><p>{currentTimeline?.event.replace(/_/g, ' ').toLowerCase()} - current score {currentTimeline?.score}</p></FlowSection>
      <FlowSection icon={<Monitor />} label="Device trust">{intel.devices.slice(0, 3).map((device) => <div className="mini-row" key={device.sessionId}><strong>{device.device.browser} on {device.device.os}</strong><span>{device.trust} - {device.score}/100 - {device.ipAddress}</span></div>)}</FlowSection>
      <FlowSection icon={<KeyRound />} label="Recovery vault"><p>{intel.recoveryVault.backupCodesRemaining} backup codes - {intel.recoveryVault.status}</p><div className="inline-form"><button onClick={sendEmailOtp}>Send email OTP</button><input value={emailOtp} onChange={(event) => setEmailOtp(event.target.value)} maxLength={6} placeholder="Email OTP" /><button onClick={verifyEmailOtp}>Verify OTP</button>{emailOtpStatus && <span>{emailOtpStatus}</span>}</div></FlowSection>
    </section>
  );
}

function AdminIntelligence({ policy, updatePolicy, incidents, explainIncident, incidentAnswer }: { policy: AdminPolicy; updatePolicy: (key: keyof AdminPolicy, value: boolean | number) => void; incidents: Incident[]; explainIncident: (incidentId: number) => void; incidentAnswer: string }) {
  return (
    <section className="intelligence-layer admin-intel">
      <FlowSection icon={<Lock />} label="Policy engine">
        <label className="policy-toggle"><span>Require MFA for admins</span><input type="checkbox" checked={policy.requireMfaForAdmins} onChange={(event) => updatePolicy('requireMfaForAdmins', event.target.checked)} /></label>
        <label className="policy-toggle"><span>Lockout threshold</span><input type="number" min={3} max={10} value={policy.lockoutThreshold} onChange={(event) => updatePolicy('lockoutThreshold', Number(event.target.value))} /></label>
        <label className="policy-toggle"><span>Risk alert threshold</span><input type="number" min={40} max={95} value={policy.riskAlertThreshold} onChange={(event) => updatePolicy('riskAlertThreshold', Number(event.target.value))} /></label>
      </FlowSection>
      <FlowSection icon={<AlertTriangle />} label="Incident queue">
        {incidents.length ? incidents.slice(0, 5).map((incident) => <div className="mini-row" key={incident.id}><strong>{incident.title}</strong><span>{incident.severity} - {incident.count} event(s)</span><button onClick={() => explainIncident(incident.id)}>Explain</button></div>) : <p>No active incidents.</p>}
      </FlowSection>
      <FlowSection icon={<Sparkles />} label="AI incident explainer">{incidentAnswer ? <AIResponse text={incidentAnswer} /> : <p>Select an incident to generate administrator guidance.</p>}</FlowSection>
    </section>
  );
}

function DemoLab({ scenarios, simulation, runDemo }: { scenarios: DemoScenario[]; simulation: DemoSimulation | null; runDemo: (scenario: string) => void }) {
  return (
    <section className="demo-lab">
      <div className="demo-intro">
        <span className="context-pill"><Shield size={14} /> Security lab</span>
        <h2>Run a controlled attack simulation.</h2>
        <p>Select a scenario to trace the defensive path and write the corresponding audit event.</p>
      </div>
      <div className="demo-stage">
        <div className="scenario-strip">
          {scenarios.map((scenario) => <button className={simulation?.id === scenario.id ? 'active' : ''} key={scenario.id} onClick={() => runDemo(scenario.id)}><strong>{scenario.title}</strong><span>{scenario.severity}</span></button>)}
        </div>
        <div className="simulation-output">
          {simulation ? <>
            <div className="simulation-header"><span>{simulation.severity}</span><strong>{simulation.title}</strong><em>{simulation.auditEvent}</em></div>
            <div className="step-stack">{simulation.steps.map((step) => <div key={step.order}><b>{String(step.order).padStart(2, '0')}</b><span>{step.text}</span><Check size={15} /></div>)}</div>
            <p className="demo-verdict">{simulation.result}</p>
            <p className="presenter-line">Audit proof: <b>{simulation.auditEvent}</b> is written to the same audit log used by the authentication flow.</p>
          </> : <div className="empty-simulation"><Radar size={26} /><strong>Choose a scenario</strong><span>The result will appear here as a live defensive trace.</span></div>}
        </div>
      </div>
    </section>
  );
}

function ReportBrief({ report, loadReport }: { report: SecurityReport | null; loadReport: () => void }) {
  const saveReport = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `secureos-report-${report.generatedAt}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };
  return (
    <section className="report-brief">
      <div>
        <span className="context-pill"><Terminal size={14} /> Security report</span>
        <h2>Generate an evidence report.</h2>
        <p>Summarizes implemented controls, current risk, recommendations, and recent security events.</p>
      </div>
      <div className="report-actions">
        <button onClick={loadReport}>Generate report</button>
        <button disabled={!report} onClick={saveReport}>Export JSON</button>
      </div>
      {report && <div className="report-output">
        <p>{report.executiveSummary}</p>
        <InlineMetrics items={[['Risk', `${report.risk.score}/100`, report.risk.level], ['Controls', String(report.controls.length), 'good'], ['Recommendations', String(report.recommendations.length), report.recommendations.length ? 'warn' : 'good']]} />
        <InsightStream items={report.demoScript.map((step, index) => [`demo ${index + 1}`, step])} />
      </div>}
    </section>
  );
}

function FlowSection({ icon, label, children }: { icon: ReactNode; label: string; children: ReactNode }) {
  return <section className="flow-section"><h2>{icon}{label}</h2>{children}</section>;
}

function InsightStream({ items }: { items: [string, string][] }) {
  return <div className="insight-stream">{items.length ? items.map(([time, text], index) => <motion.div key={`${time}-${index}`} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * 0.03 }}><time>{time}</time><span>{text}</span></motion.div>) : <div><time>--</time><span>No signal yet.</span></div>}</div>;
}

function AIResponse({ text }: { text: string }) {
  const blocks = text.split(/\n{2,}/).map((block) => block.trim()).filter(Boolean);
  return (
    <div className="ai-response">
      {blocks.map((block, index) => {
        const clean = block.replace(/^`+|`+$/g, '').trim();
        if (/^\*\*[^*]+\*\*$/.test(clean)) {
          return <h3 key={index}>{clean.replace(/\*\*/g, '')}</h3>;
        }
        const listLines = clean.split('\n').filter((line) => /^\s*[-*]\s+/.test(line) || /^\s*\d+\.\s+/.test(line));
        if (listLines.length > 1) {
          return <ul key={index}>{listLines.map((line) => <li key={line}>{renderInline(line.replace(/^\s*[-*]\s+|^\s*\d+\.\s+/, ''))}</li>)}</ul>;
        }
        return <p key={index}>{renderInline(clean.replace(/\n/g, ' '))}</p>;
      })}
    </div>
  );
}

function renderInline(text: string) {
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, index) => part.startsWith('**') && part.endsWith('**')
    ? <strong key={index}>{part.slice(2, -2)}</strong>
    : <React.Fragment key={index}>{part}</React.Fragment>);
}

function SystemTrace({ title, steps }: { title: string; steps: string[] }) {
  return <section className="trace"><h1>{title}</h1>{steps.map((step, index) => <p key={step}><span>{index === steps.length - 1 ? <Check size={14} /> : <RefreshCw size={14} />}</span>{step}</p>)}</section>;
}

function FormError({ text }: { text?: string }) {
  return text ? <p className="error"><X size={14} /> {text}</p> : null;
}

createRoot(document.getElementById('root')!).render(<App />);


