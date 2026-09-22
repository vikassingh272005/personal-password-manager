import {
  Lock,
  ShieldCheck,
  KeyRound,
  Radar,
  Smartphone,
  Sparkles,
  ArrowRight,
  Fingerprint,
  EyeOff,
  AlertTriangle,
  Repeat,
  BellOff,
  Timer,
  MonitorX,
} from 'lucide-react';
import { PhoneShell, SecureXLogo, VaultRow, HealthRow, SectionTitle } from '@/components/SecureX';

const features = [
  {
    icon: Lock,
    title: 'Encrypted vault',
    description:
      'AES-256-GCM envelopes wrap every credential. The server only ever stores ciphertext.',
  },
  {
    icon: EyeOff,
    title: 'Zero-knowledge',
    description:
      'Your master password derives your keys locally and is never transmitted, ever.',
  },
  {
    icon: Radar,
    title: 'Dark web monitoring',
    description:
      'Scan your email and saved passwords against billions of breached records — privately.',
  },
  {
    icon: Sparkles,
    title: 'Generator',
    description:
      'Cryptographically secure passwords with tunable length, symbols, and entropy readout.',
  },
  {
    icon: Fingerprint,
    title: 'Secret Key recovery',
    description:
      'A printable 32-character key unlocks your vault even if the master password is lost.',
  },
  {
    icon: Smartphone,
    title: 'Device management',
    description:
      'See every signed-in device and revoke sessions with one click.',
  },
];

const demoAccounts = [
  { title: 'Netflix', sub: 'netflix.vikram@gmail.com', url: 'netflix.com', pw: '234 567', s: 10, letter: 'N' },
  { title: 'Google Accounts', sub: 'google.com', url: 'google.com', pw: '234 567', s: 10, letter: 'G' },
  { title: 'Instagram', sub: 'vikramtech05@gmail.com', url: 'instagram.com', pw: '654978', s: 9, letter: 'I' },
];

export default function Home() {
  return (
    <div className="space-y-20 pb-16">
      {/* ---- Top nav (marketing header; the Sidebar covers authenticated md+ routes) ---- */}
      <header className="rise flex items-center justify-between">
        <SecureXLogo />
        <nav className="flex items-center gap-2.5" aria-label="Account">
          <a href="/login" className="btn-ghost !px-4 !py-2 text-xs">
            Sign in
          </a>
          <a href="/register" className="btn-primary !px-4 !py-2 text-xs">
            Get Started
          </a>
        </nav>
      </header>

      {/* ---- Watermark ---- */}
      <div aria-hidden className="watermark rise -mt-10 pt-4">
        Your Keys,
        <br />
        Your Vault
      </div>

      {/* ---- Onboarding hero + live UI previews ---- */}
      <section className="rise-1 grid grid-cols-1 items-start gap-6 lg:grid-cols-3">
        {/* Onboarding card — replicates the left mockup */}
        <PhoneShell>
          <div className="flex min-h-[480px] flex-col justify-end px-2 pb-2 pt-16">
            <SecureXLogo size="lg" />
            <h1 className="mt-8 text-4xl font-medium leading-[1.1] tracking-tight text-white">
              Your
              <br />
              Passwords,
              <br />
              <span className="text-white/40">Safely Secured</span>
            </h1>
            <p className="mt-4 max-w-[260px] text-[12px] leading-relaxed text-white/55">
              Store, manage, and protect all your passwords in one secure vault.
              Built with cutting-edge encryption and trusted privacy technology,
              your digital life stays safe always.
            </p>
            <a href="/register" className="btn-primary mt-8 w-full">
              Get Started
            </a>
            <p className="mt-4 text-center text-[11px] text-white/40">
              Already secured?{' '}
              <a href="/login" className="font-semibold text-white/80 hover:text-white">
                Sign in
              </a>
            </p>
          </div>
        </PhoneShell>

        {/* Vault list preview — replicates the middle mockup */}
        <PhoneShell>
          <div className="space-y-3">
            <div className="flex items-center justify-between px-1">
              <SecureXLogo size="sm" />
              <span className="icon-disc !h-8 !w-8 text-white/70">≡</span>
            </div>
            <h2 className="px-1 text-xl font-semibold leading-snug text-white">
              Keep ◉ Safe
              <br />
              Your Accounts!
            </h2>
            <div className="search-pill !py-2.5 text-xs">
              <span className="text-white/50">⌕</span>
              <span className="text-white/40">Search account, name</span>
            </div>
            <div className="flex gap-2 px-1">
              {['Today', 'Important', 'All Secured'].map((t, i) => (
                <span
                  key={t}
                  className={`tab-pill !px-3.5 !py-1.5 ${i === 0 ? 'tab-pill-active' : 'border border-white/10'}`}
                >
                  {t}
                </span>
              ))}
            </div>
            <div className="space-y-2">
              {demoAccounts.map((a) => (
                <VaultRow
                  key={a.title}
                  icon={<span className="text-white">{a.letter}</span>}
                  title={a.title}
                  subtitle={a.sub}
                  url={a.url}
                  secretPreview={a.pw}
                  strength={a.s}
                />
              ))}
            </div>
          </div>
        </PhoneShell>

        {/* Health preview — replicates the right mockup */}
        <PhoneShell>
          <div className="space-y-3">
            <div className="glass p-4">
              <p className="text-sm font-semibold text-white">Dark Web Monitoring</p>
              <p className="mt-1 text-[11px] leading-relaxed text-white/50">
                Get notified if your mail, password or other personal data was leaked or weak.
              </p>
            </div>
            <SectionTitle>Password Health</SectionTitle>
            <div className="h-3 overflow-hidden rounded-full border border-white/10 bg-white/[0.06]">
              <div className="h-full w-3/4 rounded-full bg-silver" />
            </div>
            <div className="space-y-2">
              <HealthRow
                icon={<AlertTriangle className="h-4 w-4 text-white" />}
                badge={1}
                title="Weak Passwords"
                subtitle="Change your password"
                href="/security"
              />
              <HealthRow
                icon={<Repeat className="h-4 w-4 text-white" />}
                badge={1}
                title="Reused Passwords"
                subtitle="Generate unique password"
                href="/security"
              />
              <HealthRow
                icon={<BellOff className="h-4 w-4 text-white" />}
                badge={1}
                title="Inactive 2FA"
                subtitle="Set up 2FA for more"
                href="/security"
              />
              <HealthRow
                icon={<MonitorX className="h-4 w-4 text-white" />}
                badge={1}
                title="Excluded from monitoring"
                subtitle="Process is NOT being tracked"
                href="/security"
              />
              <HealthRow
                icon={<Timer className="h-4 w-4 text-white" />}
                badge={1}
                title="On-Time Password"
                subtitle="See your on-time passwords"
                href="/security"
              />
            </div>
          </div>
        </PhoneShell>
      </section>

      {/* ---- Feature grid ---- */}
      <section className="rise-2">
        <h2 className="text-center text-2xl font-bold tracking-tight text-white">
          Everything a modern vault needs
        </h2>
        <p className="mx-auto mt-2 max-w-md text-center text-sm text-white/50">
          Every layout is crafted with clarity, precision, and a refined visual hierarchy.
        </p>
        <div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((feature) => (
            <div key={feature.title} className="glass group p-6">
              <div className="icon-disc">
                <feature.icon className="h-5 w-5 text-white" />
              </div>
              <h3 className="mt-4 text-sm font-semibold text-white">{feature.title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-white/55">
                {feature.description}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* ---- Monitor callout ---- */}
      <section className="glass rise-3 relative overflow-hidden p-10">
        <div className="relative flex flex-col items-center gap-6 text-center sm:flex-row sm:justify-between sm:text-left">
          <div className="max-w-lg">
            <div className="flex items-center gap-2">
              <Radar className="h-5 w-5 text-white" />
              <h2 className="text-lg font-semibold tracking-tight text-white">Dark Web Monitor</h2>
            </div>
            <p className="mt-2 text-sm leading-relaxed text-white/55">
              One scan tells you if your email appears in known breaches and if
              your saved passwords are exposed — using k-anonymity, so even the
              check itself stays private.
            </p>
          </div>
          <a href="/monitor" className="btn-primary shrink-0">
            Run a scan
            <ArrowRight className="h-4 w-4" />
          </a>
        </div>
      </section>

      {/* ---- Footer strip ---- */}
      <footer className="flex flex-col items-center gap-3 border-t border-white/10 pt-10 text-center">
        <SecureXLogo size="sm" />
        <p className="flex items-center gap-1.5 text-xs text-white/45">
          <ShieldCheck className="h-3.5 w-3.5" />
          SecureX — zero-knowledge by design. Encrypted before it ever leaves your device.
        </p>
        <p className="flex items-center gap-1.5 text-xs text-white/45">
          <KeyRound className="h-3.5 w-3.5" />
          Argon2id · AES-256-GCM · WebAuthn
        </p>
      </footer>
    </div>
  );
}
