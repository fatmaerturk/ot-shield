import React, { useState, useEffect, useMemo } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import { Icon, theme } from './theme';

interface LoginFormData {
  email: string;
  password: string;
}

interface LoginResponse {
  token: string;
  email: string;
  fullName: string;
}

const Login: React.FC = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState<LoginFormData>({ email: '', password: '' });
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [clock, setClock] = useState<string>('');

  useEffect(() => {
    const tick = () => {
      const d = new Date();
      setClock(
        d.toLocaleTimeString('en-GB', {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false,
        })
      );
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const response = await api.post<LoginResponse>('/api/auth/login', {
        email: formData.email,
        password: formData.password,
      });
      localStorage.setItem('token', response.data.token);
      localStorage.setItem(
        'user',
        JSON.stringify({ email: response.data.email, fullName: response.data.fullName })
      );
      navigate('/executive');
    } catch (err: any) {
      if (err.response) {
        setError(err.response.data?.message || 'Authentication failed. Check your credentials.');
      } else if (err.request) {
        setError('Connection error. Is the backend reachable?');
      } else {
        setError('Unexpected error: ' + err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  // Pre-compute particles once
  const particles = useMemo(
    () =>
      Array.from({ length: 22 }).map((_, i) => ({
        id: i,
        left: Math.random() * 100,
        top: Math.random() * 100,
        size: 2 + Math.random() * 4,
        duration: 8 + Math.random() * 10,
        delay: Math.random() * 6,
        opacity: 0.25 + Math.random() * 0.5,
      })),
    []
  );

  // Pre-compute telemetry sparkline path (static shape, animated via CSS)
  const sparkPath = useMemo(() => {
    const pts = Array.from({ length: 48 }).map((_, i) => {
      const x = (i / 47) * 100;
      const y =
        50 +
        Math.sin(i / 2.2) * 16 +
        Math.cos(i / 3.7) * 8 +
        (Math.random() - 0.5) * 4;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    });
    return 'M' + pts.join(' L ');
  }, []);

  const formStagger = {
    hidden: {},
    visible: { transition: { staggerChildren: 0.08, delayChildren: 0.15 } },
  };
  const formItem = {
    hidden: { opacity: 0, y: 10 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.4 } },
  };

  return (
    <div
      className="min-h-screen w-full flex relative overflow-hidden"
      style={{ background: theme.pageBackground }}
    >
      {/* Global keyframes used throughout this page */}
      <style>{`
        @keyframes ot-blob-drift {
          0%   { transform: translate(0,0) scale(1); }
          33%  { transform: translate(40px,-30px) scale(1.08); }
          66%  { transform: translate(-30px,20px) scale(0.94); }
          100% { transform: translate(0,0) scale(1); }
        }
        @keyframes ot-grid-scroll {
          0%   { background-position: 0 0; }
          100% { background-position: 42px 42px; }
        }
        @keyframes ot-gradient-sweep {
          0%   { background-position: 0% 50%; }
          50%  { background-position: 100% 50%; }
          100% { background-position: 0% 50%; }
        }
        @keyframes ot-float-up {
          0%   { transform: translateY(0) scale(1); opacity: 0; }
          10%  { opacity: var(--max-o, 0.6); }
          90%  { opacity: var(--max-o, 0.6); }
          100% { transform: translateY(-120px) scale(0.6); opacity: 0; }
        }
        @keyframes ot-spark-dash {
          0%   { stroke-dashoffset: 400; }
          100% { stroke-dashoffset: 0; }
        }
        @keyframes ot-spark-pulse {
          0%,100% { opacity: 0.55; }
          50%     { opacity: 1; }
        }
        @keyframes ot-shimmer {
          0%   { transform: translateX(-120%); }
          100% { transform: translateX(120%); }
        }
        @keyframes ot-ring-pulse {
          0%,100% { box-shadow: 0 0 0 0 rgba(124,58,237,0.0); }
          50%     { box-shadow: 0 0 0 6px rgba(124,58,237,0.12); }
        }
        @keyframes ot-badge-pulse {
          0%,100% { opacity: 1; transform: scale(1); }
          50%     { opacity: 0.7; transform: scale(1.15); }
        }
        .ot-animated-gradient {
          background-size: 220% 220%;
          animation: ot-gradient-sweep 18s ease-in-out infinite;
        }
      `}</style>

      {/* ============================= LEFT / HERO ============================= */}
      <aside
        className="relative hidden lg:flex lg:w-[46%] xl:w-[42%] flex-col justify-between overflow-hidden text-white ot-animated-gradient"
        style={{
          background:
            'linear-gradient(135deg, #1e1b4b 0%, #4c1d95 30%, #7c3aed 55%, #a21caf 80%, #be185d 100%)',
        }}
      >
        {/* ambient glow blobs - slow drift */}
        <div
          className="pointer-events-none absolute -top-24 -left-24 w-[28rem] h-[28rem] rounded-full bg-fuchsia-500/30 blur-3xl"
          style={{ animation: 'ot-blob-drift 22s ease-in-out infinite' }}
        />
        <div
          className="pointer-events-none absolute bottom-[-8rem] right-[-6rem] w-[30rem] h-[30rem] rounded-full bg-pink-500/25 blur-3xl"
          style={{ animation: 'ot-blob-drift 28s ease-in-out infinite reverse' }}
        />
        <div
          className="pointer-events-none absolute top-1/3 right-1/4 w-[16rem] h-[16rem] rounded-full bg-violet-400/20 blur-3xl"
          style={{ animation: 'ot-blob-drift 34s ease-in-out infinite' }}
        />

        {/* scrolling grid overlay */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.09]"
          style={{
            backgroundImage:
              'linear-gradient(rgba(255,255,255,0.6) 1px, transparent 1px),' +
              'linear-gradient(90deg, rgba(255,255,255,0.6) 1px, transparent 1px)',
            backgroundSize: '42px 42px',
            maskImage:
              'radial-gradient(ellipse at center, rgba(0,0,0,0.85), transparent 70%)',
            animation: 'ot-grid-scroll 14s linear infinite',
          }}
        />

        {/* floating security particles */}
        <div className="pointer-events-none absolute inset-0 overflow-hidden">
          {particles.map((p) => (
            <span
              key={p.id}
              className="absolute rounded-full bg-white"
              style={{
                left: `${p.left}%`,
                top: `${p.top}%`,
                width: p.size,
                height: p.size,
                boxShadow: '0 0 8px rgba(255,255,255,0.8)',
                animation: `ot-float-up ${p.duration}s linear ${p.delay}s infinite`,
                ['--max-o' as any]: p.opacity,
              }}
            />
          ))}
        </div>

        {/* top brand row */}
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="relative z-10 px-10 pt-10 flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <motion.div
              initial={{ rotate: -12, scale: 0.8, opacity: 0 }}
              animate={{ rotate: 0, scale: 1, opacity: 1 }}
              transition={{ type: 'spring', stiffness: 160, damping: 14, delay: 0.1 }}
              className="w-11 h-11 rounded-2xl bg-white/15 backdrop-blur flex items-center justify-center ring-1 ring-white/30"
            >
              <Icon.Shield className="w-6 h-6 text-white" />
            </motion.div>
            <div>
              <div className="text-lg font-semibold tracking-tight">OTShield</div>
              <div className="text-[11px] uppercase tracking-[0.18em] text-white/70">
                Deception · Decoy · OT defence
              </div>
            </div>
          </div>
          <div className="hidden xl:flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/10 ring-1 ring-white/20 text-xs text-white/85">
            <span
              className="w-1.5 h-1.5 rounded-full bg-emerald-400"
              style={{ animation: 'ot-badge-pulse 1.8s ease-in-out infinite' }}
            />
            All systems operational · {clock}
          </div>
        </motion.div>

        {/* hero copy */}
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.15 }}
          className="relative z-10 px-10"
        >
          <h1 className="text-4xl xl:text-5xl font-semibold leading-tight tracking-tight">
            Lure attackers.{' '}
            <span className="bg-gradient-to-r from-fuchsia-200 via-pink-200 to-violet-100 bg-clip-text text-transparent">
              Learn their playbook.
            </span>
          </h1>
          <p className="mt-4 max-w-md text-white/80 text-[15px] leading-relaxed">
            OTShield drops realistic decoys, fake HMIs and honeypots across your plant network,
            watches who bites, and turns every engagement into actionable threat intelligence for
            your SOC.
          </p>

          <motion.div
            initial="hidden"
            animate="visible"
            variants={{
              hidden: {},
              visible: { transition: { staggerChildren: 0.08, delayChildren: 0.3 } },
            }}
            className="mt-8 grid grid-cols-2 gap-3 max-w-md"
          >
            <HeroStat icon={<Icon.Target className="w-4 h-4" />} label="Decoy engagements" sub="Attackers geo-tracked" />
            <HeroStat icon={<Icon.Eye className="w-4 h-4" />} label="Fake HMIs" sub="Live interaction bait" />
            <HeroStat icon={<Icon.Activity className="w-4 h-4" />} label="Honeypot telemetry" sub="MODBUS · S7 · DNP3" />
            <HeroStat icon={<Icon.Layers className="w-4 h-4" />} label="Case management" sub="MTTR-tracked" />
          </motion.div>

          {/* live telemetry sparkline */}
          <div className="mt-8 max-w-md rounded-xl bg-white/10 ring-1 ring-white/15 backdrop-blur-sm px-4 py-3">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] uppercase tracking-[0.15em] text-white/65">
                Live traffic · zone L2
              </span>
              <span
                className="flex items-center gap-1.5 text-[11px] text-emerald-300"
                style={{ animation: 'ot-spark-pulse 2.4s ease-in-out infinite' }}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                streaming
              </span>
            </div>
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="w-full h-12">
              <defs>
                <linearGradient id="sparkStroke" x1="0" x2="1">
                  <stop offset="0%" stopColor="#f0abfc" />
                  <stop offset="100%" stopColor="#fce7f3" />
                </linearGradient>
                <linearGradient id="sparkFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stopColor="rgba(244,114,182,0.35)" />
                  <stop offset="100%" stopColor="rgba(244,114,182,0)" />
                </linearGradient>
              </defs>
              <path d={`${sparkPath} L 100,100 L 0,100 Z`} fill="url(#sparkFill)" />
              <path
                d={sparkPath}
                fill="none"
                stroke="url(#sparkStroke)"
                strokeWidth="1.2"
                vectorEffect="non-scaling-stroke"
                strokeDasharray="400"
                style={{ animation: 'ot-spark-dash 6s linear infinite' }}
              />
            </svg>
          </div>
        </motion.div>

        {/* footer trust strip */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6, duration: 0.5 }}
          className="relative z-10 px-10 pb-8 pt-10"
        >
          <div className="h-px w-full bg-white/15" />
          <div className="mt-4 flex items-center justify-between text-[11px] tracking-wide text-white/70">
            <span>© {new Date().getFullYear()} OTShield · Safetech</span>
            <span className="flex items-center gap-1.5">
              <Icon.Lock className="w-3.5 h-3.5" /> Zero-trust authentication
            </span>
          </div>
        </motion.div>
      </aside>

      {/* ============================= RIGHT / FORM ============================= */}
      <main className="flex-1 flex items-center justify-center px-6 sm:px-10 py-12 relative">
        {/* mobile brand header */}
        <div className="lg:hidden absolute top-6 left-6 flex items-center gap-2">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-violet-600 to-fuchsia-600 flex items-center justify-center">
            <Icon.Shield className="w-5 h-5 text-white" />
          </div>
          <span className="font-semibold tracking-tight text-gray-900">OTShield</span>
        </div>

        <motion.div
          initial="hidden"
          animate="visible"
          variants={formStagger}
          className="w-full max-w-md"
        >
          <motion.div variants={formItem} className="mb-8">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-violet-50 ring-1 ring-violet-100 text-[11px] font-medium text-violet-700 uppercase tracking-wider">
              <span
                className="w-1.5 h-1.5 rounded-full bg-violet-500"
                style={{ animation: 'ot-badge-pulse 1.8s ease-in-out infinite' }}
              />
              Secure sign-in
            </div>
            <h2 className="mt-4 text-3xl font-semibold tracking-tight">
              <span className={theme.gradients.primaryText}>Welcome back</span>
            </h2>
            <p className="mt-2 text-sm text-gray-500">
              Authenticate with your analyst credentials to access the SOC workspace.
            </p>
          </motion.div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <motion.div variants={formItem}>
              <Field label="Work email" icon={<MailIcon className="w-4 h-4" />}>
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="analyst@company.com"
                  className="w-full bg-transparent outline-none text-[15px] text-gray-900 placeholder:text-gray-400"
                />
              </Field>
            </motion.div>

            <motion.div variants={formItem}>
              <Field
                label="Password"
                icon={<Icon.Lock className="w-4 h-4" />}
                trailing={
                  <button
                    type="button"
                    onClick={() => setShowPassword((s) => !s)}
                    className="text-gray-400 hover:text-violet-600 transition-colors"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOffIcon className="w-4 h-4" /> : <Icon.Eye className="w-4 h-4" />}
                  </button>
                }
              >
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="••••••••"
                  className="w-full bg-transparent outline-none text-[15px] text-gray-900 placeholder:text-gray-400"
                />
              </Field>
            </motion.div>

            <motion.div variants={formItem} className="flex items-center justify-between text-sm">
              <label className="inline-flex items-center gap-2 text-gray-600 cursor-pointer select-none">
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-gray-300 text-violet-600 focus:ring-violet-500 cursor-pointer"
                />
                Keep me signed in
              </label>
              <a
                href="/forgot"
                className="font-medium text-violet-600 hover:text-fuchsia-600 transition-colors"
              >
                Forgot password?
              </a>
            </motion.div>

            {error && (
              <motion.div
                initial={{ opacity: 0, y: -4, x: 0 }}
                animate={{ opacity: 1, y: 0, x: [0, -6, 6, -4, 4, 0] }}
                transition={{ duration: 0.45 }}
                className="flex items-start gap-3 rounded-xl border border-rose-200 bg-rose-50/80 px-4 py-3 text-sm text-rose-700"
                role="alert"
              >
                <Icon.Alert className="w-4 h-4 mt-0.5 text-rose-500 shrink-0" />
                <span>{error}</span>
              </motion.div>
            )}

            <motion.div variants={formItem}>
              <button
                type="submit"
                disabled={loading}
                className="relative w-full group overflow-hidden rounded-xl py-3 text-[15px] font-medium text-white disabled:opacity-60 disabled:cursor-not-allowed transition-transform active:scale-[0.99] ot-animated-gradient"
                style={{
                  background:
                    'linear-gradient(135deg, #7c3aed 0%, #a21caf 50%, #db2777 100%)',
                  boxShadow:
                    '0 10px 25px -10px rgba(124,58,237,0.55), 0 4px 12px -4px rgba(219,39,119,0.35)',
                }}
              >
                {/* shimmer sweep on hover */}
                <span
                  className="absolute inset-y-0 -left-1/2 w-1/2 bg-gradient-to-r from-transparent via-white/35 to-transparent opacity-0 group-hover:opacity-100"
                  style={{ animation: 'ot-shimmer 1.4s linear infinite' }}
                />
                <span className="relative flex items-center justify-center gap-2">
                  {loading ? (
                    <>
                      <svg
                        className="animate-spin h-4 w-4"
                        xmlns="http://www.w3.org/2000/svg"
                        fill="none"
                        viewBox="0 0 24 24"
                      >
                        <circle
                          className="opacity-25"
                          cx="12"
                          cy="12"
                          r="10"
                          stroke="currentColor"
                          strokeWidth="4"
                        />
                        <path
                          className="opacity-75"
                          fill="currentColor"
                          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                        />
                      </svg>
                      Authenticating…
                    </>
                  ) : (
                    <>
                      Sign in to OTShield
                      <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-0.5" />
                    </>
                  )}
                </span>
              </button>
            </motion.div>
          </form>

          <motion.p variants={formItem} className="mt-8 text-center text-sm text-gray-500">
            Need access?{' '}
            <a
              href="/register"
              className="font-medium text-violet-600 hover:text-fuchsia-600 transition-colors"
            >
              Request analyst credentials
            </a>
          </motion.p>
        </motion.div>
      </main>
    </div>
  );
};

/* ---------------------------------------------------------------------- */
/*  Small presentational helpers                                          */
/* ---------------------------------------------------------------------- */

const HeroStat: React.FC<{ icon: React.ReactNode; label: string; sub: string }> = ({
  icon,
  label,
  sub,
}) => (
  <motion.div
    variants={{
      hidden: { opacity: 0, y: 10 },
      visible: { opacity: 1, y: 0, transition: { duration: 0.4 } },
    }}
    whileHover={{ y: -2, transition: { duration: 0.2 } }}
    className="rounded-xl bg-white/10 backdrop-blur-sm ring-1 ring-white/15 px-3.5 py-3 transition-colors hover:bg-white/15"
  >
    <div className="flex items-center gap-2 text-white/90">
      <span className="w-6 h-6 rounded-md bg-white/15 ring-1 ring-white/20 flex items-center justify-center">
        {icon}
      </span>
      <span className="text-[13px] font-medium">{label}</span>
    </div>
    <div className="mt-1.5 text-[11px] text-white/65 tracking-wide">{sub}</div>
  </motion.div>
);

const Field: React.FC<{
  label: string;
  icon: React.ReactNode;
  trailing?: React.ReactNode;
  children: React.ReactNode;
}> = ({ label, icon, trailing, children }) => (
  <label className="block">
    <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-gray-500">
      {label}
    </span>
    <div className="mt-1.5 flex items-center gap-2 rounded-xl bg-white ring-1 ring-gray-200 px-3.5 py-2.5 transition-all duration-300 focus-within:ring-2 focus-within:ring-violet-400 focus-within:border-transparent focus-within:shadow-[0_0_0_6px_rgba(124,58,237,0.08)] shadow-sm">
      <span className="text-gray-400 transition-colors">{icon}</span>
      <div className="flex-1">{children}</div>
      {trailing}
    </div>
  </label>
);

const MailIcon: React.FC<{ className?: string }> = ({ className = 'w-4 h-4' }) => (
  <svg
    className={className}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
    <polyline points="22,6 12,13 2,6" />
  </svg>
);

const EyeOffIcon: React.FC<{ className?: string }> = ({ className = 'w-4 h-4' }) => (
  <svg
    className={className}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-10-8-10-8a18.87 18.87 0 0 1 4.22-5.94" />
    <path d="M9.9 4.24A10.94 10.94 0 0 1 12 4c7 0 10 8 10 8a18.5 18.5 0 0 1-2.16 3.19" />
    <path d="M1 1l22 22" />
    <path d="M9.53 9.53a3 3 0 0 0 4.24 4.24" />
  </svg>
);

const ArrowRight: React.FC<{ className?: string }> = ({ className = 'w-4 h-4' }) => (
  <svg
    className={className}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.9"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <line x1="5" y1="12" x2="19" y2="12" />
    <polyline points="12 5 19 12 12 19" />
  </svg>
);

export default Login;
