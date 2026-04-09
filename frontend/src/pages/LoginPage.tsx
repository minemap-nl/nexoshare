import { useState, useEffect } from 'react';
import { Share2, Shield, Loader2, Copy, Check } from 'lucide-react';
import { startAuthentication } from '@simplewebauthn/browser';
import { API_URL } from '../api/constants';
import { isValidHttpUrl } from '../lib';
import { useAppConfig } from '../context/AppConfigContext';
import { useUI } from '../context/UIContext';
import { GlobalStyles } from '../components/layout/GlobalStyles';
import { Footer } from '../components/layout/Footer';


export function LoginPage({ onLogin }: any) {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loadingSSO, setLoadingSSO] = useState(false);

    const [initializing, setInitializing] = useState(true);
    const [copiedField, setCopiedField] = useState<'email' | 'password' | null>(null);

    const { notify } = useUI();

    const DEMO_EMAIL = 'demo@nexoshare.com';
    const DEMO_PASSWORD = 'demo';

    const copyDemoValue = (field: 'email' | 'password', value: string) => {
        void navigator.clipboard.writeText(value);
        notify(field === 'email' ? 'Email copied' : 'Password copied', 'success');
        setCopiedField(field);
        window.setTimeout(() => setCopiedField(null), 2000);
    };
    const { config, loading: cfgLoading } = useAppConfig();

    useEffect(() => {
        const nonce = new URLSearchParams(window.location.search).get('nonce');
        if (!nonce) return;
        fetch(`${API_URL}/auth/sso-exchange`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nonce })
        })
            .then(r => r.json())
            .then(data => {
                if (data.token && data.user) {
                    localStorage.setItem('sso_login', 'true');
                    onLogin(data.user);
                    window.history.replaceState({}, document.title, window.location.pathname);
                } else {
                    notify('SSO login failed', 'error');
                    setInitializing(false);
                }
            })
            .catch(() => {
                notify('SSO login failed', 'error');
                setInitializing(false);
            });
    }, [onLogin, notify]);

    useEffect(() => {
        if (cfgLoading) return;
        const params = new URLSearchParams(window.location.search);
        if (params.get('nonce')) return;
        const noRedirect = params.get('noredirect');
        if (config.ssoEnabled && config.ssoAutoRedirect && !noRedirect) {
            setLoadingSSO(true);
            window.location.href = `${API_URL}/auth/sso`;
            return;
        }
        setInitializing(false);
    }, [cfgLoading, config]);

    const [twoFactorRequired, setTwoFactorRequired] = useState(false);
    const [twoFactorCode, setTwoFactorCode] = useState('');
    const [isBackupCode, setIsBackupCode] = useState(false);
    const [tempEmail, setTempEmail] = useState('');
    const [tempPassword, setTempPassword] = useState('');

    const handleSubmit = async (e: any) => {
        e.preventDefault();
        const res = await fetch(`${API_URL}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
        const data = await res.json();
        if (res.ok) {
            if (data.requires2FA) {
                setTempEmail(email);
                setTempPassword(password);
                setTwoFactorRequired(true);
                return;
            }
            if (data.requiresSetup2FA) {
                notify('You must set up 2FA first', 'info');
                // onLogin accepteert maar 1 parameter (het user object)
                localStorage.removeItem('sso_login');
                onLogin(data.user);
                return;
            }
            localStorage.removeItem('sso_login');
            onLogin(data.user);
        } else {
            notify(data.error || "Login failed", "error");
        }
    };

    const handleVerify2FA = async (e: any) => {
        e.preventDefault();
        const res = await fetch(`${API_URL}/auth/verify-2fa`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: tempEmail, password: tempPassword, code: twoFactorCode })
        });
        const data = await res.json();
        if (res.ok) {
            localStorage.removeItem('sso_login');
            onLogin(data.user);
        } else {
            notify(data.error || '2FA verification failed', 'error');
        }
    };

    const handlePasskeyLogin = async () => {
        try {
            // 1. Haal opties op
            const optionsRes = await fetch(`${API_URL}/passkeys/auth/options`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!optionsRes.ok) {
                notify('Passkey login failed', 'error');
                return;
            }

            const options = await optionsRes.json();

            // 2. Bewaar challenge voor server lookup
            const serverChallenge = options.challenge;

            // 3. Start Authenticatie - Library handelt base64url af
            const credential = await startAuthentication(options);

            // 4. Stuur response + challenge Back naar server
            const verifyRes = await fetch(`${API_URL}/passkeys/auth/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    response: credential,
                    challenge: serverChallenge
                })
            });

            if (!verifyRes.ok) {
                const err = await verifyRes.json();
                notify(err.error || 'Passkey verification failed', 'error');
                return;
            }

            const data = await verifyRes.json();
            localStorage.removeItem('sso_login');
            onLogin(data.user);

        } catch (err: any) {
            console.error(err);
            notify(err.message || 'Passkey login failed', 'error');
        }
    };

    const [showResetRequest, setShowResetRequest] = useState(false);
    const [resetRequestEmail, setResetRequestEmail] = useState('');

    const handleResetRequest = async (e: any) => {
        e.preventDefault();
        const res = await fetch(`${API_URL}/auth/password-reset/request`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: resetRequestEmail })
        });
        const data = await res.json();
        if (res.ok) {
            notify('If this email address exists, a reset link has been sent', 'success');
            setShowResetRequest(false);
            setResetRequestEmail('');
        } else {
            notify(data.error || 'Request failed', 'error');
        }
    };

    const handleSSO = () => {
        window.location.href = `${API_URL}/auth/sso`;
    };

    if (initializing || loadingSSO) {
        return (
            <div className="min-h-screen bg-app flex flex-col items-center justify-center text-white">
                <Loader2 className="w-16 h-16 animate-spin text-primary-400 mb-4" />
                <h2 className="text-xl font-bold">{loadingSSO ? 'Redirect to SSO...' : 'Loading...'}</h2>
                {loadingSSO && (
                    <a href="/login?noredirect=true" className="mt-4 text-neutral-500 text-sm hover:text-white underline">Cancel</a>
                )}
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-app flex items-center justify-center p-4 relative overflow-hidden flex-col">
            <GlobalStyles />
            <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_50%_120%,rgba(13,148,136,0.14),rgba(0,0,0,0))]" aria-hidden />
            <form onSubmit={twoFactorRequired ? handleVerify2FA : handleSubmit} className="bg-neutral-900 p-6 md:p-10 rounded-2xl w-full max-w-md border border-neutral-800 shadow-2xl relative z-10 anim-scale mb-8">
                <div className="flex justify-center mb-8">
                    {(config.logoUrl && isValidHttpUrl(config.logoUrl)) ? <img src={config.logoUrl} className="h-16" alt="Logo" /> : <img src="/logo.svg" className="h-16" alt="Logo" />}
                </div>
                <h1 className="heading-page mb-6 text-center leading-tight">
                    Welcome to 
                    {(config.appName || 'Nexo Share').length > 6 ? <br /> : ' '}
                    <span className="whitespace-nowrap">{config.appName || 'Nexo Share'}</span>
                </h1>

                {!cfgLoading && config.demoMode && !twoFactorRequired && (
                    <div
                        role="note"
                        className="mb-6 w-full rounded-xl border-2 border-primary-400/50 bg-gradient-to-br from-primary-950/80 to-neutral-950/90 px-4 py-4 shadow-lg shadow-primary-950/20"
                    >
                        <p className="text-primary-200 text-xs font-bold uppercase tracking-wider mb-3">Demo credentials</p>
                        <div className="space-y-3">
                            <div className="flex items-center justify-between gap-2 rounded-lg bg-black/40 px-3 py-2.5 border border-neutral-800">
                                <div className="min-w-0 flex-1">
                                    <p className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500 mb-0.5">Email</p>
                                    <p className="font-mono text-sm text-white break-all">{DEMO_EMAIL}</p>
                                </div>
                                <button
                                    type="button"
                                    onClick={() => copyDemoValue('email', DEMO_EMAIL)}
                                    className="shrink-0 rounded-lg border border-neutral-600 bg-neutral-800 p-2.5 text-primary-300 hover:bg-neutral-700 hover:text-white transition btn-press"
                                    title="Copy email"
                                    aria-label="Copy demo email"
                                >
                                    {copiedField === 'email' ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                                </button>
                            </div>
                            <div className="flex items-center justify-between gap-2 rounded-lg bg-black/40 px-3 py-2.5 border border-neutral-800">
                                <div className="min-w-0 flex-1">
                                    <p className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500 mb-0.5">Password</p>
                                    <p className="font-mono text-sm text-white">{DEMO_PASSWORD}</p>
                                </div>
                                <button
                                    type="button"
                                    onClick={() => copyDemoValue('password', DEMO_PASSWORD)}
                                    className="shrink-0 rounded-lg border border-neutral-600 bg-neutral-800 p-2.5 text-primary-300 hover:bg-neutral-700 hover:text-white transition btn-press"
                                    title="Copy password"
                                    aria-label="Copy demo password"
                                >
                                    {copiedField === 'password' ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                                </button>
                            </div>
                        </div>
                    </div>
                )}

                {!twoFactorRequired ? (
                    <>
                        <input className="input-field mb-4 p-4" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
                        <input className="input-field mb-4 p-4" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
                        <button className="w-full bg-primary hover:bg-primary-700 text-white p-4 rounded-lg font-bold transition shadow-lg shadow-primary-950/25 text-lg btn-press mb-4">Login</button>

                        {config.allowPasskeys && (
                            <button type="button" onClick={handlePasskeyLogin} className="w-full bg-neutral-800 hover:bg-neutral-700 text-white p-4 rounded-lg font-bold transition shadow-lg text-lg btn-press mb-4 flex items-center justify-center gap-2">
                                <Shield className="w-5 h-5" /> Passkey Login
                            </button>
                        )}

                        {config.allowPasswordReset && (config.smtpHost || config.smtpConfigured) && (
                            <button type="button" onClick={() => setShowResetRequest(true)} className="w-full text-neutral-400 hover:text-primary-300 text-sm transition">
                                Forgot your password?
                            </button>
                        )}
                    </>
                ) : (
                    <>
                        {isBackupCode ? (
                            <>
                                <p className="text-neutral-300 mb-4">Enter a backup code:</p>
                                <input
                                    className="input-field mb-4 p-4 text-center text-xl font-mono uppercase placeholder:text-neutral-600"
                                    placeholder="XXXX-XX"
                                    value={twoFactorCode}
                                    onChange={e => setTwoFactorCode(e.target.value.toUpperCase())}
                                    autoFocus
                                />
                            </>
                        ) : (
                            <>
                                <p className="text-neutral-300 mb-4">Enter your 2FA code:</p>
                                <input
                                    className="input-field mb-4 p-4 text-center text-2xl tracking-widest placeholder:text-neutral-600"
                                    placeholder="000000"
                                    value={twoFactorCode}
                                    onChange={e => setTwoFactorCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                    maxLength={6}
                                    autoComplete="one-time-code"
                                    inputMode="numeric"
                                    pattern="[0-9]*"
                                    autoFocus
                                />
                            </>
                        )}

                        <button className="w-full bg-primary hover:bg-primary-700 text-white p-4 rounded-lg font-bold transition shadow-lg shadow-primary-950/25 text-lg btn-press mb-4">Verify</button>

                        <div className="flex flex-col gap-3 text-center">
                            {!isBackupCode ? (
                                <button type="button" onClick={() => { setIsBackupCode(true); setTwoFactorCode(''); }} className="text-neutral-400 hover:text-white text-sm transition font-medium">
                                    I don't have access to my app<br />(Use backup code)
                                </button>
                            ) : (
                                <button type="button" onClick={() => { setIsBackupCode(false); setTwoFactorCode(''); }} className="text-neutral-400 hover:text-white text-sm transition font-medium">
                                    Back to Authenticator App
                                </button>
                            )}

                            <button type="button" onClick={() => { setTwoFactorRequired(false); setTwoFactorCode(''); setIsBackupCode(false); }} className="text-neutral-500 hover:text-primary-300 text-sm transition">
                                Back to login
                            </button>
                        </div>
                    </>
                )}

                {config.ssoEnabled && !twoFactorRequired && (
                    <div className="mt-6 pt-6 border-t border-neutral-700 text-center">
                        <button type="button" onClick={handleSSO} className="text-primary-300 hover:text-primary-200 text-sm font-medium transition flex items-center justify-center gap-2 w-full">
                            <Shield className="w-4 h-4" /> Log in with SSO
                        </button>
                    </div>
                )}
            </form>
            {showResetRequest && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
                    {/* Achtergrondlaag: Klikken hier sluit de modal */}
                    <div
                        className="absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
                        onClick={() => setShowResetRequest(false)}
                    ></div>

                    <div className="relative bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full shadow-2xl transform transition-all">

                        <h2 className="heading-section mb-4">Password Reset</h2>

                        {/* Koppel hier je submit functie */}
                        <form onSubmit={handleResetRequest}>
                            <input
                                className="input-field mb-4 p-4 placeholder:text-neutral-500"
                                placeholder="Your email address"
                                required
                                type="email"
                                value={resetRequestEmail}
                                onChange={(e) => setResetRequestEmail(e.target.value)}
                            />

                            <div className="flex gap-3">
                                <button
                                    type="button"
                                    onClick={() => setShowResetRequest(false)}
                                    className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press border border-neutral-700"
                                >
                                    Cancel
                                </button>

                                <button
                                    type="submit"
                                    className="flex-1 bg-primary hover:bg-primary-700 text-white p-3 rounded-lg font-bold transition btn-press shadow-[0_0_18px_rgba(20,184,166,0.35)]"
                                >
                                    Send link
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
            <div className="z-10"><Footer transparent={true} /></div>
        </div>
    );
};
