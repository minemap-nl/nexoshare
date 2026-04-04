import { useState, useEffect, useRef, useCallback } from 'react';
import {
    Download, Upload, Share2, Settings,
    LogOut, User,
    Loader2,
    Shield,
} from 'lucide-react';
import { API_URL } from '../api/constants';
import { isValidHttpUrl } from '../lib';
import { useAppConfig } from '../context/AppConfigContext';
import { useUI } from '../context/UIContext';
import { useAuth } from '../hooks/useAuth';
import { useTokenExpiration } from '../hooks/useTokenExpiration';
import { GlobalStyles } from '../components/layout/GlobalStyles';
import { Footer } from '../components/layout/Footer';
import { ProfileView } from './ProfileView';
import { UploadView } from './UploadView';
import { MySharesView } from './MySharesView';
import { ReverseView } from './ReverseView';
import { ConfigTabs } from './ConfigTabs';
import { SetupWizard } from './SetupWizard';


export function Dashboard({ token, logout }: any) {
    const [view, setView] = useState('upload');
    const [uploadShowsSuccess, setUploadShowsSuccess] = useState(false);
    const uploadResetRef = useRef<(() => void) | null>(null);
    const { config } = useAppConfig();
    const [showSetup, setShowSetup] = useState(false);
    const [is2FALocked, setIs2FALocked] = useState(false);
    const [checking2FA, setChecking2FA] = useState(true);
    const { user } = useAuth();
    const { notify } = useUI();
    // Check of setup nodig is bij laden (geen auto-wizard in demo — voorkomt "quick start" bij elke login)
    useEffect(() => {
        if (!user || !config || config.setupCompleted || config.demoMode) return;
        if (user.email === 'admin@nexoshare.com') setShowSetup(true);
    }, [user, config]);
    useTokenExpiration(token, logout);

    useEffect(() => {
        const check2FA = async () => {
            try {
                const res = await fetch(`${API_URL}/auth/check-2fa-requirement`, { credentials: 'include' });
                if (res.ok) {
                    const data = await res.json();
                    if (data.required) {
                        setIs2FALocked(true);
                        setView('profile'); // Forceer naar profiel pagina
                    }
                }
            } catch (e) {
                console.error("2FA check failed", e);
            } finally {
                setChecking2FA(false);
            }
        };
        check2FA();
    }, []);

    const handleLogout = useCallback(() => {
        if (config.ssoEnabled && config.ssoLogoutUrl && config.ssoLogoutUrl.trim() !== '') {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            // Prevent Open Redirect via Helper
            try {
                const logoutUrl = config.ssoLogoutUrl;
                // Strict HTTP/HTTPS validation (Regex) before assign
                if (logoutUrl && /^https?:\/\//i.test(logoutUrl)) {
                    window.location.assign(logoutUrl);
                } else {
                    window.location.reload();
                }
            } catch (e) {
                window.location.reload();
            }
        } else {
            logout();
        }
    }, [config.ssoEnabled, config.ssoLogoutUrl, logout]);

    /** Patched fetch runs with an effect that only mounts once — always call latest logout logic (SSO vs local). */
    const handleLogoutRef = useRef(handleLogout);
    handleLogoutRef.current = handleLogout;

    const tabs = [
        { id: 'upload', label: 'Upload' },
        { id: 'shares', label: 'My Shares' },
        { id: 'reverse', label: 'Reverse Shares' },
        { id: 'profile', label: 'My Profile' }
    ];

    if (user?.is_admin) tabs.push({ id: 'config', label: 'Configuration' });

    // TODO: Replace this global window.fetch monkeypatch with an axios response interceptor on the
    // shared axios instance (same as axios.defaults.withCredentials in main.tsx), so only own API
    // calls are handled — no global fetch override.
    // Gebruik useRef om de originele fetch te bewaren, anders crasht de browser na een tijdje
    const originalFetchRef = useRef(window.fetch);

    useEffect(() => {
        const originalFetch = originalFetchRef.current;
        window.fetch = async (...args) => {
            const response = await originalFetch(...args);
            if (response.status === 401) {
                if (!args[0].toString().includes('logout')) {
                    handleLogoutRef.current();
                }
            }
            return response;
        };
        return () => { window.fetch = originalFetch; };
    }, []);

    const handleUploadSurfaceChange = useCallback((s: { showSuccess: boolean }) => {
        setUploadShowsSuccess(s.showSuccess);
    }, []);

    const goToUpload = useCallback(() => {
        if (is2FALocked) return;
        if (view === 'upload' && uploadShowsSuccess) {
            uploadResetRef.current?.();
        } else {
            setView('upload');
        }
    }, [is2FALocked, view, uploadShowsSuccess]);

    const selectTab = useCallback((tabId: string) => {
        if (tabId === 'upload') goToUpload();
        else setView(tabId);
    }, [goToUpload]);

    return (
        <div className="min-h-screen bg-app text-gray-100 font-sans flex flex-col">
            {showSetup && <SetupWizard onClose={() => setShowSetup(false)} />}
            <GlobalStyles />
            <nav className="bg-neutral-900 border-b border-neutral-800 h-20 flex items-center px-4 md:px-8 sticky top-0 z-50 shadow-lg relative">
                {/* Spacer links */}
                <div className="w-10 sm:w-0"></div>

                {/* Logo Container */}
                <div
                    className={`flex gap-2 md:gap-3 items-center font-bold text-xl md:text-2xl tracking-tight text-white transition z-10 flex-1 justify-center sm:justify-start ${is2FALocked ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer hover:opacity-80'}`}
                    onClick={() => !is2FALocked && goToUpload()}
                >
                    {(config.logoUrl && isValidHttpUrl(config.logoUrl)) ? (
                        <img src={config.logoUrl} className="h-8 md:h-10 rounded" alt="Logo" />
                    ) : (
                        <img src="/logo.svg" className="h-8 md:h-10 shrink-0" alt="Logo" />
                    )}
                    <span className="hidden sm:inline">{config.appName || 'Nexo Share'}</span>
                </div>

                {/* TABS - Alleen tonen als NIET gelocked */}
                {!is2FALocked && (
                    <div className="hidden lg:flex absolute left-1/2 -translate-x-1/2 bg-black/50 p-1.5 rounded-xl border border-neutral-800/50 backdrop-blur-sm z-20">
                        {tabs.map(tab => (
                            <button key={tab.id} onClick={() => selectTab(tab.id)} className={`px-6 py-2 rounded-lg text-sm font-bold transition-all duration-300 capitalize ${view === tab.id ? 'bg-neutral-800 text-white shadow-md' : 'text-neutral-400 hover:text-white hover:bg-neutral-900'}`}>{tab.label}</button>
                        ))}
                    </div>
                )}

                {/* Logout Knop - Met 'ml-auto' toegevoegd voor de zekerheid */}
                <button onClick={handleLogout} className="text-neutral-400 hover:text-red-400 hover:bg-red-500/10 p-2 rounded-lg transition btn-press z-10 flex-shrink-0 ml-auto">
                    <LogOut className="w-5 h-5 md:w-6 md:h-6" />
                </button>
            </nav>

            {/* VERBERG MOBILE NAV BIJ LOCK */}
            {!is2FALocked && (
                <div className="lg:hidden fixed bottom-0 left-0 right-0 bg-neutral-900 border-t border-neutral-800 pb-safe z-40">
                    <div className="flex justify-around items-center p-2">
                        {tabs.map(tab => {
                            // Bepaal het icoon op basis van de tab ID
                            let Icon = Upload;
                            if (tab.id === 'shares') Icon = Share2;
                            if (tab.id === 'reverse') Icon = Download;
                            if (tab.id === 'profile') Icon = User;
                            if (tab.id === 'config') Icon = Settings;

                            const isActive = view === tab.id;

                            return (
                                <button
                                    key={tab.id}
                                    onClick={() => selectTab(tab.id)}
                                    className={`flex flex-col items-center p-2 rounded-lg transition-all ${isActive ? 'text-primary-400' : 'text-neutral-500 hover:text-neutral-300'}`}
                                >
                                    <Icon className={`w-6 h-6 mb-1 ${isActive ? 'fill-primary-500/20' : ''}`} />
                                    <span className="text-[10px] font-bold">{tab.label}</span>
                                </button>
                            );
                        })}
                    </div>
                </div>
            )}

            <main className="max-w-6xl mx-auto p-4 md:p-8 w-full flex-grow pb-20 lg:pb-8">
                {checking2FA ? (
                    <div className="flex justify-center pt-20"><Loader2 className="animate-spin text-primary-400 w-10 h-10" /></div>
                ) : (
                    <>
                        {/* ALS GELOCKED: Forceer ProfileView met forcedSetup */}
                        {is2FALocked ? (
                            <div className="anim-scale">
                                <div className="bg-red-500/10 border border-red-500/50 p-4 rounded-xl mb-6 text-center text-red-200 flex items-center justify-center gap-3">
                                    <Shield className="w-6 h-6 text-red-500" />
                                    <span className="font-bold">Security Warning:</span>
                                    <span>You must set up 2FA to continue.</span>
                                </div>
                                <ProfileView
                                    user={user}
                                    config={config}
                                    forcedSetup={true}
                                    onComplete={() => {
                                        setIs2FALocked(false); // Hef de blokkade op
                                        setView('upload');
                                        notify('Thank you! Your account is now secured.', 'success');
                                    }}
                                />
                            </div>
                        ) : (
                            /* NORMALE WEERGAVE — tabs blijven gemount zodat state (o.a. File handles, uploads) behouden blijft */
                            <>
                                <div className={view === 'upload' ? 'block' : 'hidden'} aria-hidden={view !== 'upload'}>
                                    <UploadView
                                        active={view === 'upload'}
                                        onUploadSurfaceChange={handleUploadSurfaceChange}
                                        registerReset={uploadResetRef}
                                    />
                                </div>
                                <div className={view === 'shares' ? 'block' : 'hidden'} aria-hidden={view !== 'shares'}>
                                    <MySharesView active={view === 'shares'} />
                                </div>
                                {user?.is_admin && (
                                    <div className={view === 'config' ? 'block' : 'hidden'} aria-hidden={view !== 'config'}>
                                        <ConfigTabs user={user} onRestartSetup={() => setShowSetup(true)} />
                                    </div>
                                )}
                                <div className={view === 'reverse' ? 'block' : 'hidden'} aria-hidden={view !== 'reverse'}>
                                    <ReverseView active={view === 'reverse'} />
                                </div>
                                <div className={view === 'profile' ? 'block' : 'hidden'} aria-hidden={view !== 'profile'}>
                                    <ProfileView user={user} config={config} />
                                </div>
                            </>
                        )}
                    </>
                )}
            </main>

            <Footer />
        </div>
    );
};