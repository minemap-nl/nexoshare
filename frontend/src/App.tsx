import React, { useState, useEffect, useRef, createContext, useContext } from 'react';
import { createPortal } from 'react-dom';
import { AnimatePresence, motion } from 'framer-motion';

import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
import {
    Download, Upload, File as FileIcon, Folder as FolderIcon, X, Check, Share2, Settings,
    LogOut, User, Shield,
    Trash2, Send, AlertTriangle, Loader2, Info,
    XCircle, FileQuestion, CloudUpload, Eye,
    Copy, Plus, AlertCircle, ArrowRight, ChevronDown, Edit,
    Mail, Type, HardDrive, Calendar, MessageSquare, Globe,
    Sparkles, FileArchive, Contact, Lock as LockIcon
} from 'lucide-react';
import axios from 'axios';
import DOMPurify from 'dompurify';
import FilePreviewModal from './components/preview/FilePreviewModal';
import { useEscapeKey } from './hooks/useEscapeKey';
import {
    startRegistration,
    startAuthentication
} from '@simplewebauthn/browser';

axios.defaults.withCredentials = true;

const API_URL = '/api';

const formatBytes = (b: any) => {
    if (!b) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

// Crypto-veilige UUID generator voor browser
const generateUUID = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (crypto.getRandomValues(new Uint8Array(1))[0] % 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    }).replace(/-/g, '').substring(0, 16);
};

const UNITS = ['Minutes', 'Hours', 'Days', 'Weeks', 'Months', 'Years'];

const getUnitLabel = (val: number, unit: string) => {
    const map: any = {
        'Minutes': ['Minute', 'Minutes'],
        'Hours': ['Hour', 'Hours'],
        'Days': ['Day', 'Days'],
        'Weeks': ['Week', 'Weeks'],
        'Months': ['Month', 'Months'],
        'Years': ['Year', 'Years']
    };
    if (!map[unit]) return unit;
    return val === 1 ? map[unit][0] : map[unit][1];
};

// --- SECURITY HELPERS ---
const isValidHttpUrl = (url?: string): boolean => {
    if (!url) return false;
    try {
        const u = new URL(url);
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
        return false;
    }
};



// Pas de functie definitie aan:
const getFutureDate = (val: number, unit: string, locale: string = 'en-GB') => {
    if (!val || val <= 0) return 'Never expires';

    const k: any = {
        'Minutes': 60000, 'Hours': 3600000, 'Days': 86400000,
        'Weeks': 604800000, 'Months': 2592000000, 'Years': 31536000000
    };

    const ms = val * (k[unit] || 86400000);
    const date = new Date(Date.now() + ms);
    // Gebruik de variabele locale
    return date.toLocaleString(locale, { dateStyle: 'full', timeStyle: 'short' });
};

const GlobalStyles = () => (
    <style>{`
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    @keyframes slideUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes scaleIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
    @keyframes slideInRight { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    .anim-fade { animation: fadeIn 0.3s ease-out forwards; }
    .anim-slide { animation: slideUp 0.4s ease-out forwards; }
    .anim-scale { animation: scaleIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
    .anim-toast { animation: slideInRight 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
    .btn-press:active { transform: scale(0.96); }
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: #000000; }
    ::-webkit-scrollbar-thumb { background: #404040; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #525252; }
    
    /* Mobile touch improvements */
    @media (max-width: 768px) {
      * { -webkit-tap-highlight-color: transparent; }
      body { overflow-x: hidden; }
    }
  `}</style>
);

// --- SHARED COMPONENTS ---

const Footer = ({ transparent = false }: { transparent?: boolean }) => (
    <footer className={`w-full py-6 text-center text-neutral-500 text-sm mt-auto ${transparent ? '' : 'border-t border-neutral-800 bg-black backdrop-blur-sm'}`}>
        <p className="font-medium tracking-wide">Created by Minemap-nl</p>
    </footer>
);

const COMMON_EXTENSIONS = [
    { ext: '.exe', label: 'Executables' }, { ext: '.bat', label: 'Batch Files' }, { ext: '.cmd', label: 'Command Scripts' },
    { ext: '.sh', label: 'Shell Scripts' }, { ext: '.ps1', label: 'PowerShell' }, { ext: '.vbs', label: 'VBScript' },
    { ext: '.php', label: 'PHP' }, { ext: '.pl', label: 'Perl' }, { ext: '.py', label: 'Python' },
    { ext: '.msp', label: 'Windows Patch' }, { ext: '.msi', label: 'Windows Installer' }, { ext: '.jar', label: 'Java JAR' },
    { ext: '.bin', label: 'Binary' }, { ext: '.dmg', label: 'macOS Image' }, { ext: '.pkg', label: 'macOS Package' },
    { ext: '.iso', label: 'Disk Image' }, { ext: '.img', label: 'Disk Image' }, { ext: '.deb', label: 'Debian Pkg' },
    { ext: '.rpm', label: 'RedHat Pkg' }, { ext: '.apk', label: 'Android App' }, { ext: '.xapk', label: 'Android Bundle' },
    { ext: '.ipa', label: 'iOS App' }, { ext: '.dll', label: 'Dynamic Link Lib' }, { ext: '.sys', label: 'System File' }
];

// Helper Component for Extension Selection
const ExtensionSelector = ({ label, blocked, onChange }: { label: string, blocked: string[], onChange: (list: string[]) => void }) => {
    const isBlocked = (ext: string) => blocked.includes(ext.toLowerCase());

    const toggle = (ext: string) => {
        const lower = ext.toLowerCase();
        if (isBlocked(lower)) {
            onChange(blocked.filter(x => x !== lower));
        } else {
            onChange([...blocked, lower]);
        }
    };

    // Calculate 'custom' extensions (those in blocked but not in COMMON_EXTENSIONS)
    const commonSet = new Set(COMMON_EXTENSIONS.map(c => c.ext));
    const customExtensions = blocked.filter(x => !commonSet.has(x)).join(', ');

    const handleCustomChange = (e: any) => {
        const input = e.target.value;
        const newCustom = input.split(',').map((s: string) => s.trim().toLowerCase()).filter((s: string) => s.startsWith('.'));
        // Rebuild list: keep common ones that are checked, replace custom ones
        const currentCommon = blocked.filter(x => commonSet.has(x));
        // Merge en dedup
        const merged = Array.from(new Set([...currentCommon, ...newCustom]));
        onChange(merged);
    };

    return (
        <div className="bg-neutral-900/50 p-6 rounded-xl border border-neutral-800 mb-6">
            <h4 className="text-white font-bold mb-4 flex items-center gap-2"><Shield className="w-4 h-4 text-purple-500" /> {label}</h4>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
                {COMMON_EXTENSIONS.map(item => (
                    <label key={item.ext} className={`flex items-center gap-2 p-2 rounded border cursor-pointer transition text-xs ${isBlocked(item.ext) ? 'bg-red-500/10 border-red-500/30 text-red-200' : 'bg-black border-neutral-800 text-neutral-400 hover:border-neutral-600'}`}>
                        <div className={`w-4 h-4 rounded flex items-center justify-center border ${isBlocked(item.ext) ? 'bg-red-500 border-red-500' : 'border-neutral-600'}`}>
                            {isBlocked(item.ext) && <Check className="w-3 h-3 text-white" />}
                        </div>
                        <input type="checkbox" className="hidden" checked={isBlocked(item.ext)} onChange={() => toggle(item.ext)} />
                        <span className="font-mono">{item.ext}</span>
                    </label>
                ))}
            </div>
            <div>
                <label className="block text-neutral-400 text-xs font-bold mb-2">Custom Extensions (comma separated, must start with dot)</label>
                <input
                    className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white text-sm font-mono placeholder-neutral-600 focus:border-purple-500 outline-none transition"
                    placeholder=".xyz, .abc, .ransom"
                    value={customExtensions}
                    onChange={handleCustomChange}
                />
            </div>
        </div>
    );
};



// --- NOTIFICATION SYSTEM ---
type ToastType = 'success' | 'error' | 'info';
interface Toast { id: number; message: string; type: ToastType; }
interface UIContextType {
    notify: (msg: string, type?: ToastType) => void;
    confirm: (msg: string, onConfirm: () => void) => void;
    preview: (file: File | Blob | string, name: string, type?: string) => void;
    isConfirming: boolean;
    isPreviewing: boolean;
}

const UIContext = createContext<UIContextType | null>(null);

const UIProvider = ({ children }: { children: React.ReactNode }) => {
    const [toasts, setToasts] = useState<Toast[]>([]);
    const [confirmMessage, setConfirmMessage] = useState<string | null>(null);
    const [confirmCallback, setConfirmCallback] = useState<(() => void) | null>(null);

    // Preview State
    const [previewFile, setPreviewFile] = useState<File | Blob | string | null>(null);
    const [previewName, setPreviewName] = useState<string>('');
    const [previewType, setPreviewType] = useState<string | undefined>(undefined);

    const notify = (message: string, type: ToastType = 'info') => {
        const id = Date.now();
        setToasts(prev => [...prev, { id, message, type }]);
        setTimeout(() => removeToast(id), 5000);
    };

    const removeToast = (id: number) => setToasts(prev => prev.filter(t => t.id !== id));

    const confirm = (msg: string, onConfirm: () => void) => {
        setConfirmMessage(msg);
        setConfirmCallback(() => onConfirm);
    };

    const handleConfirm = () => {
        if (confirmCallback) confirmCallback();
        setConfirmMessage(null);
        setConfirmCallback(null);
    };

    const preview = React.useCallback((file: File | Blob | string, name: string, type?: string) => {
        setPreviewFile(file);
        setPreviewName(name);
        setPreviewType(type);
    }, []);

    const closePreview = React.useCallback(() => {
        setPreviewFile(null);
        setPreviewName('');
        setPreviewType(undefined);
    }, []);

    const cancelConfirm = () => {
        setConfirmMessage(null);
        setConfirmCallback(null);
    };

    // Esc key for Confirm Modal (High priority)
    useEscapeKey(cancelConfirm, !!confirmMessage);

    return (
        <UIContext.Provider value={{ notify, confirm, preview, isConfirming: !!confirmMessage, isPreviewing: !!previewFile }}>
            {children}
            <div className="fixed bottom-4 right-4 z-[10003] flex flex-col gap-2">
                {toasts.map(toast => (
                    <div key={toast.id} className={`p-4 rounded-xl shadow-lg text-white font-medium flex items-center gap-3 anim-slide ${toast.type === 'error' ? 'bg-red-500' :
                        toast.type === 'success' ? 'bg-green-500' :
                            'bg-neutral-800 border border-neutral-700'
                        }`}>
                        {toast.type === 'error' ? <AlertTriangle className="w-5 h-5" /> :
                            toast.type === 'success' ? <Check className="w-5 h-5" /> :
                                <Info className="w-5 h-5 text-purple-400" />}
                        {toast.message}
                        <button onClick={() => removeToast(toast.id)} className="ml-2 hover:bg-black/20 p-1 rounded"><X className="w-3 h-3" /></button>
                    </div>
                ))}
            </div>

            {/* Confirm Modal */}
            <AnimatePresence>
                {confirmMessage && (
                    <motion.div
                        key="confirm-modal"
                        initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                        animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                        exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                        className="fixed inset-0 z-[10002] flex items-center justify-center p-4 bg-black/60"
                        onClick={cancelConfirm}
                    >
                        <motion.div
                            initial={{ scale: 0.95, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            exit={{ scale: 0.95, opacity: 0 }}
                            onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            className="bg-neutral-900 border border-neutral-800 p-6 rounded-2xl shadow-2xl max-w-sm w-full"
                        >
                            <h3 className="text-xl font-bold text-white mb-2">Confirm</h3>
                            <p className="text-neutral-400 mb-6">{confirmMessage}</p>
                            <div className="flex gap-3">
                                <button onClick={() => setConfirmMessage(null)} className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-2 rounded-lg font-bold transition">Cancel</button>
                                <button onClick={handleConfirm} className="flex-1 bg-red-600 hover:bg-red-700 text-white p-2 rounded-lg font-bold transition shadow-lg shadow-red-900/20">Confirm</button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* File Preview Modal */}
            {/* File Preview Modal */}
            <AnimatePresence>
                {previewFile && (
                    <FilePreviewModal
                        file={previewFile}
                        name={previewName}
                        type={previewType}
                        onClose={closePreview}
                    />
                )}
            </AnimatePresence>
        </UIContext.Provider>
    );
};

const useUI = () => {
    const context = useContext(UIContext);
    if (!context) throw new Error("useUI must be used within UIProvider");
    return context;
};

const useAuth = () => {
    // We slaan de token NIET meer op in state/localStorage, de browser doet dit in de cookie.
    // We checken alleen of de user data er is.
    const [user, setUser] = useState<any>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        try {
            // Haal user info uit localStorage
            const storedUser = localStorage.getItem('user');

            // Check expliciet of de waarde niet "undefined" (string) is
            if (storedUser && storedUser !== "undefined" && storedUser !== "null") {
                setUser(JSON.parse(storedUser));
            } else {
                // Als het ongeldig is, ruim het dan direct op
                localStorage.removeItem('user');
            }
        } catch (e) {
            console.error("User parse error", e);
            // Bij een leesfout: schoonvegen zodat de error niet terugkomt
            localStorage.removeItem('user');
        }
        setLoading(false);
    }, []);

    const login = (u: any) => {
        // We slaan het token NIET meer op. De browser heeft het cookie al ontvangen.
        localStorage.setItem('user', JSON.stringify(u));
        setUser(u);
    };

    const logout = async () => {
        try {
            // Roep de backend aan om de cookie te wissen
            await fetch(`${API_URL}/auth/logout`, { method: 'POST', credentials: 'include' });
        } catch (e) {
            console.error("Logout request failed", e);
        }

        // Wis client-side state
        localStorage.clear();
        setUser(null);
        // Forceer een reload of redirect om zeker te zijn dat state schoon is
        window.location.href = '/login';
    };

    return { user, token: null, login, logout, loading };
};

// Auto-logout bij token expiratie
const useTokenExpiration = (token: string | null, logout: () => void) => {
    const { notify } = useUI();

    useEffect(() => {
        if (!token) return;

        try {
            // Decode JWT payload
            const payload = JSON.parse(atob(token.split('.')[1]));
            const exp = payload.exp * 1000; // Convert naar milliseconden
            const now = Date.now();
            const timeUntilExpiry = exp - now;

            // Als token al verlopen is
            if (timeUntilExpiry <= 0) {
                logout();
                notify('Session expired. Login again.', 'info');
                return;
            }

            // Stel timer in om uit te loggen 1 minuut voor expiratie
            const warningTime = Math.max(0, timeUntilExpiry - 60000);
            const timeout = setTimeout(() => {
                notify('Your session is about to expire. Save your work!', 'info');

                // Logout bij expiratie
                setTimeout(() => {
                    logout();
                    notify('Session expired. Login again.', 'info');
                }, 60000);
            }, warningTime);

            return () => clearTimeout(timeout);
        } catch (e) {
            // Ongeldige token
            console.error('Token parse error:', e);
            logout();
        }
    }, [token, logout, notify]);
};

const ModalPortal = ({ children }: { children: React.ReactNode }) => createPortal(children, document.body);

const CopyButton = ({ text, className }: { text: string, className?: string }) => {
    const [copied, setCopied] = useState(false);
    const { notify } = useUI();
    const copy = () => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        notify("Link is copied to your clipboard", "success");
        setTimeout(() => setCopied(false), 2000);
    };
    return (
        <button onClick={copy} className={`${className} transition-all duration-300 flex items-center gap-2 ${copied ? 'text-green-400 bg-green-500/10' : ''}`}>
            {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copied ? 'Copied' : text}
        </button>
    );
};

// --- CUSTOM CHECKBOX ---
const Checkbox = ({ checked, onChange, label, className = "" }: { checked: boolean, onChange: (e: React.ChangeEvent<HTMLInputElement>) => void, label?: React.ReactNode, className?: string }) => (
    <label className={`flex items-center gap-3 cursor-pointer group ${className}`}>
        <div className="relative flex items-center">
            <input
                type="checkbox"
                className="peer sr-only" // Verbergt de standaard browser checkbox
                checked={checked}
                onChange={onChange}
            />
            {/* De visuele box */}
            <div className={`
                w-5 h-5 rounded border transition-all duration-200 flex items-center justify-center shadow-sm
                ${checked
                    ? 'bg-purple-600 border-purple-600 shadow-purple-900/20'
                    : 'bg-neutral-900 border-neutral-700 group-hover:border-neutral-500' // Hier maak je de achtergrond donker!
                }
            `}>
                <Check className={`w-3.5 h-3.5 text-white transition-all duration-200 stroke-[3px] ${checked ? 'scale-100 opacity-100' : 'scale-50 opacity-0'}`} />
            </div>
        </div>
        {label && <span className="text-white font-medium select-none">{label}</span>}
    </label>
);

// --- COMPONENTS ---
const ProfileView = ({ user, config, forcedSetup = false, onComplete }: { user: any, config: any, forcedSetup?: boolean, onComplete?: () => void }) => {
    const [form, setForm] = useState({ name: user.name, email: user.email, password: '' });

    // Hulpfunctie: Haal hostname uit config.appUrl (bijv. "mijnshare.nl" of "localhost")
    const getDomain = (url: string) => {
        try {
            if (!url) return window.location.hostname;
            return new URL(url).hostname;
        } catch (e) {
            return window.location.hostname;
        }
    };
    const [tab, setTab] = useState<'general' | '2fa' | 'passkeys' | 'danger'>(forcedSetup ? '2fa' : 'general');

    // Validatie State voor Profiel
    const [pwdValid, setPwdValid] = useState({ length: false, upper: false, lower: false, number: false });

    // Update validatie bij typen (form.password gebruiken)
    useEffect(() => {
        const p = form.password;
        setPwdValid({
            length: p.length >= 8,
            upper: /[A-Z]/.test(p),
            lower: /[a-z]/.test(p),
            number: /[0-9]/.test(p)
        });
    }, [form.password]);

    // 2FA States
    const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
    const [twoFactorSecret, setTwoFactorSecret] = useState('');
    const [twoFactorQR, setTwoFactorQR] = useState('');
    const [twoFactorCode, setTwoFactorCode] = useState('');
    const [twoFactorBackupCodes, setTwoFactorBackupCodes] = useState<string[]>([]);
    const [backupCodesRemaining, setBackupCodesRemaining] = useState(0);
    const [show2FASetup, setShow2FASetup] = useState(false);
    useEffect(() => {
        if (forcedSetup && !twoFactorEnabled) {
            // We roepen de setup functie aan om QR codes te genereren
            handleSetup2FA();
        }
    }, [forcedSetup, twoFactorEnabled]);
    const [show2FADisable, setShow2FADisable] = useState(false);
    const [disable2FAPassword, setDisable2FAPassword] = useState('');

    // Passkey States
    const [passkeys, setPasskeys] = useState<any[]>([]);
    const [passkeyName, setPasskeyName] = useState('');
    const [showPasskeyAdd, setShowPasskeyAdd] = useState(false);

    // Delete Account States
    const [showDeleteAccount, setShowDeleteAccount] = useState(false);
    const [deletePassword, setDeletePassword] = useState('');

    const { notify, confirm, isConfirming, isPreviewing } = useUI();

    // Esc keys
    useEscapeKey(() => { setShow2FASetup(false); setTwoFactorSecret(''); setTwoFactorQR(''); }, show2FASetup && !isConfirming && !isPreviewing);
    useEscapeKey(() => setShow2FADisable(false), show2FADisable && !isConfirming && !isPreviewing);
    useEscapeKey(() => setShowPasskeyAdd(false), showPasskeyAdd && !isConfirming && !isPreviewing);
    useEscapeKey(() => setShowDeleteAccount(false), showDeleteAccount && !isConfirming && !isPreviewing);

    useEffect(() => {
        fetch2FAStatus();
        fetchPasskeys();
    }, []);

    const fetch2FAStatus = async () => {
        const res = await fetch(`${API_URL}/auth/2fa/status`, {
            credentials: 'include'
        });
        if (res.ok) {
            const data = await res.json();
            setTwoFactorEnabled(data.enabled);
            setBackupCodesRemaining(data.backupCodesRemaining);
        }
    };

    const fetchPasskeys = async () => {
        const res = await fetch(`${API_URL}/passkeys`, {
            credentials: 'include'
        });
        if (res.ok) {
            const data = await res.json();
            setPasskeys(data);
        }
    };

    const save = async () => {
        if (form.password && form.password.length > 0) {
            if (form.password.length < 8) {
                notify('Password needs to contain at least 8 characters', 'error');
                return;
            }
            if (!/[a-z]/.test(form.password) || !/[A-Z]/.test(form.password) || !/[0-9]/.test(form.password)) {
                notify('Password must contain at least 1 lowercase letter, 1 uppercase letter and 1 number', 'error');
                return;
            }
        }

        const res = await fetch(`${API_URL}/users/profile`, {
            method: 'PUT',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(form)
        });

        if (res.ok) {
            notify('Profile saved', 'success');
        } else {
            const data = await res.json();
            notify(data.error || 'Save failed', 'error');
        }
    };

    const handleSetup2FA = async () => {
        const res = await fetch(`${API_URL}/auth/2fa/setup`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await res.json();
        if (res.ok) {
            setTwoFactorSecret(data.secret);
            setTwoFactorQR(data.qrCode);
            setShow2FASetup(true);
        } else {
            notify(data.error || '2FA Setup failed', 'error');
        }
    };

    const handleEnable2FA = async (e: any) => {
        e.preventDefault();
        const res = await fetch(`${API_URL}/auth/2fa/enable`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret: twoFactorSecret, code: twoFactorCode })
        });
        const data = await res.json();
        if (res.ok) {
            setTwoFactorBackupCodes(data.backupCodes);
            setTwoFactorEnabled(true);
            setTwoFactorCode('');
            notify('2FA successfully enabled!', 'success');
            await fetch2FAStatus();
        } else {
            notify(data.error || '2FA activation failed', 'error');
        }
    };

    const handleDisable2FA = async (e: any) => {
        e.preventDefault();
        const res = await fetch(`${API_URL}/auth/2fa/disable`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: disable2FAPassword })
        });
        if (res.ok) {
            setTwoFactorEnabled(false);
            setShow2FADisable(false);
            setDisable2FAPassword('');
            setTwoFactorSecret('');
            setTwoFactorQR('');
            setTwoFactorBackupCodes([]);
            notify('2FA disabled', 'success');
            await fetch2FAStatus();
        } else {
            const data = await res.json();
            notify(data.error || 'Failed to disable 2FA', 'error');
        }
    };

    const handleRegisterPasskey = async () => {
        if (!passkeyName.trim()) {
            notify('Give your passkey a name', 'error');
            return;
        }

        try {
            const rpDomain = getDomain(config?.appUrl);

            // 1. Opties ophalen
            const optionsRes = await fetch(`${API_URL}/passkeys/register/options`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: passkeyName, domain: rpDomain })
            });

            if (!optionsRes.ok) throw new Error('Could not retrieve passkey options');

            const options = await optionsRes.json();

            // 2. Start Registratie - Library handelt base64url automatisch af
            let credential;
            try {
                // Moderne syntax (v9+)
                credential = await startRegistration(options);
            } catch (syntaxError) {
                console.warn("New syntax didn't work, try legacy...", syntaxError);
                // Legacy fallback
                credential = await startRegistration(options);
            }

            // 3. Verificatie naar server sturen
            const verifyRes = await fetch(`${API_URL}/passkeys/register/verify`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    response: credential,
                    name: passkeyName,
                    domain: rpDomain
                })
            });

            const verifyData = await verifyRes.json();
            if (!verifyRes.ok) throw new Error(verifyData.error || 'Passkey verification failed');

            notify('Passkey registered successfully', 'success');
            setPasskeyName('');
            setShowPasskeyAdd(false);
            await fetchPasskeys();

        } catch (err: any) {
            console.error("Passkey Error:", err);
            notify(err.message || 'Passkey registration failed', 'error');
        }
    };

    const handleDeletePasskey = async (id: number) => {
        confirm('Are you sure you want to delete this passkey?', async () => {
            const res = await fetch(`${API_URL}/passkeys/${id}`, {
                method: 'DELETE',
                credentials: 'include'
            });
            if (res.ok) {
                notify('Passkey deleted', 'success');
                await fetchPasskeys();
            } else {
                notify('Passkey deletion failed', 'error');
            }
        });
    };

    const handleDeleteAccount = async (e: any) => {
        e.preventDefault();
        confirm('Are you SURE you want to delete your account? This cannot be undone!', async () => {
            const res = await fetch(`${API_URL}/users/me/delete`, {
                method: 'DELETE',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: deletePassword })
            });
            if (res.ok) {
                notify('Account deleted successfully', 'success');
                setTimeout(() => {
                    localStorage.removeItem('token');
                    localStorage.removeItem('user');
                    window.location.href = '/login';
                }, 1000);
            } else {
                const data = await res.json();
                notify(data.error || 'Deletion failed', 'error');
            }
        });
    };

    const tabClass = (id: string) => `flex-1 text-center px-4 py-4 font-bold transition whitespace-nowrap border-b-2 cursor-pointer ${tab === id ? 'border-purple-500 text-white bg-neutral-800' : 'border-transparent text-neutral-400 hover:text-white hover:bg-neutral-800'}`;

    const handleCopyAllCodes = () => {
        const text = twoFactorBackupCodes.join('\n');
        navigator.clipboard.writeText(text);
        notify('All codes copied to clipboard', 'success');
    };

    const handleDownloadCodes = () => {
        const text = `${config.appName || 'Nexo Share'} Backup Codes\n\nKeep these codes in a safe place.\nIf you no longer have access to your authenticator app, you can use these codes to log in.\n\n${twoFactorBackupCodes.join('\n')}\n\nGenerated on: ${new Date().toLocaleString('en-GB')}`;
        // Create Blob URL
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);

        // Use direct download trigger via existing anchor or new approach
        // Snyk flags appendChild. Let's use a simpler approach.
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;

        let safeAppName = (config.appName || 'Nexo Share').replace(/[^a-zA-Z0-9_\-]/g, '').trim();
        if (!safeAppName) safeAppName = "Nexo-Share";

        a.setAttribute('download', `${safeAppName}-backup-codes.txt`);
        document.body.appendChild(a);
        a.click();

        // Clean up
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);

        notify('Codes downloaded', 'success');
    };

    return (
        <div className="max-w-4xl mx-auto anim-slide">
            <div className="bg-neutral-900 rounded-xl border border-neutral-800 shadow-xl overflow-hidden">
                {/* VERBERG TABS BIJ FORCED SETUP */}
                {!forcedSetup && (
                    <div className="flex border-b border-neutral-800 overflow-x-auto scrollbar-hide">
                        <button onClick={() => setTab('general')} className={tabClass('general')}>General</button>
                        <button onClick={() => setTab('2fa')} className={tabClass('2fa')}>2FA</button>
                        <button onClick={() => setTab('passkeys')} className={tabClass('passkeys')}>Passkeys</button>
                        <button onClick={() => setTab('danger')} className={tabClass('danger')}>Danger Zone</button>
                    </div>
                )}

                <div className="p-4 md:p-8">
                    {tab === 'general' && (
                        <div className="space-y-4">
                            <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-2"><User className="text-purple-500" /> My profile</h2>
                            <div><label className="block text-neutral-400 text-sm font-bold mb-2">Name</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div>
                            <div><label className="block text-neutral-400 text-sm font-bold mb-2">Email</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} /></div>
                            {/* Password Sectie */}
                            <div className="pt-4 border-t border-neutral-800 mt-4">
                                <h3 className="text-white font-bold mb-4 flex items-center gap-2">
                                    <LockIcon className="w-4 h-4 text-purple-500" /> Change Password
                                </h3>

                                <div className="grid gap-4">
                                    {/* 1. Huidig Password (Altijd zichtbaar, bovenaan) */}
                                    <div>
                                        <label className="block text-neutral-400 text-sm font-bold mb-2">Current Password</label>
                                        <input
                                            className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none"
                                            type="password"
                                            placeholder="Your current password (required for changing)"
                                            value={(form as any).currentPassword || ''}
                                            onChange={e => setForm({ ...form, currentPassword: e.target.value } as any)}
                                        />
                                    </div>

                                    {/* 2. Nieuw Password */}
                                    <div>
                                        <label className="block text-neutral-400 text-sm font-bold mb-2">New Password</label>
                                        <input
                                            className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none"
                                            type="password"
                                            placeholder="New password (leave blank if you don't want to change it)"
                                            value={form.password}
                                            onChange={e => setForm({ ...form, password: e.target.value })}
                                        />
                                    </div>
                                </div>

                                {/* Validatie Box (Alleen tonen als er een nieuw Password wordt getypt) */}
                                {form.password.length > 0 && (
                                    <div className="mt-3 grid grid-cols-2 gap-2 text-xs p-3 bg-neutral-900/50 rounded-lg border border-neutral-800 anim-slide">
                                        <div className={`flex items-center gap-1.5 ${pwdValid.length ? 'text-green-500' : 'text-neutral-500'}`}>
                                            {pwdValid.length ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} 8+ characters
                                        </div>
                                        <div className={`flex items-center gap-1.5 ${pwdValid.upper ? 'text-green-500' : 'text-neutral-500'}`}>
                                            {pwdValid.upper ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Upper case
                                        </div>
                                        <div className={`flex items-center gap-1.5 ${pwdValid.lower ? 'text-green-500' : 'text-neutral-500'}`}>
                                            {pwdValid.lower ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Lower case
                                        </div>
                                        <div className={`flex items-center gap-1.5 ${pwdValid.number ? 'text-green-500' : 'text-neutral-500'}`}>
                                            {pwdValid.number ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Number
                                        </div>
                                    </div>
                                )}
                            </div>
                            <button onClick={save} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 text-white px-6 py-3 rounded-lg font-bold mt-4 transition btn-press w-full">Save</button>
                        </div>
                    )}

                    {tab === '2fa' && (
                        <div className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h2 className="text-2xl font-bold text-white mb-2 flex items-center gap-2"><Shield className="text-purple-500" /> Two-factor authentication</h2>
                                    <p className="text-neutral-400">Extra security for your account</p>
                                </div>
                                <div className={`px-4 py-2 rounded-lg font-bold ${twoFactorEnabled ? 'bg-green-500/20 text-green-400' : 'bg-neutral-800 text-neutral-400'}`}>
                                    {twoFactorEnabled ? 'Active' : 'Inactive'}
                                </div>
                            </div>

                            {twoFactorEnabled ? (
                                <div className="bg-neutral-800/50 rounded-lg p-6 border border-neutral-700">
                                    <div className="flex items-center justify-between mb-4">
                                        <div>
                                            <p className="text-white font-bold">2FA is enabled</p>
                                            <p className="text-neutral-400 text-sm">Backup codes remaining: {backupCodesRemaining}</p>
                                        </div>
                                        <button onClick={() => setShow2FADisable(true)} className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-bold transition btn-press">
                                            Disable
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <div className="bg-neutral-800/50 rounded-lg p-6 border border-neutral-700">
                                    <p className="text-neutral-300 mb-4">Enable two-factor authentication for extra security of your account.</p>
                                    <button onClick={handleSetup2FA} className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-3 rounded-lg font-bold transition btn-press">
                                        Set up 2FA
                                    </button>
                                </div>
                            )}
                        </div>
                    )}

                    {tab === 'passkeys' && (
                        <div className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h2 className="text-2xl font-bold text-white mb-2 flex items-center gap-2"><Shield className="text-purple-500" /> Passkeys</h2>
                                    <p className="text-neutral-400">Log in without password</p>
                                </div>
                                <button onClick={() => setShowPasskeyAdd(true)} className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg font-bold transition btn-press flex items-center gap-2">
                                    <Plus className="w-4 h-4" /> Add Passkey
                                </button>
                            </div>

                            {passkeys.length === 0 ? (
                                <div className="bg-neutral-800/50 rounded-lg p-8 border border-neutral-700 text-center">
                                    <Shield className="w-16 h-16 text-neutral-600 mx-auto mb-4" />
                                    <p className="text-neutral-400">No passkeys configured</p>
                                </div>
                            ) : (
                                <div className="space-y-3">
                                    {passkeys.map(pk => (
                                        <div key={pk.id} className="bg-neutral-800/50 rounded-lg p-4 border border-neutral-700 flex items-center justify-between">
                                            <div>
                                                <p className="text-white font-bold">{pk.name}</p>
                                                <p className="text-neutral-400 text-sm">Added: {new Date(pk.created_at).toLocaleDateString(config.appLocale || 'en-GB')}</p>
                                            </div>
                                            <button onClick={() => handleDeletePasskey(pk.id)} className="text-red-400 hover:text-red-300 p-2 rounded-lg hover:bg-red-500/10 transition">
                                                <Trash2 className="w-5 h-5" />
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}

                    {tab === 'danger' && (
                        <div className="space-y-6">
                            <h2 className="text-2xl font-bold text-red-500 mb-4 flex items-center gap-2"><AlertCircle /> Danger Zone</h2>
                            <div className="bg-red-500/10 rounded-lg p-6 border border-red-500/30">
                                <h3 className="text-white font-bold mb-2">Delete account</h3>
                                <p className="text-neutral-400 text-sm mb-4">
                                    This will permanently delete your account and all associated data. This action cannot be undone.
                                </p>
                                <button onClick={() => setShowDeleteAccount(true)} className="bg-red-600 hover:bg-red-700 text-white px-6 py-3 rounded-lg font-bold transition btn-press">
                                    Delete account
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* 2FA Setup Modal */}
            <AnimatePresence>
                {show2FASetup && (
                    <ModalPortal>
                        <motion.div
                            key="2fa-setup-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 z-[9999] flex items-center justify-center p-4"
                            onClick={() => { setShow2FASetup(false); setTwoFactorSecret(''); setTwoFactorQR(''); }}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full shadow-2xl"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h2 className="text-2xl font-bold mb-4 text-white">Configure 2FA</h2>

                                {twoFactorBackupCodes.length === 0 ? (
                                    <>
                                        <p className="text-neutral-300 mb-4">Scan this QR code with your authenticator app:</p>

                                        {/* Witte achtergrond voor QR zorgt voor beter contrast */}
                                        <div className="bg-white p-2 rounded-lg mb-4 flex justify-center">
                                            {twoFactorQR && (twoFactorQR.startsWith('data:image/') || twoFactorQR.startsWith('https://')) ?
                                                <img src={twoFactorQR} className="rounded max-h-48" alt="2FA QR Code" />
                                                : null
                                            }
                                        </div>

                                        <div className="bg-black rounded-lg p-3 mb-4 border border-neutral-800">
                                            <p className="text-neutral-400 text-xs mb-1">Or enter manually:</p>
                                            <p className="text-white font-mono text-sm break-all select-all">{twoFactorSecret}</p>
                                        </div>

                                        <form onSubmit={handleEnable2FA}>
                                            <input
                                                type="text"
                                                className="w-full bg-black border border-neutral-700 text-white rounded-lg p-3 mb-4 focus:border-purple-500 outline-none text-center text-2xl tracking-widest"
                                                placeholder="000000"
                                                value={twoFactorCode}
                                                onChange={e => setTwoFactorCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                                maxLength={6}
                                                required
                                            />
                                            <div className="flex gap-3">
                                                <button type="button" onClick={() => { setShow2FASetup(false); setTwoFactorSecret(''); setTwoFactorQR(''); }} className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press border border-neutral-700">
                                                    Cancel
                                                </button>
                                                <button type="submit" className="flex-1 bg-purple-600 hover:bg-purple-700 text-white p-3 rounded-lg font-bold transition btn-press shadow-[0_0_15px_rgba(147,51,234,0.3)]">
                                                    Activate
                                                </button>
                                            </div>
                                        </form>
                                    </>
                                ) : (
                                    <>
                                        <p className="text-green-400 mb-4 font-bold flex items-center gap-2">✓ 2FA successfully enabled!</p>

                                        <p className="text-neutral-300 text-sm mb-4">
                                            These are your backup codes. Keep them safe! You'll need them if you lose your phone.
                                        </p>

                                        {/* --- KNOPPEN VOOR ALLES --- */}
                                        <div className="flex gap-3 mb-4">
                                            <button
                                                onClick={handleDownloadCodes}
                                                className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press border border-neutral-700 flex items-center justify-center gap-2"
                                            >
                                                <Download className="w-4 h-4" /> Download .txt
                                            </button>
                                            <button
                                                onClick={handleCopyAllCodes}
                                                className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press border border-neutral-700 flex items-center justify-center gap-2"
                                            >
                                                <Copy className="w-4 h-4" /> Copy everything
                                            </button>
                                        </div>

                                        <div className="bg-black rounded-lg p-4 mb-4 space-y-2 max-h-60 overflow-y-auto border border-neutral-800">
                                            {twoFactorBackupCodes.map((code, i) => (
                                                <div key={i} className="flex items-center justify-center bg-neutral-900 p-2 rounded border border-neutral-800">
                                                    <code className="text-white font-mono text-lg tracking-widest">{code}</code>
                                                </div>
                                            ))}
                                        </div>

                                        <button onClick={() => { setShow2FASetup(false); setTwoFactorBackupCodes([]); setTwoFactorSecret(''); setTwoFactorQR(''); if (onComplete) onComplete(); }} className="w-full bg-purple-600 hover:bg-purple-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                            I saved them, Close
                                        </button>
                                    </>
                                )}
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>

            {/* 2FA Disable Modal */}
            <AnimatePresence>
                {show2FADisable && (
                    <ModalPortal>
                        <motion.div
                            key="2fa-disable-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50"
                            onClick={() => setShow2FADisable(false)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h2 className="text-2xl font-bold mb-4 text-white">Disable 2FA</h2>
                                <p className="text-neutral-300 mb-4">Enter your password to disable 2FA:</p>
                                <form onSubmit={handleDisable2FA}>
                                    <input type="password" autoComplete="current-password" className="w-full bg-black border border-neutral-700 text-white rounded-lg p-3 mb-4 focus:border-purple-500 outline-none" placeholder="Password" value={disable2FAPassword} onChange={e => setDisable2FAPassword(e.target.value)} required />
                                    <div className="flex gap-3">
                                        <button type="button" onClick={() => { setShow2FADisable(false); setDisable2FAPassword(''); }} className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                            Cancel
                                        </button>
                                        <button type="submit" className="flex-1 bg-red-600 hover:bg-red-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                            Turn off
                                        </button>
                                    </div>
                                </form>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>

            {/* Passkey Add Modal */}
            <AnimatePresence>
                {showPasskeyAdd && (
                    <ModalPortal>
                        <motion.div
                            key="passkey-add-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50"
                            onClick={() => setShowPasskeyAdd(false)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h2 className="text-2xl font-bold mb-4 text-white">Add Passkey</h2>
                                <p className="text-neutral-300 mb-4">Give your passkey a recognizable name:</p>
                                <input type="text" className="w-full bg-black border border-neutral-700 text-white rounded-lg p-3 mb-4 focus:border-purple-500 outline-none" placeholder="For example: iPhone, Windows Hello, YubiKey" value={passkeyName} onChange={e => setPasskeyName(e.target.value)} />
                                <div className="flex gap-3">
                                    <button onClick={() => { setShowPasskeyAdd(false); setPasskeyName(''); }} className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                        Cancel
                                    </button>
                                    <button onClick={handleRegisterPasskey} className="flex-1 bg-purple-600 hover:bg-purple-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                        Register
                                    </button>
                                </div>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>

            {/* Delete Account Modal */}
            {/* Delete Account Modal */}
            <AnimatePresence>
                {showDeleteAccount && (
                    <ModalPortal>
                        <motion.div
                            key="delete-account-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50"
                            onClick={() => setShowDeleteAccount(false)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 p-8 rounded-2xl border border-red-500/50 max-w-md w-full"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h2 className="text-2xl font-bold mb-4 text-red-500 flex items-center gap-2"><AlertCircle /> Delete Account</h2>
                                <p className="text-neutral-300 mb-4">This action <strong>cannot</strong> be undone. All your data will be permanently deleted.</p>
                                <form onSubmit={handleDeleteAccount}>
                                    <label className="block text-neutral-400 text-sm font-bold mb-2">Enter your password to confirm:</label>
                                    <input type="password" autoComplete="current-password" className="w-full bg-black border border-neutral-700 text-white rounded-lg p-3 mb-4 focus:border-red-500 outline-none" placeholder="Password" value={deletePassword} onChange={e => setDeletePassword(e.target.value)} required />
                                    <div className="flex gap-3">
                                        <button type="button" onClick={() => { setShowDeleteAccount(false); setDeletePassword(''); }} className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                            Cancel
                                        </button>
                                        <button type="submit" className="flex-1 bg-red-600 hover:bg-red-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                            Delete permanently
                                        </button>
                                    </div>
                                </form>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>
        </div>
    );
};

// --- Folder Upload Parsing ---
interface UploadItem {
    file: File | null; // Null if it's a directory
    path: string;
    name: string; // Display name
    id: string;
    isDirectory: boolean;
    size: number;
}

const traverseFileTree = async (item: any, path = ''): Promise<UploadItem[]> => {
    return new Promise((resolve) => {
        if (item.isFile) {
            item.file((file: any) => {
                const fullPath = path + file.name;
                resolve([{
                    file,
                    path: fullPath,
                    name: file.name,
                    id: generateUUID(),
                    isDirectory: false,
                    size: file.size
                }]);
            });
        } else if (item.isDirectory) {
            // Add the directory itself as an item!
            const dirFullPath = path + item.name;
            const dirItem: UploadItem = {
                file: null,
                path: dirFullPath,
                name: item.name,
                id: generateUUID(),
                isDirectory: true,
                size: 0
            };

            const dirReader = item.createReader();
            const entries: any[] = [];

            const readEntries = () => {
                dirReader.readEntries(async (batch: any[]) => {
                    if (batch.length > 0) {
                        entries.push(...batch);
                        readEntries();
                    } else {
                        const promises = entries.map(entry => traverseFileTree(entry, path + item.name + '/'));
                        const results = await Promise.all(promises);
                        // Return directory item + children
                        resolve([dirItem, ...results.flat()]);
                    }
                });
            };
            readEntries();
        } else {
            resolve([]);
        }
    });
};

// --- File System Access API Interfaces ---
interface FileSystemHandle {
    kind: 'file' | 'directory';
    name: string;
}
interface FileSystemFileHandle extends FileSystemHandle {
    kind: 'file';
    getFile(): Promise<File>;
}
interface FileSystemDirectoryHandle extends FileSystemHandle {
    kind: 'directory';
    values(): AsyncIterableIterator<FileSystemHandle>;
}

// --- Helper: Recursive Handle Reader ---
const processHandle = async (handle: FileSystemHandle, path = ''): Promise<UploadItem[]> => {
    if (handle.kind === 'file') {
        const fileHandle = handle as FileSystemFileHandle;
        const file = await fileHandle.getFile();
        const fullPath = path + file.name;
        return [{
            file,
            path: fullPath,
            name: file.name,
            id: generateUUID(),
            isDirectory: false,
            size: file.size
        }];
    } else if (handle.kind === 'directory') {
        const dirHandle = handle as FileSystemDirectoryHandle;
        const dirFullPath = path + handle.name;

        // Create directory item
        const dirItem: UploadItem = {
            file: null,
            path: dirFullPath,
            name: handle.name,
            id: generateUUID(),
            isDirectory: true,
            size: 0
        };

        const results: UploadItem[] = [dirItem];

        // Recursively read children
        for await (const entry of dirHandle.values()) {
            const children = await processHandle(entry, path + handle.name + '/');
            results.push(...children);
        }

        return results;
    }
    return [];
};

const sortFiles = (items: UploadItem[]): UploadItem[] => {
    return items.sort((a, b) => a.path.localeCompare(b.path));
};

const synthesizeDirectoryItems = (items: UploadItem[]): UploadItem[] => {
    const existingPaths = new Set(items.map(i => i.path));
    const foldersToAdd = new Map<string, UploadItem>();

    items.forEach(item => {
        const parts = item.path.split('/');
        let currentPath = '';
        for (let i = 0; i < parts.length - 1; i++) {
            const part = parts[i];
            currentPath = currentPath ? `${currentPath}/${part}` : part;

            if (!existingPaths.has(currentPath) && !foldersToAdd.has(currentPath)) {
                foldersToAdd.set(currentPath, {
                    file: null,
                    path: currentPath,
                    name: part,
                    id: generateUUID(),
                    isDirectory: true,
                    size: 0
                });
            }
        }
    });

    return [...foldersToAdd.values(), ...items];
};




const UploadView = () => {
    const [files, setFiles] = useState<UploadItem[]>([]);
    const [uploading, setUploading] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [result, setResult] = useState<any>(null);
    const [showSettings, setShowSettings] = useState(false);
    const [options, setOpts] = useState({
        name: '', password: '', recipients: '', message: '', customSlug: '',
        expirationVal: 1, expirationUnit: 'Weeks',
        maxDownloads: undefined as number | undefined
    });
    const [idLength, setIdLength] = useState(12);
    const [contacts, setContacts] = useState<any[]>([]);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const folderInputRef = useRef<HTMLInputElement>(null); // Nieue Ref voor mappen
    const { notify, preview, isConfirming, isPreviewing } = useUI();

    useEscapeKey(() => setShowSettings(false), showSettings && !isConfirming && !isPreviewing);
    const [locale, setLocale] = useState('en-GB');
    const [maxLimitLabel, setMaxLimitLabel] = useState('');

    useEffect(() => {
        const loadData = async () => {
            try {
                const res = await fetch(`${API_URL}/contacts`, { credentials: 'include' });
                if (res.ok) {
                    const data = await res.json();
                    if (Array.isArray(data)) setContacts(data);
                }
            } catch (e) { console.error(e); }
        };
        loadData();
        fetch(`${API_URL}/config`, { credentials: 'include' }).then(r => r.json()).then(cfg => {
            if (cfg.appLocale) setLocale(cfg.appLocale);
            if (cfg.shareIdLength) {
                setIdLength(parseInt(cfg.shareIdLength));
                generateId(parseInt(cfg.shareIdLength));
            }
            // Zet defaults vanuit config
            setOpts(prev => ({
                ...prev,
                expirationVal: cfg.defaultExpirationVal || 1,
                expirationUnit: cfg.defaultExpirationUnit || 'Weeks'
            }));
            const maxVal = cfg.maxSizeVal || 10; // Default fallback
            const maxUnit = cfg.maxSizeUnit || 'GB';
            setMaxLimitLabel(`${maxVal} ${maxUnit}`);
        });
    }, []);

    const generateId = async (len: number) => {
        try {
            const res = await fetch(`${API_URL}/utils/generate-id?length=${len}`, { credentials: 'include' });
            const data = await res.json();
            if (data.id) setOpts(prev => ({ ...prev, customSlug: data.id }));
        } catch (e) { console.error(e); }
    };

    const handleDrop = async (e: any) => {
        e.preventDefault();

        const items = e.dataTransfer.items;
        if (items) {
            const promises = [];
            for (let i = 0; i < items.length; i++) {
                const item = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null;
                if (item) {
                    promises.push(traverseFileTree(item));
                } else if (items[i].kind === 'file') {
                    // Fallback
                    const f = items[i].getAsFile();
                    if (f) promises.push(Promise.resolve([{
                        file: f,
                        path: f.name,
                        name: f.name,
                        id: generateUUID(),
                        isDirectory: false,
                        size: f.size
                    }]));
                }
            }
            const results = await Promise.all(promises);
            let flatFiles = results.flat();

            // Consolidate and Sort
            setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...flatFiles])));
        } else if (e.target.files) {
            // Fallback
            const newFiles = Array.from(e.target.files as FileList).map((f: any) => ({
                file: f,
                path: f.webkitRelativePath || f.name,
                name: f.name,
                id: generateUUID(),
                isDirectory: false,
                size: f.size
            }));
            setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...newFiles])));
        }

        // Reset inputs
        if (e.target.value) e.target.value = '';
    };

    const handleFileSelect = (e: any) => {
        if (e.target.files) {
            const newFiles = Array.from(e.target.files as FileList).map((f: any) => ({
                file: f,
                path: f.webkitRelativePath || f.name,
                name: f.name,
                id: generateUUID(),
                isDirectory: false,
                size: f.size
            }));

            setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...newFiles])));
            e.target.value = '';
        }
    };

    // --- On Pick Folder: Native API with Fallback ---
    const onPickFolder = async () => {
        try {
            // @ts-ignore: API might not be in standard definitions yet
            if (window.showDirectoryPicker) {
                // @ts-ignore
                const dirHandle = await window.showDirectoryPicker();
                const items = await processHandle(dirHandle);
                setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...items]))); // synthesize call ensures robustness even if API returns perfect structure
            } else {
                // Fallback for Safari/Firefox
                folderInputRef.current?.click();
            }
        } catch (err: any) {
            // AbortError means user cancelled, ignore.
            if (err.name !== 'AbortError') {
                console.error('Folder pick failed, trying fallback...', err);
                folderInputRef.current?.click();
            }
        }
    };

    const handleUpload = async () => {
        setUploading(true);
        setShowSettings(false);
        setUploadProgress(0);
        let currentShareId: string | null = null; // ID onthouden voor cleanup

        try {
            const configRes = await fetch(`${API_URL}/config`, { credentials: 'include' });
            const config = await configRes.json();

            // 1. VOORAF CHECKEN OP LIMIETEN
            const k = 1024;
            const sizeMap: any = { 'KB': k, 'MB': k * k, 'GB': k * k * k, 'TB': k * k * k * k };
            const maxBytes = (config.maxSizeVal || 10) * (sizeMap[config.maxSizeUnit] || sizeMap['MB']);

            const uploadableFiles = files.filter(f => !f.isDirectory && f.file); // Filter out folders for upload mechanics
            const totalUploadSize = uploadableFiles.reduce((acc, item) => acc + item.size, 0);

            if (totalUploadSize > maxBytes) {
                throw new Error(`Total size (${formatBytes(totalUploadSize)}) exceeds the limit of ${config.maxSizeVal} ${config.maxSizeUnit}.`);
            }

            const chunkSizeVal = config.chunkSizeVal || 50;
            const chunkSizeUnit = config.chunkSizeUnit || 'MB';
            const CHUNK_SIZE = chunkSizeVal * (sizeMap[chunkSizeUnit] || sizeMap['MB']);

            const initPayload = { ...options };
            const initRes = await axios.post(`${API_URL}/shares/init`, initPayload);

            if (!initRes.data.success) throw new Error('Initialization failed');

            const shareId = initRes.data.shareId;
            currentShareId = shareId;

            const uploadedFilesMeta = [];
            let uploadedBytes = 0;
            let totalBytes = totalUploadSize;

            // We use standard loop to handle async await in order
            for (const item of uploadableFiles) {
                const file = item.file as File;
                const fileId = generateUUID();
                const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

                for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                    const start = chunkIndex * CHUNK_SIZE;
                    const end = Math.min(start + CHUNK_SIZE, file.size);
                    const chunk = file.slice(start, end);

                    const fd = new FormData();
                    fd.append('chunk', chunk);
                    fd.append('chunkIndex', chunkIndex.toString());
                    fd.append('totalChunks', totalChunks.toString());
                    fd.append('fileName', file.name);
                    fd.append('fileId', fileId);

                    // --- RETRY LOGICA (AUTO-HERSTEL) ---
                    let attempts = 0;
                    const maxAttempts = 10;
                    let success = false;

                    while (!success && attempts < maxAttempts) {
                        try {
                            await axios.post(`${API_URL}/shares/${shareId}/chunk`, fd);
                            success = true;
                        } catch (err) {
                            attempts++;
                            console.warn(`Chunk ${chunkIndex} failed, retrying (${attempts}/${maxAttempts})...`);
                            if (attempts >= maxAttempts) throw new Error(`Upload failed after ${maxAttempts} attempts.`);
                            await new Promise(res => setTimeout(res, 1000 * attempts)); // Backoff
                        }
                    }

                    uploadedBytes += chunk.size;
                    setUploadProgress(Math.round((uploadedBytes * 100) / totalBytes));
                }

                uploadedFilesMeta.push({
                    fileName: file.name,
                    originalName: item.path, // Use the Wrapper Path!
                    fileId: fileId,
                    size: file.size,
                    mimeType: file.type
                });
            }

            setUploadProgress(99);
            const finalRes = await axios.post(`${API_URL}/shares/${shareId}/finalize`, {
                files: uploadedFilesMeta
            });

            if (finalRes.data.success) {
                setResult(finalRes.data);
                setFiles([]);
                notify("Successfully uploaded!", "success");
            }

        } catch (e: any) {
            // 2. CLEANUP: VERWIJDER LEGE MAP BIJ FOUTEN
            if (currentShareId) {
                try {
                    console.log('Cleaning up failed share:', currentShareId);
                    await axios.delete(`${API_URL}/shares/${currentShareId}`);
                } catch (cleanupErr) { console.error("Cleanup failed", cleanupErr); }
            }

            const msg = e.response?.data?.error || e.message || 'Upload failed';
            notify(msg, "error");
        } finally {
            setUploading(false);
            setUploadProgress(0);
        }
    };

    const reset = () => {
        setResult(null);
        setOpts({
            name: '', password: '', recipients: '', message: '', customSlug: '',
            expirationVal: 1, expirationUnit: 'Weeks', maxDownloads: undefined
        });
        generateId(idLength);
    };

    // QR Logic binnen de component
    const [qrCode, setQrCode] = useState<string | null>(null);

    useEffect(() => {
        if (result?.shareUrl) {
            fetch(`${API_URL}/utils/qr?url=${encodeURIComponent(result.shareUrl)}`)
                .then(r => r.json())
                .then(d => setQrCode(d.qr))
                .catch(console.error);
        }
    }, [result]);

    if (result) return (
        <div className="bg-neutral-900 p-4 md:p-8 rounded-2xl border border-neutral-800 text-center max-w-xl mx-auto mt-10 shadow-2xl anim-scale">
            <div className="w-16 h-16 md:w-20 md:h-20 bg-purple-600/20 rounded-full flex items-center justify-center mx-auto mb-4 md:mb-6"><Check className="text-purple-500 w-8 h-8 md:w-10 md:h-10" /></div>
            <h2 className="text-2xl md:text-3xl font-bold text-white mb-2">Files Shared!</h2>
            <p className="text-neutral-400 mb-6">The recipients have been notified.</p>

            <div className="bg-black/50 p-4 rounded-xl mb-6 border border-neutral-800">
                <div className="flex items-center gap-3 mb-4">
                    <CopyButton text={result.shareUrl} className="flex-1 bg-transparent text-white px-2 outline-none font-mono text-sm justify-center break-all whitespace-normal text-center" />
                </div>
                {/* QR Code Sectie - Klikbaar om te kopiëren */}
                {qrCode && (
                    <div className="flex flex-col items-center justify-center pt-6 border-t border-neutral-800 mt-4">
                        <div
                            className="group relative bg-white p-3 rounded-xl mb-3 cursor-pointer transition-transform hover:scale-105 active:scale-95 shadow-lg"
                            onClick={async () => {
                                try {
                                    const res = await fetch(qrCode);
                                    const blob = await res.blob();
                                    // Schrijf de afbeelding naar klembord
                                    await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
                                    // Visuele feedback (simpel alert of toast, hier gebruiken we even button tekst feedback hack of gewoon alert)
                                    // Voor nu een simpele log/alert, in productie zou je een toast notification doen.
                                    const el = document.getElementById('qr-hint');
                                    if (el) { el.innerText = "Copied!"; setTimeout(() => el.innerText = "Click to copy QR", 2000); }
                                } catch (e) {
                                    console.error('Copy failed', e);
                                }
                            }}
                        >
                            {qrCode && (qrCode.startsWith('data:image/') || qrCode.startsWith('https://')) ?
                                <img src={qrCode} alt="QR Code" className="w-32 h-32" />
                                : null
                            }

                            {/* Hover Overlay */}
                            <div className="absolute inset-0 bg-black/0 group-hover:bg-black/10 rounded-xl flex items-center justify-center transition-colors">
                                <Copy className="text-transparent group-hover:text-black/50 w-8 h-8 transition-colors" />
                            </div>
                        </div>
                        <p id="qr-hint" className="text-xs text-neutral-500 font-medium transition-colors">Click to copy QR</p>
                    </div>
                )}
            </div>
            <button onClick={reset} className="text-neutral-400 hover:text-white underline transition">Create new share</button>
        </div>
    );

    return (
        <div className="relative anim-fade">
            <div className="bg-neutral-900 border-2 border-dashed border-neutral-800 rounded-2xl md:p-10 flex flex-col items-center justify-center min-h-[250px] md:min-h-[300px] hover:border-purple-500 hover:bg-neutral-900/80 transition-all duration-300 group relative overflow-hidden"
                onDragOver={e => e.preventDefault()}
                onDrop={handleDrop}
            >
                {/* 1. Invisible Click Overlay for File Upload - Acts as background click */}
                <div
                    className="absolute inset-0 z-0 cursor-pointer"
                    onClick={() => fileInputRef.current?.click()}
                />

                {/* 2. Hidden Inputs */}
                <input ref={fileInputRef} type="file" multiple className="hidden" onChange={handleFileSelect} />
                {/* @ts-ignore: Directory attribute is standard but TS might complain without proper types */}
                <input ref={folderInputRef} type="file" multiple webkitdirectory="" directory="" className="hidden" onChange={handleFileSelect} />

                {/* 3. Content - Pointer events none on text/icon so clicks fall through to overlay */}
                <div className="relative z-10 pointer-events-none flex flex-col items-center p-6">
                    <div className="bg-black p-3 md:p-4 rounded-full mb-3 md:mb-4 group-hover:scale-110 transition-transform duration-300"><Upload className="w-8 h-8 md:w-10 md:h-10 text-purple-500" /></div>
                    <h2 className="text-xl md:text-2xl font-bold text-white mb-2">Upload files or folders</h2>
                    <p className="text-sm md:text-base text-neutral-400 text-center max-w-sm">Drag files & folders here, or click to browse files.</p>
                </div>

                {/* 4. Buttons - High Z-Index to catch their own clicks */}
                <div className="relative z-20 flex gap-3 mt-0 pb-6 pointer-events-auto">
                    <button onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }} className="text-xs bg-neutral-800 hover:bg-neutral-700 text-white px-3 py-2 rounded-lg transition border border-neutral-700 cursor-pointer hover:border-purple-500">Select Files</button>
                    <button onClick={(e) => { e.stopPropagation(); onPickFolder(); }} className="text-xs bg-neutral-800 hover:bg-neutral-700 text-white px-3 py-2 rounded-lg transition border border-neutral-700 flex items-center gap-2 cursor-pointer hover:border-purple-500"><FolderIcon className="w-3 h-3" /> Select Folder</button>
                </div>
                {maxLimitLabel && (
                    <div className="mt-0 px-3 py-1 rounded-full bg-neutral-800 border border-neutral-700 text-xs text-neutral-400 font-medium group-hover:border-purple-500/30 group-hover:text-purple-300 transition-colors mb-4 md:mb-0">
                        Max size: {maxLimitLabel}
                    </div>
                )}
            </div>

            {files.length > 0 && (
                <div className="mt-2 anim-slide bg-neutral-900 rounded-2xl border border-neutral-800 overflow-hidden shadow-xl" style={{ "--indent-step": "24px" } as React.CSSProperties}>
                    <style>{`@media (max-width: 768px) { .anim-slide { --indent-step: 12px !important; } }`}</style>
                    <div className="max-h-[300px] overflow-y-auto">
                        {files.map((item) => {
                            // Calculate depth for indentation
                            // Example path: Folder/Sub/file.txt (depth 2)
                            // Example folder: Folder/Sub (depth 1)
                            const segments = item.path.split('/');
                            // If it is a folder, it doesn't have a filename at the end, so segments length matches depth closer?
                            // Actually, just using split length - 1 works well if paths are consistent.
                            const depth = Math.max(0, segments.length - 1);
                            // Responsive indentation using CSS variable defined in parent or fallback
                            // We use style with calc for responsive indent

                            return (
                                <div key={item.id} className={`flex justify-between items-center px-3 py-2 md:px-4 md:py-3 border-b border-neutral-800 last:border-0 hover:bg-neutral-800/50 transition gap-2 ${item.isDirectory ? 'bg-neutral-800/30' : ''}`}>
                                    <div
                                        className="flex items-center gap-2 md:gap-4 overflow-hidden flex-1 min-w-0 cursor-pointer"
                                        style={{ paddingLeft: `calc(${depth} * var(--indent-step, 12px))` }}
                                        onClick={() => !item.isDirectory && item.file && preview(item.file, item.name)}
                                    >
                                        <div className="bg-black p-2 rounded-lg flex-shrink-0 relative">
                                            {item.isDirectory ? (
                                                <FolderIcon className="w-4 h-4 text-purple-400" />
                                            ) : (
                                                <div className="uppercase text-xs font-bold text-purple-400">{item.name.split('.').pop()}</div>
                                            )}
                                            {depth > 0 && <div className="absolute -left-3 top-1/2 -translate-y-1/2 w-2 h-[1px] bg-neutral-600"></div>}
                                        </div>
                                        <div className="min-w-0 flex-1">
                                            <p className={`text-white font-medium truncate text-sm md:text-base ${item.isDirectory ? 'text-purple-300' : ''}`}>{item.name}</p>
                                            {!item.isDirectory && (
                                                <p className="text-neutral-500 text-xs flex gap-2">
                                                    <span>{formatBytes(item.size)}</span>
                                                </p>
                                            )}
                                        </div>
                                    </div>
                                    <button
                                        onClick={(e) => { e.stopPropagation(); item.file && preview(item.file, item.name); }}
                                        className="text-neutral-500 hover:text-white p-2 transition flex-shrink-0 hidden md:block"
                                        title="Preview"
                                    >
                                        <Eye className="w-4 h-4 md:w-5 md:h-5" />
                                    </button>
                                    <button onClick={(e) => {
                                        e.stopPropagation();
                                        // If removing a directory, maybe remove all children? For now just remove the item.
                                        // Smart removal: remove this item AND any item that starts with its path!
                                        setFiles(files.filter(x => x.id !== item.id && !x.path.startsWith(item.path + '/')))
                                    }} className="text-neutral-500 hover:text-red-400 p-2 transition flex-shrink-0"><X className="w-4 h-4 md:w-5 md:h-5" /></button>
                                </div>
                            )
                        })}
                    </div>

                    {/* PROGRESS BAR */}
                    {uploading && (
                        <div className="px-4 py-3 bg-black border-t border-neutral-800">
                            <div className="flex justify-between text-xs text-neutral-400 mb-1">
                                <span>Uploading...</span>
                                <span>{uploadProgress}%</span>
                            </div>
                            <div className="w-full bg-neutral-800 rounded-full h-2 overflow-hidden">
                                <div className="bg-gradient-to-r from-purple-600 to-purple-400 h-2 rounded-full transition-all duration-300" style={{ width: `${uploadProgress}%` }}></div>
                            </div>
                        </div>
                    )}

                    <div className="p-4 bg-neutral-900/90 border-t border-neutral-800 flex justify-end">
                        <button onClick={() => setShowSettings(true)} disabled={uploading} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 text-white px-8 py-3 rounded-xl font-bold shadow-lg shadow-purple-900/20 transition-all btn-press flex items-center gap-2 text-lg">
                            {uploading ? <Loader2 className="w-5 h-5 animate-spin" /> : <ArrowRight className="w-5 h-5" />}
                            {uploading ? 'In progress...' : 'Share'}
                        </button>
                    </div>
                </div>
            )}

            <AnimatePresence>
                {showSettings && (
                    <ModalPortal>
                        <motion.div
                            key="settings-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 z-[9999] flex items-center justify-center p-4"
                            onClick={() => setShowSettings(false)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 w-full max-w-2xl rounded-2xl border border-neutral-700 shadow-2xl p-4 md:p-8 space-y-2 md:space-y-2 max-h-[90vh] overflow-y-auto"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h3 className="text-2xl font-bold text-white flex gap-2 items-center"><Settings className="text-purple-500" /> Share Settings</h3>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div>
                                        <label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Name</label>
                                        <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" value={options.name} onChange={e => setOpts({ ...options, name: e.target.value })} placeholder="Optional" />
                                    </div>

                                    {/* ID GENERATOR UI */}
                                    <div>
                                        <label className="text-xs font-bold text-neutral-500 uppercase mb-1 flex justify-between">
                                            <span>Unique Link ID</span>
                                            <span className="text-purple-400">{idLength} characters</span>
                                        </label>
                                        <div className="flex gap-2 mb-2">
                                            <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none font-mono text-center tracking-wider" value={options.customSlug} onChange={e => setOpts({ ...options, customSlug: e.target.value })} />
                                            <button onClick={() => generateId(idLength)} className="bg-neutral-800 hover:bg-neutral-700 p-3 rounded-lg text-white transition" title="Generate new ID">
                                                <Loader2 className="w-5 h-5" />
                                            </button>
                                        </div>
                                        <input
                                            type="range"
                                            min="8"
                                            max="32"
                                            value={idLength}
                                            onChange={(e) => {
                                                const len = parseInt(e.target.value);
                                                setIdLength(len);
                                                generateId(len);
                                            }}
                                            className="w-full accent-purple-600 h-2 bg-neutral-800 rounded-lg appearance-none cursor-pointer"
                                        />
                                    </div>
                                </div>

                                <div><label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Message</label><textarea className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" rows={2} value={options.message} onChange={e => setOpts({ ...options, message: e.target.value })} /></div>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div><label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Password</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" type="password" placeholder="Optional" value={options.password} onChange={e => setOpts({ ...options, password: e.target.value })} /></div>
                                    <div>
                                        <label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Expires after</label>
                                        <div className="flex gap-2">
                                            <input
                                                type="number" min="0"
                                                className="w-20 bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition text-center"
                                                value={options.expirationVal}
                                                onChange={e => {
                                                    const val = e.target.value;
                                                    setOpts({ ...options, expirationVal: val === '' ? 0 : parseInt(val) })
                                                }}
                                            />
                                            <div className="relative flex-1">
                                                <select
                                                    className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white appearance-none focus:border-purple-500 outline-none transition pr-10"
                                                    value={options.expirationUnit}
                                                    onChange={e => setOpts({ ...options, expirationUnit: e.target.value })}
                                                >
                                                    {UNITS.map(u => (
                                                        <option key={u} value={u}>
                                                            {getUnitLabel(options.expirationVal, u)}
                                                        </option>
                                                    ))}
                                                </select>
                                                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                            </div>
                                        </div>
                                        <div className="text-[10px] text-neutral-500 mt-1.5 flex items-center gap-1.5">
                                            <Info className="w-3 h-3" />
                                            {options.expirationVal > 0
                                                ? <span>Expires on: <span className="text-purple-400">{getFutureDate(options.expirationVal, options.expirationUnit, locale)}</span></span>
                                                : <span>Link <span className="text-green-500">always remains valid</span></span>
                                            }
                                        </div>
                                    </div>

                                    <div>
                                        <label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Max Downloads (Optional)</label>
                                        <input
                                            type="number"
                                            min="0"
                                            placeholder="Unlimited"
                                            className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition"
                                            value={options.maxDownloads || ''}
                                            onChange={e => setOpts({ ...options, maxDownloads: e.target.value ? parseInt(e.target.value) : undefined })}
                                        />
                                        <p className="text-[10px] text-neutral-500 mt-1">Leave empty for unlimited</p>
                                    </div>
                                </div>

                                <div>
                                    <label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Recipients</label>
                                    <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" placeholder="dan@example.com..." value={options.recipients} onChange={e => setOpts({ ...options, recipients: e.target.value })} list="contacts" />
                                    <datalist id="contacts">{contacts.map(c => <option key={c.id} value={c.email} />)}</datalist>
                                </div>

                                <div className="flex justify-end gap-3 pt-4 border-t border-neutral-800">
                                    <button onClick={() => setShowSettings(false)} className="text-neutral-400 hover:text-white px-4 py-2 transition">Cancel</button>
                                    <button onClick={handleUpload} disabled={uploading} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 px-8 py-3 rounded-lg text-white font-bold transition btn-press shadow-lg shadow-purple-900/20">{uploading ? 'In progress...' : 'Send'}</button>
                                </div>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>
        </div>
    );
};

const MySharesView = () => {
    const [shares, setShares] = useState<any[]>([]);
    const [editing, setEditing] = useState<any>(null);
    const [newFiles, setNewFiles] = useState<File[]>([]);
    const [editProgress, setEditProgress] = useState(0);
    const [isSaving, setIsSaving] = useState(false);
    const [resending, setResending] = useState<any>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const { notify, confirm, preview, isConfirming, isPreviewing } = useUI();

    // Esc keys
    useEscapeKey(() => setEditing(null), !!editing && !isConfirming && !isPreviewing);
    useEscapeKey(() => setResending(null), !!resending && !isConfirming && !isPreviewing);

    useEffect(() => { load(); }, []);
    const load = async () => {
        try {
            const res = await fetch(`${API_URL}/shares`, { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                // Voorkom crash: update alleen als het een array is
                if (Array.isArray(data)) {
                    setShares(data);
                } else {
                    setShares([]); // Veilige fallback
                }
            }
        } catch (e) {
            console.error("Error loading shares:", e);
        }
    };

    const deleteShare = async (id: string) => {
        confirm("Are you sure you want to delete this share? This cannot be undone.", async () => {
            await fetch(`${API_URL}/shares/${id}`, { method: 'DELETE', credentials: 'include' });
            setShares(shares.filter(s => s.id !== id));
            notify("Share deleted", "success");
        });
    };

    const deleteFile = async (shareId: string, fileId: string | number) => {
        confirm("Do you want to delete this file?", async () => {
            const res = await fetch(`${API_URL}/shares/${shareId}/files/${fileId}`, { method: 'DELETE', credentials: 'include' });
            const data = await res.json(); // Lees antwoord van server

            if (res.ok) {
                if (data.shareDeleted) {
                    // Als de server zegt dat de share weg is:
                    setEditing(null); // Sluit modal
                    notify("Share deleted because it was empty", "info");
                } else {
                    // Normale afhandeling: update lijst in modal
                    if (editing) {
                        const updatedShare = { ...editing };
                        updatedShare.files = updatedShare.files.filter((f: any) => f.id !== fileId);
                        setEditing(updatedShare);
                    }
                    notify("File deleted", "success");
                }
                load(); // Ververs de hoofdlijst
            } else {
                notify("Error while deleting", "error");
            }
        });
    };

    const deleteFolder = async (shareId: string, path: string) => {
        confirm("Are you sure you want to delete this folder and all its contents?", async () => {
            const res = await fetch(`${API_URL}/shares/${shareId}/folder?path=${encodeURIComponent(path)}`, {
                method: 'DELETE',
                credentials: 'include'
            });
            const data = await res.json();

            if (res.ok) {
                if (data.shareDeleted) {
                    setEditing(null);
                    notify("Share deleted because it was empty", "info");
                } else {
                    if (editing) {
                        // We moeten herladen vanuit de server omdat we niet precies weten welke IDs zijn verwijderd (enkel prefix)
                        // Alternatief kan zijn: filter alle files die starten met 'path/'
                        const updatedShare = { ...editing };
                        updatedShare.files = updatedShare.files.filter((f: any) => !f.original_name.startsWith(path + '/'));
                        setEditing(updatedShare);
                    }
                    notify("Folder deleted", "success");
                }
                load();
            } else {
                notify(data.error || "Error while deleting folder", "error");
            }
        });
    };

    const [stagedFiles, setStagedFiles] = useState<any[]>([]); // { tempId, originalName, size, mimeType }
    const [isStaging, setIsStaging] = useState(false);

    // Als we een edit openen, reset staged
    useEffect(() => {
        if (editing) {
            setStagedFiles([]);
        }
    }, [editing?.id]);

    const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
        if (!e.target.files || e.target.files.length === 0) return;
        setIsStaging(true);
        setEditProgress(0);

        const files = Array.from(e.target.files);
        // We gebruiken de bestaande chunked upload logica, maar naar de 'stage' endpoint

        try {
            const configRes = await fetch(`${API_URL}/config`, { credentials: 'include' });
            const config = await configRes.json();
            const k = 1024;
            const map: any = { 'KB': k, 'MB': k * k };
            const CHUNK_SIZE = (config.chunkSizeVal || 50) * (map[config.chunkSizeUnit || 'MB'] || k * k);

            const uploadedFilesMeta = [];
            let totalBytes = files.reduce((acc, f) => acc + f.size, 0);
            let uploadedBytes = 0;

            for (const file of files) {
                const fileId = generateUUID();
                const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

                for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                    const start = chunkIndex * CHUNK_SIZE;
                    const end = Math.min(start + CHUNK_SIZE, file.size);
                    const chunk = file.slice(start, end);

                    const chunkFd = new FormData();
                    chunkFd.append('chunk', chunk);
                    chunkFd.append('chunkIndex', chunkIndex.toString());
                    chunkFd.append('totalChunks', totalChunks.toString());
                    chunkFd.append('fileName', file.name);
                    chunkFd.append('fileId', fileId);

                    await axios.post(`${API_URL}/shares/${editing.id}/chunk`, chunkFd);

                    uploadedBytes += chunk.size;
                    setEditProgress(Math.round((uploadedBytes * 100) / totalBytes));
                }

                uploadedFilesMeta.push({
                    fileName: file.name,
                    fileId: fileId,
                    size: file.size,
                    mimeType: file.type
                });
            }

            // Call STAGE endpoint
            const res = await axios.post(`${API_URL}/shares/${editing.id}/stage`, {
                files: uploadedFilesMeta
            });

            if (res.data.success) {
                setStagedFiles(prev => [...prev, ...res.data.stagedFiles]);
                notify("Files scanned & ready to save", "success");
            }

        } catch (e: any) {
            console.error(e);
            notify(e.response?.data?.error || e.message || 'Scan failed', "error");
        } finally {
            setIsStaging(false);
            setEditProgress(0);
            if (fileInputRef.current) fileInputRef.current.value = '';
        }
    };

    const saveEdit = async () => {
        setIsSaving(true);
        try {
            const fd = new FormData();
            fd.append('name', editing.name);

            if (editing.removePassword) {
                fd.append('password', '');
                fd.append('remove_password', 'true');
            } else if (editing.password) {
                fd.append('password', editing.password);
            }

            if (editing.newSlug) fd.append('customSlug', editing.newSlug);

            if (editing.newExpirationVal !== undefined && editing.newExpirationVal !== null && !isNaN(editing.newExpirationVal)) {
                fd.append('expirationVal', editing.newExpirationVal.toString());
                fd.append('expirationUnit', editing.newExpirationUnit || 'Days');
            }

            // Add Staged Files
            if (stagedFiles.length > 0) {
                fd.append('staged_files', JSON.stringify(stagedFiles));
            }

            // Update metadata
            const res = await fetch(`${API_URL}/shares/${editing.id}`, {
                method: 'PUT',
                credentials: 'include',
                body: fd
            });

            const json = await res.json();
            if (!res.ok) throw new Error(json.error || 'Metadata update failed');

            setEditing(null);
            setStagedFiles([]);
            load();
            notify("Changes saved", "success");

        } catch (e: any) {
            console.error(e);
            notify(e.message || 'Update failed', "error");
        } finally {
            setIsSaving(false);
        }
    };

    const submitResend = async () => {
        await fetch(`${API_URL}/shares/${resending.id}/resend`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recipients: resending.recipients, message: resending.message }) });
        setResending(null);
        notify("Email resent!", "success");
    };

    return (
        <div className="space-y-6 anim-slide">
            <h2 className="text-2xl font-bold text-white mb-6">My Shares</h2>

            {shares.length === 0 && (
                <div className="bg-neutral-900/50 rounded-2xl border-2 border-dashed border-neutral-800 p-10 flex flex-col items-center justify-center text-neutral-500">
                    <FileQuestion className="w-12 h-12 mb-4 opacity-50" />
                    <p className="text-lg font-medium">You haven't shared any files yet.</p>
                    <p className="text-sm">Upload your first file to get started!</p>
                </div>
            )}

            <div className="grid gap-4">
                {shares.map(s => (
                    <div key={s.id} className="bg-neutral-900 rounded-xl border border-neutral-800 p-4 md:p-6 flex flex-col md:flex-row justify-between items-start gap-4 hover:border-neutral-600 transition duration-300">
                        <div className="flex-1 min-w-0">
                            <h3 className="text-lg md:text-xl font-bold text-white flex items-center gap-2 flex-wrap">{s.name} {s.protected && <LockIcon className="w-4 h-4 text-yellow-500" />}</h3>
                            <div className="text-neutral-400 text-xs md:text-sm mt-1 flex gap-2 md:gap-3 flex-wrap">
                                <span>{s.files?.length || 0} files</span>
                                <span>•</span>
                                <span>{formatBytes(s.total_size)}</span>
                                <span className="hidden sm:inline">•</span>
                                <span>Expires on: {s.expires_at ? new Date(s.expires_at).toLocaleDateString() : 'Never'}</span>
                                <span className="hidden sm:inline">•</span>
                                <span className={`flex items-center gap-1 ${s.max_downloads && s.download_count >= s.max_downloads ? 'text-red-500 font-bold' : ''}`}>
                                    <Download className="w-3 h-3" />
                                    {s.download_count || 0}
                                    {s.max_downloads ? ` / ${s.max_downloads}` : ''}
                                </span>
                            </div>
                            <div className="mt-3"><CopyButton text={s.url} className="text-purple-400 hover:text-purple-300 text-sm bg-purple-500/10 px-2 py-1 rounded w-fit break-all text-left whitespace-normal" /></div>
                        </div>
                        <div className="flex gap-2 flex-shrink-0 self-start">
                            <button
                                onClick={() => setEditing(s)}
                                className="p-2 hover:bg-neutral-800 rounded text-neutral-400 hover:text-white transition"
                                title="Edit"
                            >
                                <Edit className="w-5 h-5" />
                            </button>
                            <button
                                onClick={() => setResending(s)}
                                className="p-2 hover:bg-neutral-800 rounded text-neutral-400 hover:text-white transition"
                                title="Resend email"
                            >
                                <Mail className="w-5 h-5" />
                            </button>
                            <button
                                onClick={() => deleteShare(s.id)}
                                className="p-2 hover:bg-red-500/10 rounded text-red-500 transition"
                                title="Delete"
                            >
                                <Trash2 className="w-5 h-5" />
                            </button>
                        </div>
                    </div>
                ))}
            </div>

            <AnimatePresence>
                {editing && (
                    <ModalPortal>
                        <motion.div
                            key="edit-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(8px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            transition={{ duration: 0.2 }}
                            className="fixed inset-0 bg-black/80 z-[9999] flex items-center justify-center p-4 text-left"
                            onClick={() => !isSaving && setEditing(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0, y: 20 }}
                                animate={{ scale: 1, opacity: 1, y: 0 }}
                                exit={{ scale: 0.95, opacity: 0, y: 20 }}
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                                className="bg-neutral-900 w-full max-w-2xl rounded-2xl border border-neutral-700 shadow-2xl p-4 md:p-8 space-y-4 md:space-y-6 max-h-[90vh] overflow-y-auto"
                            >
                                <h3 className="text-2xl font-bold text-white flex gap-2 items-center"><Edit className="text-purple-500" /> Edit Share</h3>

                                {/* Naam & Link */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div><label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Name</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" value={editing.name} onChange={e => setEditing({ ...editing, name: e.target.value })} /></div>
                                    <div><label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Link / ID</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" defaultValue={editing.id} onChange={e => setEditing({ ...editing, newSlug: e.target.value })} /></div>
                                </div>

                                {/* Password & Expiration */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div>
                                        <label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Password</label>
                                        <div className="relative">
                                            <input
                                                className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition pr-10"
                                                type="password"
                                                autoComplete="current-password"
                                                placeholder={editing.protected ? "Password set (type to change)" : "Leave blank for no change"}
                                                onChange={e => setEditing({ ...editing, password: e.target.value, removePassword: false })}
                                            />
                                            {editing.protected && !editing.removePassword && (
                                                <button
                                                    type="button"
                                                    onClick={() => setEditing({ ...editing, protected: false, removePassword: true, password: '' })}
                                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-neutral-400 hover:text-red-500 transition-colors p-1 rounded-md hover:bg-neutral-800"
                                                    title="Delete password"
                                                >
                                                    <X className="w-5 h-5" />
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                    <div>
                                        <label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">New Expiry Time</label>
                                        <div className="flex gap-2">
                                            <input
                                                type="number" min="0" placeholder="-"
                                                className="w-20 bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition text-center"
                                                value={editing.newExpirationVal ?? ''}
                                                onChange={e => {
                                                    const val = e.target.value;
                                                    setEditing({
                                                        ...editing,
                                                        // Als leeg, maak 0. Anders parseInt.
                                                        newExpirationVal: val === '' ? 0 : parseInt(val),
                                                        newExpirationUnit: editing.newExpirationUnit || 'Days'
                                                    });
                                                }}
                                            />
                                            <div className="relative flex-1">
                                                <select
                                                    className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white appearance-none focus:border-purple-500 outline-none transition pr-10"
                                                    value={editing.newExpirationUnit || 'Days'}
                                                    onChange={e => setEditing({ ...editing, newExpirationUnit: e.target.value })}
                                                >
                                                    {UNITS.map(u => (
                                                        <option key={u} value={u}>
                                                            {getUnitLabel(editing.newExpirationVal || 1, u)}
                                                        </option>
                                                    ))}
                                                </select>
                                                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                            </div>
                                        </div>
                                        {editing.newExpirationVal !== undefined && !isNaN(editing.newExpirationVal) && (
                                            <p className="text-[10px] text-neutral-500 mt-1">
                                                New date: <span className="text-purple-400">{getFutureDate(editing.newExpirationVal, editing.newExpirationUnit || 'Days')}</span>
                                            </p>
                                        )}
                                    </div>
                                </div>

                                {/* Bestanden */}
                                <div>
                                    <label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Files</label>

                                    {/* Hierarchical File Tree */}
                                    {(() => {
                                        const dbItems: UploadItem[] = (editing.files || []).map((f: any) => ({
                                            file: null,
                                            path: f.original_name,
                                            name: f.original_name.split('/').pop() || f.original_name,
                                            id: f.id,
                                            isDirectory: false,
                                            size: f.size
                                        }));
                                        const stagedItems: UploadItem[] = stagedFiles.map(f => ({
                                            file: null, // It's on server now
                                            path: f.originalName,
                                            name: f.originalName,
                                            id: f.tempId, // Use tempId for identification
                                            isDirectory: false,
                                            size: f.size,
                                            isStaged: true // Vlaggetje om te weten dat hij staged is
                                        }));

                                        // Sort and synthesize tree
                                        const combined = sortFiles(synthesizeDirectoryItems([...dbItems, ...stagedItems]));

                                        return (
                                            <div className="bg-neutral-800/50 rounded-lg border border-neutral-700 overflow-hidden max-h-[300px] overflow-y-auto" style={{ "--indent-step": "24px" } as React.CSSProperties}>
                                                <style>{`@media (max-width: 768px) { [style*="--indent-step"] { --indent-step: 12px !important; } }`}</style>
                                                {combined.length === 0 ? (
                                                    <p className="text-center text-neutral-500 py-8">No files in this share.</p>
                                                ) : (
                                                    combined.map((item: any) => {
                                                        const segments = item.path.split('/');
                                                        const depth = Math.max(0, segments.length - 1);

                                                        return (
                                                            <div key={item.id} className={`flex justify-between items-center px-3 py-2 border-b border-neutral-700 last:border-0 hover:bg-neutral-700/50 transition gap-2 ${item.isDirectory ? 'bg-neutral-700/30' : ''}`}>
                                                                <div
                                                                    className="flex items-center gap-2 md:gap-4 overflow-hidden flex-1 cursor-pointer"
                                                                    style={{ paddingLeft: `calc(${depth} * var(--indent-step, 12px))` }}
                                                                    onClick={() => {
                                                                        if (item.isDirectory) return;
                                                                        if (item.isStaged) {
                                                                            preview(`${API_URL}/shares/preview-stage/${item.id}`, item.name);
                                                                        } else {
                                                                            preview(`${API_URL}/shares/${editing.id}/files/${item.id}`, item.name);
                                                                        }
                                                                    }}
                                                                >
                                                                    <div className="bg-black p-2 rounded-lg text-purple-400 font-bold text-xs uppercase text-center shrink-0 flex items-center justify-center min-w-[2.5rem]">
                                                                        {item.isDirectory ? <FolderIcon className="w-4 h-4" /> : item.name.split('.').pop()}
                                                                        {depth > 0 && <div className="absolute -left-3 top-1/2 -translate-y-1/2 w-2 h-[1px] bg-neutral-600"></div>}
                                                                    </div>
                                                                    <div className="min-w-0">
                                                                        <p className={`font-medium truncate ${item.isDirectory ? 'text-purple-300' : 'text-neutral-200'}`}>
                                                                            {item.name} {item.isStaged && <span className="text-[10px] bg-green-900/50 text-green-400 px-1.5 py-0.5 rounded ml-2 border border-green-800">New</span>}
                                                                        </p>
                                                                        {!item.isDirectory && <p className="text-xs text-neutral-500">{formatBytes(item.size)}</p>}
                                                                    </div>
                                                                </div>

                                                                <div className="flex items-center gap-1">
                                                                    {!item.isStaged && ( // Staged folder deletion niet supported
                                                                        <button
                                                                            onClick={(e) => {
                                                                                e.stopPropagation();
                                                                                if (item.isDirectory) {
                                                                                    deleteFolder(editing.id, item.path);
                                                                                } else if (item.isStaged) {
                                                                                    setStagedFiles(prev => prev.filter(p => p.tempId !== item.id));
                                                                                } else {
                                                                                    deleteFile(editing.id, item.id);
                                                                                }
                                                                            }}
                                                                            className="p-2 text-neutral-500 hover:text-red-400 hover:bg-red-500/10 rounded transition"
                                                                        >
                                                                            <X className="w-4 h-4" />
                                                                        </button>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        );
                                                    })
                                                )}
                                            </div>
                                        );
                                    })()}

                                    {isStaging && (
                                        <div className="mt-2">
                                            <div className="flex justify-between text-xs text-neutral-400 mb-1">
                                                <span>Scanning & Staging files...</span>
                                                <span>{editProgress}%</span>
                                            </div>
                                            <div className="w-full bg-neutral-800 rounded-full h-1.5">
                                                <div className="bg-green-500 h-1.5 rounded-full transition-all duration-300" style={{ width: `${editProgress}%` }}></div>
                                            </div>
                                        </div>
                                    )}

                                    <div className="mt-4 flex gap-2">
                                        <button onClick={() => fileInputRef.current?.click()} className="bg-neutral-800 hover:bg-neutral-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition border border-neutral-700 flex items-center gap-2">
                                            <Plus className="w-4 h-4" /> Add Files
                                        </button>

                                        <input
                                            ref={fileInputRef}
                                            type="file"
                                            multiple
                                            className="hidden"
                                            onChange={handleFileSelect}
                                        />
                                    </div>
                                </div>

                                {/* Progress Bar (Alleen zichtbaar tijdens Save) */}
                                {isSaving && (
                                    <div className="mt-4">
                                        <div className="flex justify-between text-xs text-neutral-400 mb-1">
                                            <span>{newFiles.length > 0 ? 'Uploading files...' : 'Save...'}</span>
                                            <span>{editProgress}%</span>
                                        </div>
                                        <div className="w-full bg-neutral-800 rounded-full h-2 overflow-hidden">
                                            <div
                                                className="bg-gradient-to-r from-purple-600 to-purple-400 h-2 rounded-full transition-all duration-300"
                                                style={{ width: `${newFiles.length > 0 ? editProgress : 100}%` }}
                                            ></div>
                                        </div>
                                    </div>
                                )}

                                {/* Actieknoppen */}
                                <div className="flex justify-end gap-3 pt-4 border-t border-neutral-700 mt-4">
                                    <button onClick={() => { setEditing(null); setNewFiles([]) }} disabled={isSaving} className="text-neutral-400 hover:text-white px-4 py-2 transition">Cancel</button>
                                    <button onClick={saveEdit} disabled={isSaving} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 px-6 py-2 rounded-lg text-white font-bold transition btn-press flex items-center gap-2">
                                        {isSaving && <Loader2 className="w-4 h-4 animate-spin" />}
                                        Save
                                    </button>
                                </div>

                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>

            <AnimatePresence>
                {resending && (
                    <ModalPortal>
                        <motion.div
                            key="resend-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 z-[9999] flex items-center justify-center p-4"
                            onClick={() => setResending(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                                className="bg-neutral-900 w-full max-w-lg rounded-2xl border border-neutral-700 p-4 md:p-8 shadow-2xl"
                            >
                                <h3 className="text-xl font-bold text-white mb-6 flex gap-2 items-center"><Mail className="text-purple-500" /> Resend mail</h3>
                                <div className="space-y-4">
                                    <div><label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Recipients</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none" value={resending.recipients || ''} onChange={e => setResending({ ...resending, recipients: e.target.value })} /></div>
                                    <div><label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Message</label><textarea className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none" rows={4} value={resending.message || ''} onChange={e => setResending({ ...resending, message: e.target.value })} /></div>
                                </div>
                                <div className="flex justify-end gap-3 mt-6 border-t border-neutral-700 pt-4">
                                    <button onClick={() => setResending(null)} className="text-neutral-400 hover:text-white px-4 py-2 transition">Cancel</button>
                                    <button onClick={submitResend} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 px-6 py-2 rounded-lg text-white font-bold transition btn-press flex items-center gap-2"><Send className="w-4 h-4" /> Send</button>
                                </div>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>
        </div>
    );
};

const ReverseView = () => {
    const [shares, setShares] = useState<any[]>([]);
    const [createMode, setCreateMode] = useState(false);
    const [viewFiles, setViewFiles] = useState<any>(null);
    const [uploadedFiles, setUploadedFiles] = useState<any[]>([]);
    // Update state met expirationVal en expirationUnit (Default: 1 Week)
    const [newShare, setNewShare] = useState({
        name: '',
        maxSizeVal: 1, // Standaard 1
        maxSizeUnit: 'GB', // Standaard GB
        expirationVal: 1,
        expirationUnit: 'Weeks',
        password: '',
        notify: true,
        sendEmailTo: '',
        thankYouMessage: '',
        customSlug: ''
    });
    const [idLength, setIdLength] = useState(12);
    const [copiedId, setCopiedId] = useState<string | null>(null);
    const { notify, confirm, preview, isConfirming, isPreviewing } = useUI();

    // Esc keys
    useEscapeKey(() => setCreateMode(false), createMode && !isConfirming && !isPreviewing);
    useEscapeKey(() => setViewFiles(null), !!viewFiles && !isConfirming && !isPreviewing);

    useEffect(() => {
        load();
        // Initial ID generation
        fetch(`${API_URL}/config`, { credentials: 'include' }).then(r => r.json()).then(cfg => {
            if (cfg.shareIdLength) {
                setIdLength(parseInt(cfg.shareIdLength));
                generateId(parseInt(cfg.shareIdLength));
            } else {
                generateId(12);
            }
        });
    }, []);

    const generateId = async (len: number) => {
        try {
            const res = await fetch(`${API_URL}/utils/generate-id?length=${len}`, { credentials: 'include' });
            const data = await res.json();
            if (data.id) setNewShare(prev => ({ ...prev, customSlug: data.id }));
        } catch (e) { console.error(e); }
    };

    const load = async () => {
        try {
            const res = await fetch(`${API_URL}/reverse`, { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                if (Array.isArray(data)) setShares(data);
            }
        } catch (e) { console.error(e); }
    };
    const create = async () => {
        // Bereken bytes op basis van gekozen unit
        const multiplier = newShare.maxSizeUnit === 'GB' ? 1024 * 1024 * 1024 : 1024 * 1024;
        const sizeInBytes = (newShare.maxSizeVal || 0) * multiplier;

        const res = await fetch(`${API_URL}/reverse`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...newShare,
                maxSize: sizeInBytes // Verstuur als bytes
            })
        });

        if (res.ok) {
            setCreateMode(false);
            // Reset formulier
            setNewShare({
                name: '', maxSizeVal: 1, maxSizeUnit: 'GB', expirationVal: 1,
                expirationUnit: 'Weeks', password: '', notify: true,
                sendEmailTo: '', thankYouMessage: '', customSlug: ''
            });
            load();
            notify("Reverse share created", "success");
        } else {
            const data = await res.json();
            notify(data.error || "Creation failed", "error");
        }
    };
    const deleteReverse = async (id: string) => { confirm("Delete?", async () => { await fetch(`${API_URL}/reverse/${id}`, { method: 'DELETE', credentials: 'include' }); load(); notify("Deleted", "success"); }); };
    const openFiles = async (id: string) => {
        const res = await fetch(`${API_URL}/reverse/${id}/files`, { credentials: 'include' });
        const json = await res.json();
        setUploadedFiles(json);


        // We reuse the viewFiles state logic, but we might need a separate state for the tree items if 'viewFiles' is just the ID string.
        // The original code used 'viewFiles' as the ID string. We'll stick to that and calculate the tree on render or use a useEffect/memo if needed.
        // For simplicity/perf, let's add a local var or state. Since this is inside MySharesView functional component, we can add a state for it at the top level or reuse 'uploadedFiles' if we typed it loosely. 
        // Better: let's add a state 'viewFilesTree' at the top level of MySharesView.
        setViewFiles(id);
    };

    const handleCopy = (id: string, url: string) => {
        navigator.clipboard.writeText(url);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    if (viewFiles) {
        // Compute tree on the fly (or memoize if slow)
        const mapped: UploadItem[] = (uploadedFiles || []).map((f: any) => ({
            file: null,
            path: f.original_name,
            name: f.original_name.split('/').pop() || f.original_name,
            id: f.id,
            isDirectory: false,
            size: f.size
        }));
        const treeItems = sortFiles(synthesizeDirectoryItems(mapped));

        return (
            <div className="bg-neutral-900 rounded-xl border border-neutral-800 p-6 anim-scale">
                <div className="flex justify-between items-center mb-6"><h3 className="text-xl font-bold text-white flex gap-2"><Download className="text-purple-500" /> Received Files</h3><button onClick={() => setViewFiles(null)} className="text-neutral-400 hover:text-white transition">Back</button></div>
                {uploadedFiles.length === 0 ? <p className="text-neutral-500">Nothing uploaded yet.</p> : (
                    <div className="max-h-[500px] overflow-y-auto bg-black/30 rounded-lg border border-neutral-800" style={{ "--indent-step": "24px" } as React.CSSProperties}>
                        <style>{`@media (max-width: 768px) { [style*="--indent-step"] { --indent-step: 12px !important; } }`}</style>
                        {treeItems.map(item => {
                            const segments = item.path.split('/');
                            const depth = Math.max(0, segments.length - 1);

                            return (
                                <div key={item.id} className={`flex justify-between items-center px-3 py-2 last:border-0 hover:bg-neutral-800/50 transition gap-2 ${item.isDirectory ? 'bg-neutral-800/30' : ''}`}>
                                    <div className="flex items-center gap-2 md:gap-4 overflow-hidden flex-1 min-w-0" style={{ paddingLeft: `calc(${depth} * var(--indent-step, 12px))` }}>
                                        <div className="bg-black p-2 rounded-lg flex-shrink-0 relative">
                                            {item.isDirectory ? <FolderIcon className="w-4 h-4 text-purple-400" /> : <div className="uppercase text-xs font-bold text-purple-400 min-w-[2.5rem] w-auto text-center">{item.name.split('.').pop()}</div>}
                                            {depth > 0 && <div className="absolute -left-3 top-1/2 -translate-y-1/2 w-2 h-[1px] bg-neutral-600"></div>}
                                        </div>
                                        <div className="min-w-0 flex-1">
                                            <p className={`text-neutral-200 font-medium truncate text-sm md:text-base ${item.isDirectory ? 'text-purple-300' : ''}`}>{item.name}</p>
                                            {!item.isDirectory && <p className="text-neutral-500 text-xs">{formatBytes(item.size)}</p>}
                                        </div>
                                    </div>
                                    {!item.isDirectory && (
                                        <>
                                            <button onClick={() => preview(`${API_URL}/reverse/files/${item.id}/download`, item.name)} className="text-neutral-500 hover:text-white transition p-2 rounded hover:bg-neutral-800 flex-shrink-0" title="Preview"><Eye className="w-4 h-4" /></button>
                                            <a href={`${API_URL}/reverse/files/${encodeURIComponent(item.id)}/download`} className="text-purple-400 hover:text-white transition p-2 rounded hover:bg-neutral-800 flex-shrink-0"><Download className="w-4 h-4" /></a>
                                        </>
                                    )}
                                </div>
                            );
                        })}
                        <div className="p-4 border-t border-neutral-800 sticky bottom-0 bg-neutral-900/95 backdrop-blur">
                            <a href={`${API_URL}/reverse/${viewFiles}/download`} className="block w-full text-center bg-green-600 hover:bg-green-700 text-white px-4 py-3 rounded-lg font-bold transition btn-press shadow-lg shadow-green-900/20">Download everything (.zip)</a>
                        </div>
                    </div>
                )}
            </div>
        );
    }

    return (
        <div className="space-y-6 anim-slide">
            <div className="flex justify-between items-center"><h2 className="text-2xl font-bold text-white">Reverse Shares</h2><button onClick={() => setCreateMode(true)} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 text-white px-4 py-2 rounded-lg font-bold flex items-center gap-2 transition btn-press"><Plus className="w-4 h-4" /> New link</button></div>
            <AnimatePresence>
                {createMode && (
                    <motion.div
                        key="create-panel"
                        initial={{ opacity: 0, height: 0, marginBottom: 0 }}
                        animate={{ opacity: 1, height: 'auto', marginBottom: 24 }}
                        exit={{ opacity: 0, height: 0, marginBottom: 0 }}
                        className="overflow-hidden"
                    >
                        <div className="bg-neutral-900 p-4 md:p-6 rounded-xl border border-neutral-800 space-y-4">
                            <h3 className="font-bold text-white">Create new link</h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                                {/* Naam Veld */}
                                <div className="relative group">
                                    <Type className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-neutral-500 group-focus-within:text-purple-400 transition" />
                                    <input
                                        className="w-full bg-black border border-neutral-700 rounded-lg py-2.5 pl-10 pr-4 text-white focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all placeholder:text-neutral-600"
                                        placeholder="Name of the share (e.g. Project X)"
                                        value={newShare.name}
                                        onChange={e => setNewShare({ ...newShare, name: e.target.value })}
                                    />
                                </div>

                                {/* Password Veld */}
                                <div className="relative group">
                                    <LockIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-neutral-500 group-focus-within:text-purple-400 transition" />
                                    <input
                                        type="password"
                                        className="w-full bg-black border border-neutral-700 rounded-lg py-2.5 pl-10 pr-4 text-white focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all placeholder:text-neutral-600"
                                        placeholder="Password (Optional)"
                                        value={newShare.password}
                                        onChange={e => setNewShare({ ...newShare, password: e.target.value })}
                                    />
                                </div>

                                {/* Max Grootte met Eenheid Selectie */}
                                <div>
                                    <div className="flex gap-2 relative group">
                                        <div className="relative flex-1">
                                            <HardDrive className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-neutral-500 group-focus-within:text-purple-400 transition" />
                                            <input
                                                type="number"
                                                min="1"
                                                className="w-full bg-black border border-neutral-700 rounded-lg py-2.5 pl-10 pr-4 text-white focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all placeholder:text-neutral-600"
                                                placeholder="Max Upload"
                                                value={newShare.maxSizeVal}
                                                onChange={e => {
                                                    const val = e.target.value;
                                                    setNewShare({ ...newShare, maxSizeVal: val === '' ? 0 : parseInt(val) })
                                                }}
                                            />
                                        </div>
                                        {/* Aangepaste breedte: w-20 ipv w-28 */}
                                        <div className="relative w-20">
                                            <select
                                                className="w-full bg-black border border-neutral-700 rounded-lg py-2.5 px-2 text-white appearance-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all cursor-pointer font-medium pl-3"
                                                value={newShare.maxSizeUnit}
                                                onChange={e => setNewShare({ ...newShare, maxSizeUnit: e.target.value })}
                                            >
                                                <option value="MB">MB</option>
                                                <option value="GB">GB</option>
                                            </select>
                                            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-neutral-500 pointer-events-none" />
                                        </div>
                                    </div>
                                </div>

                                {/* Expiratie Controls met Datum Preview */}
                                <div>
                                    <div className="flex gap-2 relative group">
                                        <div className="relative flex-1">
                                            <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-neutral-500 group-focus-within:text-purple-400 transition" />
                                            <input
                                                type="number"
                                                min="0"
                                                className="w-full bg-black border border-neutral-700 rounded-lg py-2.5 pl-10 pr-4 text-white focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all placeholder:text-neutral-600"
                                                placeholder="0 = Never"
                                                value={newShare.expirationVal}
                                                onChange={e => {
                                                    const val = e.target.value;
                                                    setNewShare({ ...newShare, expirationVal: val === '' ? 0 : parseInt(val) })
                                                }}
                                            />
                                        </div>
                                        <div className="relative w-32">
                                            <select
                                                className="w-full bg-black border border-neutral-700 rounded-lg py-2.5 px-3 text-white appearance-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all cursor-pointer"
                                                value={newShare.expirationUnit}
                                                onChange={e => setNewShare({ ...newShare, expirationUnit: e.target.value })}
                                            >
                                                {UNITS.map(u => (
                                                    <option key={u} value={u}>{getUnitLabel(newShare.expirationVal || 0, u)}</option>
                                                ))}
                                            </select>
                                            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                        </div>
                                    </div>
                                    {/* Datum Preview Tekst */}
                                    <p className="text-xs text-neutral-500 mt-1.5 ml-1 flex items-center gap-1.5">
                                        <Info className="w-3 h-3" />
                                        {!newShare.expirationVal || newShare.expirationVal === 0
                                            ? "Never expires (Optional)"
                                            : <span>Expires on: <span className="text-purple-400">{getFutureDate(newShare.expirationVal, newShare.expirationUnit)}</span></span>
                                        }
                                    </p>
                                </div>

                                {/* Email Veld & ID Generator Split */}
                                <div className="md:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {/* Linkerkant: Email */}
                                    <div className="relative group">
                                        <label className="text-xs font-bold text-neutral-500 uppercase mb-1 block ml-1">Recipient (Email)</label>
                                        <div className="relative">
                                            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-neutral-500 group-focus-within:text-purple-400 transition" />
                                            <input
                                                className="w-full bg-black border border-neutral-700 rounded-lg py-2.5 pl-10 pr-4 text-white focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all placeholder:text-neutral-600"
                                                placeholder="dan@example.com (Optional)"
                                                value={newShare.sendEmailTo}
                                                onChange={e => setNewShare({ ...newShare, sendEmailTo: e.target.value })}
                                            />
                                        </div>
                                    </div>

                                    {/* Rechterkant: Custom ID */}
                                    <div>
                                        <label className="text-xs font-bold text-neutral-500 uppercase mb-1 flex justify-between ml-1">
                                            <span>Link ID</span>
                                            <span className="text-purple-400">{idLength} characters</span>
                                        </label>
                                        <div className="flex gap-2 mb-2">
                                            <input
                                                className="w-full bg-black border border-neutral-700 rounded-lg py-2 px-3 text-white focus:border-purple-500 outline-none font-mono text-center tracking-wider"
                                                value={newShare.customSlug}
                                                onChange={e => setNewShare({ ...newShare, customSlug: e.target.value })}
                                            />
                                            <button onClick={() => generateId(idLength)} className="bg-neutral-800 hover:bg-neutral-700 p-2 rounded-lg text-white transition flex-shrink-0" title="Generate new ID">
                                                <Loader2 className="w-5 h-5" />
                                            </button>
                                        </div>
                                        <input
                                            type="range"
                                            min="8"
                                            max="32"
                                            value={idLength}
                                            onChange={(e) => {
                                                const len = parseInt(e.target.value);
                                                setIdLength(len);
                                                generateId(len);
                                            }}
                                            className="w-full accent-purple-600 h-2 bg-neutral-800 rounded-lg appearance-none cursor-pointer"
                                        />
                                    </div>
                                </div>

                                {/* Bedankt Bericht */}
                                <div className="md:col-span-2 relative group">
                                    <MessageSquare className="absolute left-3 top-3 w-5 h-5 text-neutral-500 group-focus-within:text-purple-400 transition" />
                                    <input
                                        className="w-full bg-black border border-neutral-700 rounded-lg py-2.5 pl-10 pr-4 text-white focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all placeholder:text-neutral-600"
                                        placeholder="Custom Thank You Message (e.g. Thanks for the files!)"
                                        value={newShare.thankYouMessage}
                                        onChange={e => setNewShare({ ...newShare, thankYouMessage: e.target.value })}
                                    />
                                    <p className="text-xs text-neutral-500 mt-1.5 ml-1">This message is what the uploader sees after successful submission.</p>
                                </div>

                                <div className="md:col-span-2 mt-2">
                                    <Checkbox
                                        checked={newShare.notify}
                                        onChange={(e) => setNewShare({ ...newShare, notify: e.target.checked })}
                                        label="Send me an email notification for every upload"
                                    />
                                </div>
                            </div>
                            <div className="flex justify-end gap-2"><button onClick={() => setCreateMode(false)} className="text-neutral-400 px-4 hover:text-white transition">Cancel</button><button onClick={create} className="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded font-bold transition btn-press shadow-lg shadow-green-900/20">Create</button></div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {shares.length === 0 && !createMode && (
                <div className="bg-neutral-900/50 rounded-2xl border-2 border-dashed border-neutral-800 p-10 flex flex-col items-center justify-center text-neutral-500">
                    <FileQuestion className="w-12 h-12 mb-4 opacity-50" /><p className="text-lg font-medium">You don't have any reverse shares yet.</p><p className="text-sm">Create a link to receive files.</p>
                </div>
            )}

            <div className="grid gap-4">
                {shares.map(s => (
                    <div key={s.id} className="bg-neutral-900 p-4 md:p-6 rounded-xl border border-neutral-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 hover:border-neutral-600 transition duration-300">
                        <div>
                            <h4 className="font-bold text-white flex items-center gap-2">{s.name} {s.protected && <LockIcon className="w-3 h-3 text-yellow-500" />}</h4>
                            <div className="flex gap-4 text-sm text-neutral-400 mt-1 flex-wrap">
                                <CopyButton text={s.url} className="bg-purple-500/10 text-purple-400 px-2 rounded font-mono break-all text-left whitespace-normal" />
                                <span>{s.file_count || 0} receive files</span>

                                {/* Datum weergave */}
                                <span className="hidden sm:inline">•</span>
                                <span>Expires on: {s.expires_at ? new Date(s.expires_at).toLocaleDateString() : 'Never'}</span>
                            </div>
                        </div>
                        <div className="flex gap-2">
                            <button
                                onClick={() => handleCopy(s.id, s.url)}
                                className={`p-2 rounded transition-all duration-300 ${copiedId === s.id
                                    ? 'bg-green-600 text-white scale-110'
                                    : 'bg-neutral-700 hover:bg-neutral-600 text-white'
                                    }`}
                                title="Copy link"
                            >
                                {copiedId === s.id ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                            </button>
                            <button onClick={() => openFiles(s.id)} className="p-2 bg-purple-600 hover:bg-purple-700 rounded text-white transition" title="View files"><Eye className="w-4 h-4" /></button>
                            <button onClick={() => deleteReverse(s.id)} className="p-2 bg-red-500/10 text-red-500 hover:bg-red-500/20 rounded transition"><Trash2 className="w-4 h-4" /></button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

const ConfigTabs = ({ user, onRestartSetup }: { user: any, onRestartSetup: () => void }) => {
    const [config, setConfig] = useState<any>({});
    const [activeTab, setActiveTab] = useState('general');
    const [users, setUsers] = useState<any[]>([]);
    const [contacts, setContacts] = useState<any[]>([]);
    const [newUser, setNewUser] = useState({ email: '', name: '', password: '', is_admin: false });
    const [editUser, setEditUser] = useState<any>(null);
    const { notify, confirm, isConfirming, isPreviewing } = useUI();

    useEscapeKey(() => setEditUser(null), !!editUser && !isConfirming && !isPreviewing);

    // Validatie State voor Users Tab
    const [pwdValid, setPwdValid] = useState({ length: false, upper: false, lower: false, number: false });
    const [isPwdFocused, setIsPwdFocused] = useState(false);

    // We checken zowel newUser (aanmaken) als editUser (bewerken)
    useEffect(() => {
        // Welk Password zijn we aan het typen?
        const p = editUser ? (editUser.password || '') : newUser.password;

        setPwdValid({
            length: p.length >= 8,
            upper: /[A-Z]/.test(p),
            lower: /[a-z]/.test(p),
            number: /[0-9]/.test(p)
        });
    }, [newUser.password, editUser]);

    useEffect(() => {
        fetch(`${API_URL}/config`, { credentials: 'include' })
            .then(r => r.json())
            .then(data => {
                data.smtpPass = '';
                data.oidcSecret = '';

                setConfig(data);
            });
        fetchUsers();
        fetchContacts();
    }, []);

    const fetchUsers = async () => {
        try {
            const res = await fetch(`${API_URL}/users`, { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                if (Array.isArray(data)) setUsers(data);
            }
        } catch (e) { console.error(e); }
    };

    const fetchContacts = async () => {
        try {
            const res = await fetch(`${API_URL}/contacts`, { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                if (Array.isArray(data)) setContacts(data);
            }
        } catch (e) { console.error(e); }
    };
    const save = async () => { const res = await fetch(`${API_URL}/config`, { method: 'PUT', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config) }); if (res.ok) notify('Settings saved', 'success'); else notify('Saving failed', 'error'); };
    const testEmail = async () => {
        const targetEmail = user.email;
        if (!targetEmail) return;

        notify(`Test connection to ${targetEmail}...`, 'info'); // Feedback dat hij bezig is

        try {
            const res = await fetch(`${API_URL}/config/test-email`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ...config,
                    testEmail: targetEmail
                })
            });

            if (res.ok) {
                // HIER IS DE AANPASSING:
                notify(`Test email successfully sent to ${targetEmail}`, 'success');
            } else {
                const data = await res.json();
                notify(`Error sending to ${targetEmail}: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (e: any) {
            notify(`Network error while testing to ${targetEmail}`, 'error');
        }
    };
    const createUser = async () => { const res = await fetch(`${API_URL}/users`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newUser) }); if (res.ok) { setNewUser({ email: '', name: '', password: '', is_admin: false }); fetchUsers(); notify('User added', 'success'); } };
    const deleteUser = async (id: number) => { confirm('Delete user?', async () => { await fetch(`${API_URL}/users/${id}`, { method: 'DELETE', credentials: 'include' }); fetchUsers(); notify('Deleted', 'success'); }); };
    const deleteContact = async (id: number) => { confirm('Delete contact?', async () => { await fetch(`${API_URL}/contacts/${id}`, { method: 'DELETE', credentials: 'include' }); fetchContacts(); notify('Deleted', 'success'); }); };
    const reset2FA = async (id: number) => {
        confirm('Reset 2FA for this user?', async () => {
            const res = await fetch(`${API_URL}/users/${id}/2fa/reset`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' }
            });
            if (res.ok) {
                notify('2FA reset', 'success');
            } else {
                notify('2FA reset failed', 'error');
            }
        });
    };

    const updateUser = async () => {
        const res = await fetch(`${API_URL}/users/${editUser.id}`, { method: 'PUT', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(editUser) });
        if (res.ok) { setEditUser(null); fetchUsers(); notify('User updated', 'success'); }
        else notify('Update failed', 'error');
    };

    // Gebruikt nu de juiste URL en veldnamen voor de backend
    const handleBrandingUpload = async (file: File, field: 'logoUrl' | 'faviconUrl') => {
        // Client-side validatie (dubbele check)
        if (file.size > 5 * 1024 * 1024) {
            notify('File is too large (max 5MB)', 'error');
            return;
        }

        const fd = new FormData();
        // De backend verwacht de key 'logo' of 'favicon', niet 'file'
        const backendField = field === 'logoUrl' ? 'logo' : 'favicon';
        fd.append(backendField, file);

        try {
            notify('Uploading...', 'info');
            // Juiste API route gebruiken (/config/branding i.p.v. /config/upload-branding)
            const res = await fetch(`${API_URL}/config/branding`, {
                method: 'POST',
                credentials: 'include',
                body: fd
            });

            if (res.ok) {
                const data = await res.json();

                // Update de config direct met de nieuwe URL
                setConfig((prev: any) => ({
                    ...prev,
                    [field]: field === 'logoUrl' ? data.logoUrl : data.faviconUrl
                }));

                notify('Image uploaded! Click "Save" to confirm.', 'success');
            } else {
                const err = await res.json();
                notify(err.error || 'Upload failed', 'error');
            }
        } catch (error) {
            console.error(error);
            notify('Upload error', 'error');
        }
    };

    const tabClass = (id: string) => `flex-1 text-center px-4 md:px-6 py-4 font-bold border-b-2 transition duration-300 whitespace-nowrap text-sm md:text-base ${activeTab === id ? 'border-purple-500 text-white bg-neutral-900' : 'border-transparent text-neutral-400 hover:text-white hover:bg-neutral-900'}`;

    return (
        <div className="bg-neutral-900 rounded-xl border border-neutral-800 overflow-hidden max-w-4xl mx-auto shadow-xl anim-slide">
            <div className="flex border-b border-neutral-800 bg-black/50 overflow-x-auto scrollbar-hide">
                <button onClick={() => setActiveTab('general')} className={tabClass('general')}>General</button>
                <button onClick={() => setActiveTab('system')} className={tabClass('system')}>System</button>
                <button onClick={() => setActiveTab('security')} className={tabClass('security')}>Security</button>
                <button onClick={() => setActiveTab('smtp')} className={tabClass('smtp')}>SMTP</button>
                <button onClick={() => setActiveTab('sso')} className={tabClass('sso')}>SSO</button>
                <button onClick={() => setActiveTab('users')} className={tabClass('users')}>Users</button>
            </div>
            <div className="p-4 md:p-8">
                {activeTab === 'general' && (
                    <div className="space-y-6 anim-fade">
                        <div className="flex justify-between items-center mb-6">
                            <h3 className="text-white font-bold text-xl flex gap-2"><Globe className="w-6 h-6 text-purple-500" /> Branding & Domain</h3>
                            <button onClick={onRestartSetup} className="text-neutral-400 hover:text-white text-xs md:text-sm flex items-center gap-2 border border-neutral-700 px-3 py-1.5 rounded-lg hover:bg-neutral-800 transition">
                                <Sparkles className="w-4 h-4 text-purple-400" /> Restart setup
                            </button>
                        </div>
                        <div><label className="block text-neutral-400 text-sm font-bold mb-2">Application Name</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" value={config.appName || ''} onChange={e => setConfig({ ...config, appName: e.target.value })} /></div>
                        <div>
                            <label className="block text-neutral-400 text-sm font-bold mb-2">Logo</label>
                            <div className="flex gap-2">
                                <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" placeholder="https://..." value={config.logoUrl || ''} onChange={e => setConfig({ ...config, logoUrl: e.target.value })} />
                                <label className="bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-white p-3 rounded-lg cursor-pointer transition flex items-center justify-center min-w-[3rem]" title="Upload Logo">
                                    <Upload className="w-5 h-5" />
                                    <input type="file" accept="image/*" className="hidden" onChange={(e) => {
                                        if (e.target.files && e.target.files[0]) {
                                            handleBrandingUpload(e.target.files[0], 'logoUrl');
                                        }
                                    }} />
                                </label>
                            </div>
                            {/* De src checkt nu of het begint met http, zo niet plakt hij er niets voor (relatief) */}
                            {config.logoUrl && <img src={config.logoUrl} alt="Logo Preview" className="mt-2 h-10 object-contain bg-neutral-800/50 p-1 rounded" />}
                        </div>

                        <div>
                            <label className="block text-neutral-400 text-sm font-bold mb-2">Favicon</label>
                            <div className="flex gap-2">
                                <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" placeholder="https://..." value={config.faviconUrl || ''} onChange={e => setConfig({ ...config, faviconUrl: e.target.value })} />
                                <label className="bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-white p-3 rounded-lg cursor-pointer transition flex items-center justify-center min-w-[3rem]" title="Upload Favicon">
                                    <Upload className="w-5 h-5" />
                                    <input type="file" accept="image/x-icon,image/png,image/svg+xml" className="hidden" onChange={(e) => {
                                        if (e.target.files && e.target.files[0]) {
                                            handleBrandingUpload(e.target.files[0], 'faviconUrl');
                                        }
                                    }} />
                                </label>
                            </div>
                            {config.faviconUrl && <img src={config.faviconUrl} alt="Favicon Preview" className="mt-2 w-8 h-8 object-contain bg-neutral-800/50 p-1 rounded" />}
                        </div>
                        <div><label className="block text-neutral-400 text-sm font-bold mb-2">App URL</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" placeholder="https://share.domain.nl" value={config.appUrl || ''} onChange={e => setConfig({ ...config, appUrl: e.target.value })} /></div>

                        <h3 className="text-white font-bold text-xl mt-8 mb-6 flex gap-2"><Shield className="w-6 h-6 text-purple-500" /> Security & Session</h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label className="block text-neutral-400 text-sm font-bold mb-2">Session duration</label>
                                <input
                                    type="number"
                                    className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white"
                                    value={config.sessionVal ?? ''}
                                    onChange={e => setConfig({ ...config, sessionVal: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                    onBlur={() => { if (config.sessionVal === '') setConfig({ ...config, sessionVal: 7 }) }}
                                    placeholder="7"
                                />
                            </div>
                            <div>
                                <label className="block text-neutral-400 text-sm font-bold mb-2">Unit</label>
                                <div className="relative">
                                    <select
                                        className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white appearance-none outline-none focus:border-purple-500 transition pr-10"
                                        value={config.sessionUnit || 'Days'}
                                        onChange={e => setConfig({ ...config, sessionUnit: e.target.value })}
                                    >
                                        <option>Minutes</option>
                                        <option>Hours</option>
                                        <option>Days</option>
                                        <option>Weeks</option>
                                    </select>
                                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                </div>
                            </div>
                        </div>
                        <Checkbox
                            checked={config.secureCookies || false}
                            onChange={(e) => setConfig({ ...config, secureCookies: e.target.checked })}
                            label="Secure Cookies (Require HTTPS)"
                        />

                        <h3 className="text-white font-bold text-xl mt-8 mb-6 flex gap-2 border-t border-neutral-800 pt-6"><Shield className="w-6 h-6 text-purple-500" /> 2FA & Authentication</h3>
                        <div className="space-y-3">
                            <Checkbox
                                checked={config.require2FA || false}
                                onChange={(e) => setConfig({ ...config, require2FA: e.target.checked })}
                                label="Make 2FA Mandatory for all users"
                            />
                            <Checkbox
                                checked={config.allowPasskeys !== false}
                                onChange={e => setConfig({ ...config, allowPasskeys: e.target.checked })}
                                label="Allow Passkeys"
                            />
                            <Checkbox
                                checked={config.allowPasswordReset !== false}
                                onChange={e => setConfig({ ...config, allowPasswordReset: e.target.checked })}
                                label="Allow Password Reset (requires SMTP)"
                            />
                        </div>

                        <button onClick={save} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 text-white px-6 py-2 rounded-lg font-bold mt-4 transition btn-press">Save</button>
                    </div>
                )}

                {activeTab === 'system' && (
                    <div className="space-y-6 anim-fade">
                        <h3 className="text-white font-bold text-xl mb-6 flex gap-2"><HardDrive className="w-6 h-6 text-purple-500" /> Storage & Uploads</h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label className="block text-neutral-400 text-sm font-bold mb-2">Max Size</label>
                                <input
                                    type="number"
                                    className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white"
                                    value={config.maxSizeVal ?? ''}
                                    onChange={e => setConfig({ ...config, maxSizeVal: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                    onBlur={() => { if (config.maxSizeVal === '') setConfig({ ...config, maxSizeVal: 10 }) }}
                                    placeholder="10"
                                />
                            </div>
                            <div>
                                <label className="block text-neutral-400 text-sm font-bold mb-2">Unit</label>
                                <div className="relative">
                                    <select
                                        className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white appearance-none outline-none focus:border-purple-500 transition pr-10"
                                        value={config.maxSizeUnit || 'GB'}
                                        onChange={e => setConfig({ ...config, maxSizeUnit: e.target.value })}
                                    >
                                        <option>MB</option>
                                        <option>GB</option>
                                        <option>TB</option>
                                    </select>
                                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                </div>
                            </div>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label className="block text-neutral-400 text-sm font-bold mb-2">Chunk Size (Upload)</label>
                                <input
                                    type="number"
                                    className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white"
                                    value={config.chunkSizeVal ?? ''}
                                    onChange={e => setConfig({ ...config, chunkSizeVal: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                    onBlur={() => { if (config.chunkSizeVal === '') setConfig({ ...config, chunkSizeVal: 50 }) }}
                                    placeholder="50"
                                />
                            </div>
                            <div>
                                <label className="block text-neutral-400 text-sm font-bold mb-2">Unit</label>
                                <div className="relative">
                                    <select
                                        className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white appearance-none outline-none focus:border-purple-500 transition pr-10"
                                        value={config.chunkSizeUnit || 'MB'}
                                        onChange={e => setConfig({ ...config, chunkSizeUnit: e.target.value })}
                                    >
                                        <option>KB</option>
                                        <option>MB</option>
                                    </select>
                                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                </div>
                            </div>
                        </div>
                        <div>
                            <label className="block text-neutral-400 text-sm font-bold mb-2">Default Share ID Length</label>
                            <input
                                type="number"
                                min="8"
                                className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white"
                                value={config.shareIdLength ?? ''}
                                onChange={e => setConfig({ ...config, shareIdLength: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                onBlur={() => { if (config.shareIdLength === '' || (config.shareIdLength as number) < 8) setConfig({ ...config, shareIdLength: 12 }) }} // Default 12 (en minimaal 8)
                                placeholder="12"
                            />
                            <p className="text-neutral-500 text-xs mt-1">Minimum 8 for safety.</p>
                        </div>
                        <h4 className="text-white font-bold text-lg mt-6 mb-4 flex gap-2 border-t border-neutral-800 pt-6">Expiration Times Policy</h4>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                            {/* Standaard Vervaltijd */}
                            <div>
                                <label className="block text-neutral-400 text-sm font-bold mb-2">Standard Expiry Time</label>
                                <div className="flex gap-3">
                                    <input
                                        type="number" min="0"
                                        className="w-24 bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                        value={config.defaultExpirationVal ?? ''}
                                        onChange={e => setConfig({ ...config, defaultExpirationVal: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                        onBlur={() => { if (config.defaultExpirationVal === '') setConfig({ ...config, defaultExpirationVal: 1 }) }}
                                        placeholder="1"
                                    />
                                    <div className="relative flex-1">
                                        <select
                                            className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white appearance-none outline-none focus:border-purple-500 transition pr-10"
                                            value={config.defaultExpirationUnit || 'Weeks'}
                                            onChange={e => setConfig({ ...config, defaultExpirationUnit: e.target.value })}
                                        >
                                            {UNITS.map(u => (
                                                <option key={u} value={u}>{getUnitLabel(config.defaultExpirationVal || 1, u)}</option>
                                            ))}
                                        </select>
                                        <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                    </div>
                                </div>
                            </div>

                            {/* Maximale Vervaltijd */}
                            <div>
                                <label className="block text-neutral-400 text-sm font-bold mb-2">Maximum Expiration Time</label>
                                <div className="flex gap-3">
                                    <input
                                        type="number" min="0"
                                        className="w-24 bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                        value={config.maxExpirationVal ?? ''}
                                        onChange={e => setConfig({ ...config, maxExpirationVal: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                        onBlur={() => { if (config.maxExpirationVal === '') setConfig({ ...config, maxExpirationVal: 0 }) }}
                                        placeholder="0"
                                    />
                                    <div className="relative flex-1">
                                        <select
                                            className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white appearance-none outline-none focus:border-purple-500 transition pr-10"
                                            value={config.maxExpirationUnit || 'Months'}
                                            onChange={e => setConfig({ ...config, maxExpirationUnit: e.target.value })}
                                        >
                                            {UNITS.map(u => (
                                                <option key={u} value={u}>{getUnitLabel(config.maxExpirationVal || 0, u)}</option>
                                            ))}
                                        </select>
                                        <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                    </div>
                                </div>
                            </div>
                        </div>

                        <h3 className="text-white font-bold text-xl mt-8 mb-6 flex gap-2"><FileArchive className="w-6 h-6 text-purple-500" /> Compression (Zip)</h3>
                        <div><label className="block text-neutral-400 text-sm font-bold mb-2">Compression Level (0-9)</label><input type="range" min="0" max="9" className="w-full accent-purple-600" value={config.zipLevel || 5} onChange={e => setConfig({ ...config, zipLevel: parseInt(e.target.value) })} /><div className="text-white text-center font-bold mt-2">{config.zipLevel || 5}</div></div>
                        <div className="pt-2">
                            <Checkbox
                                checked={config.zipNoMedia || false}
                                onChange={e => setConfig({ ...config, zipNoMedia: e.target.checked })}
                                label="No compression for media"
                            />
                        </div>
                        <button onClick={save} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 text-white px-6 py-2 rounded-lg font-bold mt-4 transition btn-press">Save</button>
                    </div>
                )}

                {activeTab === 'security' && (
                    <div className="space-y-6 anim-fade">
                        <h3 className="text-white font-bold text-xl mb-6 flex gap-2"><Shield className="w-6 h-6 text-purple-500" /> Security Policies</h3>

                        <div className="space-y-4 bg-red-500/5 p-4 rounded-xl border border-red-500/20 mb-8">
                            <div className="flex items-start gap-3">
                                <Checkbox
                                    checked={config.clamavMustScan || false}
                                    onChange={e => setConfig({ ...config, clamavMustScan: e.target.checked })}
                                    className="mt-1"
                                />
                                <div>
                                    <span className="text-white font-bold block cursor-pointer" onClick={() => setConfig({ ...config, clamavMustScan: !config.clamavMustScan })}>Enforce Virus Scan</span>
                                    <p className="text-neutral-400 text-sm mt-1">
                                        If checked, uploads will be <strong>rejected</strong> if the ClamAV scanner is unreachable.
                                        <br />
                                        <span className="text-xs text-neutral-500">Default (off): Uploads will continue, but will not be scanned if ClamAV is offline.</span>
                                    </p>
                                </div>
                            </div>
                        </div>

                        <div className="border-t border-neutral-800 pt-6">
                            <h3 className="text-white font-bold text-xl mb-6 flex gap-2"><FileIcon className="w-6 h-6 text-purple-500" /> File Type Restrictions</h3>
                            <p className="text-neutral-400 text-sm mb-6">Specify which file extensions should be blocked. <br />Files with these extensions will be rejected immediately upon upload.</p>

                            <ExtensionSelector
                                label="Authenticated User Uploads"
                                blocked={config.blockedExtensionsUser || []}
                                onChange={(list) => setConfig({ ...config, blockedExtensionsUser: list })}
                            />

                            <ExtensionSelector
                                label="Guest / Reverse Share Uploads"
                                blocked={config.blockedExtensionsGuest || []}
                                onChange={(list) => setConfig({ ...config, blockedExtensionsGuest: list })}
                            />
                        </div>

                        <button onClick={save} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 text-white px-6 py-2 rounded-lg font-bold mt-4 transition btn-press">Save</button>
                    </div>
                )}

                {activeTab === 'smtp' && (
                    <div className="space-y-6 anim-fade">
                        <h3 className="text-white font-bold text-xl mb-6 flex gap-2"><Mail className="w-6 h-6 text-purple-500" /> Email Configuration</h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="md:col-span-2"><label className="block text-neutral-400 text-sm font-bold mb-2">Host</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" value={config.smtpHost || ''} onChange={e => setConfig({ ...config, smtpHost: e.target.value })} placeholder="smtp.office365.com" /></div>

                            <div><label className="block text-neutral-400 text-sm font-bold mb-2">Port</label><input type="number" className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" value={config.smtpPort || ''} onChange={e => setConfig({ ...config, smtpPort: parseInt(e.target.value) })} placeholder="465" /></div>

                            {/* Afzender Adres */}
                            <div><label className="block text-neutral-400 text-sm font-bold mb-2">Sender (From)</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" value={config.smtpFrom || ''} onChange={e => setConfig({ ...config, smtpFrom: e.target.value })} placeholder="noreply@domain.nl" /></div>

                            <div><label className="block text-neutral-400 text-sm font-bold mb-2">Username</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" value={config.smtpUser || ''} onChange={e => setConfig({ ...config, smtpUser: e.target.value })} placeholder="email@domain.nl" /></div>

                            <div>
                                <label className="block text-neutral-400 text-sm font-bold mb-2">Password</label>
                                <input
                                    className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition"
                                    type="password"
                                    placeholder="Leave blank for no change"
                                    value={config.smtpPass || ''}
                                    onChange={e => setConfig({ ...config, smtpPass: e.target.value })}
                                />
                            </div>
                        </div>

                        <div className="flex flex-col gap-4 pt-2 border-t border-neutral-800 mt-4">
                            <Checkbox
                                checked={config.smtpSecure || false}
                                onChange={e => setConfig({ ...config, smtpSecure: e.target.checked })}
                                label="Use SSL (Often port 465)"
                            />
                            <Checkbox
                                checked={config.smtpStartTls !== false}
                                onChange={e => setConfig({ ...config, smtpStartTls: e.target.checked })}
                                label="Use STARTTLS (Often port 587)"
                            />
                            <div className="flex items-start gap-3">
                                <Checkbox
                                    checked={config.smtpAllowLocal || false}
                                    onChange={e => setConfig({ ...config, smtpAllowLocal: e.target.checked })}
                                    className="mt-1"
                                />
                                <div>
                                    <span className="text-white font-medium block cursor-pointer" onClick={() => setConfig({ ...config, smtpAllowLocal: !config.smtpAllowLocal })}>Allow Local/Private IP addresses</span>
                                    <span className="text-neutral-500 text-xs">Only enable this if your SMTP server is on the same network (e.g. 192.168.x.x or localhost).</span>
                                </div>
                            </div>
                        </div>

                        <div className="flex gap-3 mt-6 items-center">
                            <button onClick={save} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 text-white px-6 py-2 rounded-lg font-bold transition btn-press shadow-lg shadow-purple-900/20">Save</button>
                            <button onClick={testEmail} className="bg-neutral-800 hover:bg-neutral-700 text-white px-6 py-2 rounded-lg font-bold border border-neutral-700 transition btn-press flex items-center gap-2"><Send className="w-4 h-4" /> Test Connection</button>
                        </div>

                        {/* Contactenlijst blijft hieronder ongewijzigd... */}
                        <div className="border-t border-neutral-700 pt-6 mt-6">
                            <h4 className="text-white font-bold mb-4 flex items-center gap-2"><Contact className="w-5 h-5" /> Saved Contacts</h4>
                            <div className="bg-black rounded-lg p-4 max-h-60 overflow-y-auto space-y-2 border border-neutral-700">
                                {contacts.map(c => (
                                    <div key={c.id} className="flex justify-between items-center bg-neutral-900 p-3 rounded-lg border border-neutral-700 hover:border-neutral-500 transition">
                                        <span className="text-neutral-300">{c.email}</span>
                                        <button onClick={() => deleteContact(c.id)} className="text-red-400 hover:text-red-300 transition"><X className="w-4 h-4" /></button>
                                    </div>
                                ))}
                                {contacts.length === 0 && <span className="text-neutral-500 text-sm">No contacts saved yet.</span>}
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'sso' && (
                    <div className="space-y-6 anim-fade">
                        <h3 className="text-white font-bold text-xl mb-6 flex gap-2"><Shield className="w-6 h-6 text-purple-500" /> SSO (OIDC)</h3>
                        <div className="bg-neutral-800/50 border border-neutral-700 p-4 rounded-lg text-neutral-300 text-sm mb-6">Callback URL: <code className="bg-black/50 px-2 py-1 rounded border border-neutral-700 text-purple-400 break-all inline-block">{window.location.origin}/api/auth/callback</code></div>

                        <div><label className="block text-neutral-400 text-sm font-bold mb-2">Issuer URL</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" value={config.oidcIssuer || ''} onChange={e => setConfig({ ...config, oidcIssuer: e.target.value })} /></div>
                        <div><label className="block text-neutral-400 text-sm font-bold mb-2">Client ID</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" value={config.oidcClientId || ''} onChange={e => setConfig({ ...config, oidcClientId: e.target.value })} /></div>
                        <div>
                            <label className="block text-neutral-400 text-sm font-bold mb-2">Client Secret</label>
                            <input
                                className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none"
                                type="password"
                                placeholder="Leave blank for no change"
                                value={config.oidcSecret || ''}
                                onChange={e => setConfig({ ...config, oidcSecret: e.target.value })}
                            />
                        </div>

                        <div><label className="block text-neutral-400 text-sm font-bold mb-2">SSO Logout URL (Optional)</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white focus:border-purple-500 outline-none transition" placeholder="E.g. https://auth.provider.com/logout?returnTo=..." value={config.ssoLogoutUrl || ''} onChange={e => setConfig({ ...config, ssoLogoutUrl: e.target.value })} /></div>

                        <div className="space-y-3 pt-2">
                            <Checkbox
                                checked={config.ssoEnabled || false}
                                onChange={e => setConfig({ ...config, ssoEnabled: e.target.checked })}
                                label="Enable SSO"
                            />
                            <Checkbox
                                checked={config.ssoAutoRedirect || false}
                                onChange={e => setConfig({ ...config, ssoAutoRedirect: e.target.checked })}
                                label="Auto-Redirect to SSO (Skip login)"
                            />
                        </div>

                        <button onClick={save} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 text-white px-6 py-2 rounded-lg font-bold mt-4 transition btn-press">Save settings</button>
                    </div>
                )}

                {activeTab === 'users' && (
                    <div className="anim-fade">
                        <h3 className="text-white font-bold text-xl mb-6 flex gap-2"><User className="w-6 h-6 text-purple-500" /> User management</h3>
                        <div className="bg-black/50 p-6 rounded-xl mb-6 border border-neutral-700">
                            <h4 className="text-white text-sm font-bold mb-4 uppercase text-neutral-500">Add new user</h4>
                            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                                <input placeholder="Name" className="bg-neutral-900 text-white p-3 rounded-lg border border-neutral-700 focus:border-purple-500 outline-none transition" value={newUser.name} onChange={e => setNewUser({ ...newUser, name: e.target.value })} />
                                <input placeholder="Email" className="bg-neutral-900 text-white p-3 rounded-lg border border-neutral-700 focus:border-purple-500 outline-none transition" value={newUser.email} onChange={e => setNewUser({ ...newUser, email: e.target.value })} />

                                {/* Password Veld met Focus events */}
                                <input
                                    placeholder="Password"
                                    type="password"
                                    className="bg-neutral-900 text-white p-3 rounded-lg border border-neutral-700 focus:border-purple-500 outline-none transition"
                                    value={newUser.password}
                                    onChange={e => setNewUser({ ...newUser, password: e.target.value })}
                                    onFocus={() => setIsPwdFocused(true)} // Laat zien
                                    onBlur={() => setIsPwdFocused(false)} // Verberg
                                />

                                <div className="flex gap-2">
                                    <div className="bg-neutral-900 px-3 rounded-lg border border-neutral-700 flex-1 flex items-center justify-center">
                                        <Checkbox
                                            checked={newUser.is_admin}
                                            onChange={e => setNewUser({ ...newUser, is_admin: e.target.checked })}
                                            label={<span className="text-sm">Admin</span>}
                                        />
                                    </div>
                                    <button onClick={createUser} className="bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg transition btn-press"><Plus className="w-5 h-5" /></button>
                                </div>
                            </div>

                            {/* Validatie Box (Zichtbaar zodra er tekst is, of als er focus is) */}
                            <div className={`overflow-hidden transition-all duration-300 ${(isPwdFocused || newUser.password.length > 0) ? 'max-h-20 opacity-100 mt-3' : 'max-h-0 opacity-0'}`}>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs bg-neutral-900/50 p-3 rounded-lg border border-neutral-800">
                                    <div className={`flex items-center gap-1.5 ${pwdValid.length ? 'text-green-500' : 'text-neutral-500'}`}>
                                        {pwdValid.length ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} 8+ characters
                                    </div>
                                    <div className={`flex items-center gap-1.5 ${pwdValid.upper ? 'text-green-500' : 'text-neutral-500'}`}>
                                        {pwdValid.upper ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Upper case
                                    </div>
                                    <div className={`flex items-center gap-1.5 ${pwdValid.lower ? 'text-green-500' : 'text-neutral-500'}`}>
                                        {pwdValid.lower ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Lower case
                                    </div>
                                    <div className={`flex items-center gap-1.5 ${pwdValid.number ? 'text-green-500' : 'text-neutral-500'}`}>
                                        {pwdValid.number ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Number
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="space-y-3 mb-6">
                            {users.map(u => (
                                <div key={u.id} className="flex justify-between items-center bg-neutral-900 p-4 rounded-xl border border-neutral-700 hover:border-neutral-600 transition">
                                    <div className="flex items-center gap-4">
                                        <div className="w-10 h-10 bg-gradient-to-br from-purple-600 to-neutral-700 rounded-full flex items-center justify-center font-bold text-white">{u.name.charAt(0)}</div>
                                        <div>
                                            <div className="font-bold text-white flex items-center gap-2">{u.name} {u.is_admin && <span className="text-[10px] bg-purple-600 text-white px-2 py-0.5 rounded-full uppercase tracking-wider">Admin</span>}</div>
                                            <div className="text-sm text-neutral-500">{u.email}</div>
                                        </div>
                                    </div>
                                    <div className="flex gap-2">
                                        <button onClick={() => setEditUser(u)} className="text-neutral-400 hover:bg-neutral-800 p-2 rounded-lg transition" title="Edit"><Edit className="w-5 h-5" /></button>
                                        <button onClick={() => reset2FA(u.id)} className="text-neutral-400 hover:bg-purple-500/10 hover:text-purple-500 p-2 rounded-lg transition btn-press" title="Reset 2FA"><Shield className="w-5 h-5" /></button>
                                        <button onClick={() => deleteUser(u.id)} className="text-neutral-500 hover:bg-red-500/10 hover:text-red-500 p-2 rounded-lg transition btn-press" title="Delete"><Trash2 className="w-5 h-5" /></button>
                                    </div>
                                </div>
                            ))}
                        </div>
                        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 md:p-6 text-sm text-yellow-200/80">
                            <h4 className="text-yellow-500 font-bold mb-2 flex items-center gap-2">
                                <Info className="w-4 h-4" /> Password Requirements
                            </h4>
                            <ul className="list-disc list-inside space-y-1 ml-1">
                                <li>At least <strong>8 characters</strong> long</li>
                                <li>At least 1 <strong>upper case</strong> (A-Z)</li>
                                <li>At least 1 <strong>lower case</strong> (a-z)</li>
                                <li>At least 1 <strong>number</strong> (0-9)</li>
                            </ul>
                            <p className="mt-3 text-xs opacity-70">
                                Weak passwords will be rejected.
                            </p>
                        </div>
                    </div>
                )}
            </div>

            <AnimatePresence>
                {editUser && (
                    <ModalPortal>
                        <motion.div
                            key="edit-user-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 z-[9999] flex items-center justify-center p-4"
                            onClick={() => setEditUser(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 w-full max-w-lg rounded-2xl border border-neutral-700 p-4 md:p-8 shadow-2xl"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h3 className="text-xl font-bold text-white mb-6">Edit User</h3>
                                <div className="space-y-4">
                                    <div><label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Name</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white" value={editUser.name} onChange={e => setEditUser({ ...editUser, name: e.target.value })} /></div>
                                    <div><label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Email</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white" value={editUser.email} onChange={e => setEditUser({ ...editUser, email: e.target.value })} /></div>
                                    <div><label className="text-xs font-bold text-neutral-500 uppercase mb-1 block">Password (Leave blank for no change)</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white" type="password" placeholder="New Password" onChange={e => setEditUser({ ...editUser, password: e.target.value })}
                                    />
                                        {/* Validatie Box voor Edit User */}
                                        {editUser.password && editUser.password.length > 0 && (
                                            <div className="mt-2 grid grid-cols-2 gap-2 text-xs mb-3 p-3 bg-neutral-900/50 rounded-lg border border-neutral-800">
                                                <div className={`flex items-center gap-1.5 ${pwdValid.length ? 'text-green-500' : 'text-neutral-500'}`}>
                                                    {pwdValid.length ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} 8+ characters
                                                </div>
                                                <div className={`flex items-center gap-1.5 ${pwdValid.upper ? 'text-green-500' : 'text-neutral-500'}`}>
                                                    {pwdValid.upper ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Upper case
                                                </div>
                                                <div className={`flex items-center gap-1.5 ${pwdValid.lower ? 'text-green-500' : 'text-neutral-500'}`}>
                                                    {pwdValid.lower ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Lower case
                                                </div>
                                                <div className={`flex items-center gap-1.5 ${pwdValid.number ? 'text-green-500' : 'text-neutral-500'}`}>
                                                    {pwdValid.number ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Number
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                    <Checkbox
                                        checked={editUser.is_admin}
                                        onChange={e => setEditUser({ ...editUser, is_admin: e.target.checked })}
                                        label="Admin privileges"
                                    />
                                </div>
                                <div className="flex justify-end gap-3 mt-6 border-t border-neutral-700 pt-4">
                                    <button onClick={() => setEditUser(null)} className="text-neutral-400 hover:text-white px-4 py-2 transition">Cancel</button>
                                    <button onClick={updateUser} className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 px-6 py-2 rounded-lg text-white font-bold transition btn-press">Save</button>
                                </div>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>
        </div>
    );
};

// --- FIRST TIME SETUP WIZARD ---
const SetupWizard = ({ onClose }: { onClose: () => void }) => {
    const [step, setStep] = useState(0);
    // secureCookies verwijderd uit state
    const [config, setConfig] = useState<any>({
        appName: 'Nexo Share', appUrl: '',
        smtpHost: '', smtpPort: 465, smtpUser: '', smtpPass: '', smtpFrom: '', smtpSecure: true, smtpStartTls: false
    });
    const [newUser, setNewUser] = useState({ name: '', email: '', password: '' });
    const [loading, setLoading] = useState(false);
    const { notify } = useUI();

    // Validatie State
    const [pwdValid, setPwdValid] = useState({ length: false, upper: false, lower: false, number: false });

    // Update validatie bij typen
    useEffect(() => {
        const p = newUser.password;
        setPwdValid({
            length: p.length >= 8,
            upper: /[A-Z]/.test(p),
            lower: /[a-z]/.test(p),
            number: /[0-9]/.test(p)
        });
    }, [newUser.password]);

    const isPasswordValid = Object.values(pwdValid).every(Boolean);
    const isStepUserValid = newUser.name.trim() !== '' && newUser.email.includes('@') && isPasswordValid;

    // Haal huidige config op bij start
    useEffect(() => {
        axios.get(`${API_URL}/config`).then(r => setConfig((prev: any) => ({ ...prev, ...r.data }))).catch(console.error);
    }, []);

    const saveConfig = async () => {
        try {
            await axios.put(`${API_URL}/config`, config);
        } catch (e) { console.error(e); }
    };

    const createUser = async () => {
        if (!isStepUserValid) return;
        try {
            await axios.post(`${API_URL}/users`, { ...newUser, is_admin: true });
            notify('New admin created', 'success');
        } catch (e: any) {
            notify(e.response?.data?.error || 'User creation failed', 'error');
            throw e;
        }
    };

    const finish = async () => {
        setLoading(true);
        try {
            if (step >= 1) await saveConfig(); // Sla config op
            if (step >= 3 && newUser.email && newUser.password) await createUser(); // Sla user op
            await axios.post(`${API_URL}/config/setup-complete`);
            window.location.reload();
        } catch (e) {
            console.error(e);
            setLoading(false);
        }
    };

    return (
        <ModalPortal>
            <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[9999] flex items-center justify-center p-4 anim-fade">
                <div className="bg-neutral-900 border border-neutral-800 rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] anim-scale">

                    {/* Header */}
                    <div className="p-6 border-b border-neutral-800 flex justify-between items-center bg-black/40">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-full bg-purple-500/20 flex items-center justify-center text-purple-400">
                                {step === 4 ? <Check className="w-6 h-6" /> : <Sparkles className="w-6 h-6" />}
                            </div>
                            <div>
                                <h2 className="text-xl font-bold text-white">Welcome to {config.appName || 'Nexo Share'}</h2>
                                <p className="text-sm text-neutral-400">First installation setup {step > 0 && `(${step}/3)`}</p>
                            </div>
                        </div>
                        {step < 4 && <button onClick={onClose} className="text-neutral-500 hover:text-white px-3 py-1 text-sm transition">Skip</button>}
                    </div>

                    {/* Content */}
                    <div className="p-8 overflow-y-auto flex-1">
                        {step === 0 && (
                            <div className="text-center py-4">
                                <Shield className="w-20 h-20 text-purple-500 mx-auto mb-6 opacity-80" />
                                <h3 className="text-2xl font-bold text-white mb-4">Let's secure your server</h3>
                                <p className="text-neutral-400 max-w-md mx-auto mb-8 leading-relaxed">
                                    We'll help you in 3 steps with basic settings, email configuration, and creating a secure admin account.
                                </p>
                                <button onClick={() => setStep(1)} className="bg-purple-600 hover:bg-purple-700 text-white px-8 py-3 rounded-lg font-bold transition flex items-center gap-2 mx-auto shadow-lg shadow-purple-900/20">
                                    Start Setup <ArrowRight className="w-4 h-4" />
                                </button>
                            </div>
                        )}

                        {step === 1 && (
                            <div className="space-y-6 anim-slide">
                                <h3 className="text-xl font-bold text-white mb-2">1. Basic Settings</h3>
                                <div className="grid gap-4">
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Application Name <span className="text-red-500">*</span></label>
                                        <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                            value={config.appName || ''} onChange={e => setConfig({ ...config, appName: e.target.value })} placeholder="My Company Share" />
                                    </div>
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Public URL</label>
                                        <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                            value={config.appUrl || ''} onChange={e => setConfig({ ...config, appUrl: e.target.value })} placeholder="https://share.mycompany.com" />
                                        <p className="text-xs text-neutral-500 mt-1">Used for links in emails.</p>
                                    </div>
                                </div>
                                <div className="flex justify-end pt-4">
                                    <button onClick={() => setStep(2)} disabled={!config.appName} className="bg-white text-black px-6 py-2 rounded-lg font-bold hover:bg-neutral-200 transition disabled:opacity-50">Next</button>
                                </div>
                            </div>
                        )}

                        {step === 2 && (
                            <div className="space-y-6 anim-slide">
                                <h3 className="text-xl font-bold text-white mb-2">2. E-mail Settings (SMTP)</h3>
                                <p className="text-neutral-400 text-sm mb-4">Required for password resets and notifications. You may skip this step.</p>

                                <div className="grid grid-cols-2 gap-4">
                                    <div className="col-span-2">
                                        <label className="block text-neutral-400 text-sm mb-1">SMTP Host</label>
                                        <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                            value={config.smtpHost || ''} onChange={e => setConfig({ ...config, smtpHost: e.target.value })} placeholder="smtp.office365.com" />
                                    </div>
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Port</label>
                                        <input type="number" className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                            value={config.smtpPort || ''} onChange={e => setConfig({ ...config, smtpPort: parseInt(e.target.value) })} placeholder="465" />
                                    </div>
                                    {/* mt-7 (28px) compenseert precies voor het label 'Poort' + margin van de bHours */}
                                    <div className="flex flex-col gap-1 mt-6">
                                        <Checkbox
                                            checked={config.smtpSecure || false}
                                            onChange={(e) => setConfig({ ...config, smtpSecure: e.target.checked })}
                                            label="Use SSL (Port 465)"
                                        />
                                        <Checkbox
                                            checked={config.smtpStartTls !== false}
                                            onChange={(e) => setConfig({ ...config, smtpStartTls: e.target.checked })}
                                            label="Use STARTTLS (Port 587)"
                                        />
                                    </div>
                                    <div className="col-span-2">
                                        <label className="block text-neutral-400 text-sm mb-1">Username</label>
                                        <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                            value={config.smtpUser || ''} onChange={e => setConfig({ ...config, smtpUser: e.target.value })} placeholder="email@company.com" />
                                    </div>
                                    <div className="col-span-2">
                                        <label className="block text-neutral-400 text-sm mb-1">Password</label>
                                        <input type="password" className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                            value={config.smtpPass || ''} onChange={e => setConfig({ ...config, smtpPass: e.target.value })} placeholder="••••••••" />
                                    </div>
                                    <div className="col-span-2">
                                        <label className="block text-neutral-400 text-sm mb-1">Sender Address (From)</label>
                                        <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                            value={config.smtpFrom || ''} onChange={e => setConfig({ ...config, smtpFrom: e.target.value })} placeholder="noreply@company.com" />
                                    </div>
                                </div>
                                <div className="flex justify-between pt-4">
                                    <button onClick={() => setStep(1)} className="text-neutral-400 hover:text-white text-sm">Back</button>
                                    <button onClick={() => setStep(3)} className="bg-white text-black px-6 py-2 rounded-lg font-bold hover:bg-neutral-200 transition">Next</button>
                                </div>
                            </div>
                        )}

                        {step === 3 && (
                            <div className="space-y-6 anim-slide">
                                <h3 className="text-xl font-bold text-white mb-2">3. Create your own Admin account</h3>
                                <div className="grid gap-4 bg-black/30 p-6 rounded-xl border border-neutral-800">
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Your name</label>
                                        <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                            value={newUser.name} onChange={e => setNewUser({ ...newUser, name: e.target.value })} placeholder="Jan Jansen" />
                                    </div>
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Email Address</label>
                                        <input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                            value={newUser.email} onChange={e => setNewUser({ ...newUser, email: e.target.value })} placeholder="jan@company.com" />
                                    </div>
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Password</label>
                                        <input type="password" className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white outline-none focus:border-purple-500 transition"
                                            value={newUser.password} onChange={e => setNewUser({ ...newUser, password: e.target.value })} placeholder="••••••••" />

                                        {/* Password Validatie */}
                                        <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                                            <div className={`flex items-center gap-1.5 ${pwdValid.length ? 'text-green-500' : 'text-neutral-500'}`}>
                                                {pwdValid.length ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} 8+ characters
                                            </div>
                                            <div className={`flex items-center gap-1.5 ${pwdValid.upper ? 'text-green-500' : 'text-neutral-500'}`}>
                                                {pwdValid.upper ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Upper case
                                            </div>
                                            <div className={`flex items-center gap-1.5 ${pwdValid.lower ? 'text-green-500' : 'text-neutral-500'}`}>
                                                {pwdValid.lower ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Lower case
                                            </div>
                                            <div className={`flex items-center gap-1.5 ${pwdValid.number ? 'text-green-500' : 'text-neutral-500'}`}>
                                                {pwdValid.number ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Number
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div className="flex justify-between items-center pt-4">
                                    <button onClick={() => setStep(2)} className="text-neutral-400 hover:text-white text-sm">Back</button>
                                    <button onClick={() => setStep(4)} disabled={!isStepUserValid} className="bg-white text-black px-6 py-2 rounded-lg font-bold hover:bg-neutral-200 transition disabled:opacity-50 disabled:cursor-not-allowed">Create Account and Continue</button>
                                </div>
                            </div>
                        )}

                        {step === 4 && (
                            <div className="text-center py-4 anim-slide">
                                <div className="w-20 h-20 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                                    <Check className="w-10 h-10 text-green-500" />
                                </div>
                                <h3 className="text-2xl font-bold text-white mb-4">Done!</h3>
                                <p className="text-neutral-400 max-w-md mx-auto mb-8">
                                    All settings have been saved. <br /><br />
                                    The application is now reloading. Then log in with your <strong>new account</strong>.
                                </p>
                                <button onClick={finish} disabled={loading} className="bg-green-600 hover:bg-green-700 text-white px-8 py-3 rounded-lg font-bold transition w-full md:w-auto flex items-center justify-center gap-2 mx-auto shadow-lg shadow-green-900/20">
                                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Finish & Reload"}
                                </button>
                            </div>
                        )}
                    </div>

                    {/* Progress Bar */}
                    <div className="h-1 bg-neutral-800 w-full">
                        <div className="h-full bg-purple-600 transition-all duration-500 ease-out" style={{ width: `${(step / 4) * 100}%` }}></div>
                    </div>
                </div>
            </div>
        </ModalPortal>
    );
};

const Dashboard = ({ token, logout }: any) => {
    const [view, setView] = useState('upload');
    const [config, setConfig] = useState<any>({});
    const [showSetup, setShowSetup] = useState(false);
    const [is2FALocked, setIs2FALocked] = useState(false);
    const [checking2FA, setChecking2FA] = useState(true);
    const { user } = useAuth();
    const { notify } = useUI();
    // Check of setup nodig is bij laden
    useEffect(() => {
        if (user && user.email === 'admin@nexoshare.com') {
            axios.get(`${API_URL}/config`).then(r => {
                // Check of setupCompleted false is in de config response
                if (r.data && !r.data.setupCompleted) setShowSetup(true);
            }).catch(console.error);
        }
    }, [user]);
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

    useEffect(() => {
        fetch(`${API_URL}/config`).then(r => r.json()).then(data => {
            setConfig(data);
            if (data.faviconUrl) {
                let link = document.querySelector("link[rel~='icon']") as HTMLLinkElement;
                if (!link) {
                    link = document.createElement('link');
                    link.rel = 'icon';
                    document.getElementsByTagName('head')[0].appendChild(link);
                }
                link.href = data.faviconUrl;
            }
        });
    }, []);

    const handleLogout = () => {
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
    };

    const tabs = [
        { id: 'upload', label: 'Upload' },
        { id: 'shares', label: 'My Shares' },
        { id: 'reverse', label: 'Reverse Shares' },
        { id: 'profile', label: 'My Profile' }
    ];

    if (user?.is_admin) tabs.push({ id: 'config', label: 'Configuration' });

    // Gebruik useRef om de originele fetch te bewaren, anders crasht de browser na een tijdje
    const originalFetchRef = useRef(window.fetch);

    useEffect(() => {
        const originalFetch = originalFetchRef.current;
        window.fetch = async (...args) => {
            const response = await originalFetch(...args);
            if (response.status === 401) {
                if (!args[0].toString().includes('logout')) {
                    handleLogout();
                }
            }
            return response;
        };
        return () => { window.fetch = originalFetch; };
    }, []);

    return (
        <div className="min-h-screen bg-black text-gray-100 font-sans flex flex-col">
            {showSetup && <SetupWizard onClose={() => setShowSetup(false)} />}
            <GlobalStyles />
            <nav className="bg-neutral-900 border-b border-neutral-800 h-20 flex items-center px-4 md:px-8 sticky top-0 z-50 shadow-lg relative">
                {/* Spacer links */}
                <div className="w-10 sm:w-0"></div>

                {/* Logo Container */}
                <div
                    className={`flex gap-2 md:gap-3 items-center font-bold text-xl md:text-2xl tracking-tight text-white transition z-10 flex-1 justify-center sm:justify-start ${is2FALocked ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer hover:opacity-80'}`}
                    onClick={() => !is2FALocked && setView('upload')}
                >
                    {(config.logoUrl && isValidHttpUrl(config.logoUrl)) ? (
                        <img src={config.logoUrl} className="h-8 md:h-10 rounded" alt="Logo" />
                    ) : (
                        <div className="bg-gradient-to-br from-purple-600 to-blue-600 p-2 rounded-lg shadow-lg shadow-purple-900/20">
                            <Share2 className="text-white w-5 h-5 md:w-6 md:h-6" />
                        </div>
                    )}
                    <span className="hidden sm:inline">{config.appName || 'Nexo Share'}</span>
                </div>

                {/* TABS - Alleen tonen als NIET gelocked */}
                {!is2FALocked && (
                    <div className="hidden lg:flex absolute left-1/2 -translate-x-1/2 bg-black/50 p-1.5 rounded-xl border border-neutral-800/50 backdrop-blur-sm z-20">
                        {tabs.map(tab => (
                            <button key={tab.id} onClick={() => setView(tab.id)} className={`px-6 py-2 rounded-lg text-sm font-bold transition-all duration-300 capitalize ${view === tab.id ? 'bg-neutral-800 text-white shadow-md' : 'text-neutral-400 hover:text-white hover:bg-neutral-900'}`}>{tab.label}</button>
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
                                    onClick={() => setView(tab.id)}
                                    className={`flex flex-col items-center p-2 rounded-lg transition-all ${isActive ? 'text-purple-500' : 'text-neutral-500 hover:text-neutral-300'}`}
                                >
                                    <Icon className={`w-6 h-6 mb-1 ${isActive ? 'fill-purple-500/20' : ''}`} />
                                    <span className="text-[10px] font-bold">{tab.label}</span>
                                </button>
                            );
                        })}
                    </div>
                </div>
            )}

            <main className="max-w-6xl mx-auto p-4 md:p-8 w-full flex-grow pb-20 lg:pb-8">
                {checking2FA ? (
                    <div className="flex justify-center pt-20"><Loader2 className="animate-spin text-purple-500 w-10 h-10" /></div>
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
                                        setView('upload');     // Ga naar het hoofdscherm
                                        notify('Thank you! Your account is now secured.', 'success');
                                    }}
                                />
                            </div>
                        ) : (
                            /* NORMALE WEERGAVE */
                            <>
                                {view === 'upload' && <UploadView />}
                                {view === 'shares' && <MySharesView />}
                                {view === 'config' && user?.is_admin && <ConfigTabs user={user} onRestartSetup={() => setShowSetup(true)} />}
                                {view === 'reverse' && <ReverseView />}
                                {view === 'profile' && <ProfileView user={user} config={config} />}
                            </>
                        )}
                    </>
                )}
            </main>

            <Footer />
        </div>
    );
};

const LoginPage = ({ onLogin }: any) => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [config, setConfig] = useState<any>({});
    const [loadingSSO, setLoadingSSO] = useState(false);

    const [initializing, setInitializing] = useState(true);

    const { notify } = useUI();

    useEffect(() => {
        fetch(`${API_URL}/config`).then(r => r.json()).then(data => {
            setConfig(data);

            if (data.faviconUrl) {
                let link = document.querySelector("link[rel~='icon']") as HTMLLinkElement;
                if (!link) {
                    link = document.createElement('link');
                    link.rel = 'icon';
                    document.getElementsByTagName('head')[0].appendChild(link);
                }
                link.href = data.faviconUrl;
            }

            const params = new URLSearchParams(window.location.search);
            const noRedirect = params.get('noredirect');
            const nonce = params.get('nonce');

            if (data.ssoEnabled && data.ssoAutoRedirect && !noRedirect && !nonce) {
                setLoadingSSO(true);
                window.location.href = `${API_URL}/auth/sso`;
                return;
            } else {
                setInitializing(false);
            }
        }).catch(() => {
            setInitializing(false);
        });

        const params = new URLSearchParams(window.location.search);
        const nonce = params.get('nonce');
        if (nonce) {
            fetch(`${API_URL}/auth/sso-exchange`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ nonce })
            })
                .then(r => r.json())
                .then(data => {
                    if (data.token && data.user) {
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
        }
    }, []);

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
                onLogin(data.user);
                return;
            }
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
            <div className="min-h-screen bg-black flex flex-col items-center justify-center text-white">
                <Loader2 className="w-16 h-16 animate-spin text-purple-500 mb-4" />
                <h2 className="text-xl font-bold">{loadingSSO ? 'Redirect to SSO...' : 'Loading...'}</h2>
                {loadingSSO && (
                    <a href="/login?noredirect=true" className="mt-4 text-neutral-500 text-sm hover:text-white underline">Cancel</a>
                )}
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-black flex items-center justify-center p-4 relative overflow-hidden flex-col">
            <GlobalStyles />
            <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_50%_120%,rgba(120,50,255,0.1),rgba(0,0,0,0))]"></div>
            <form onSubmit={twoFactorRequired ? handleVerify2FA : handleSubmit} className="bg-neutral-900 p-6 md:p-10 rounded-2xl w-full max-w-md border border-neutral-800 shadow-2xl relative z-10 anim-scale mb-8">
                <div className="flex justify-center mb-8">
                    {(config.logoUrl && isValidHttpUrl(config.logoUrl)) ? <img src={config.logoUrl} className="h-16" alt="Logo" /> : <div className="bg-gradient-to-br from-purple-600 to-blue-600 p-4 rounded-2xl shadow-xl shadow-purple-900/30"><Share2 className="w-10 h-10 text-white" /></div>}
                </div>
                <h1 className="text-3xl font-bold text-white mb-8 text-center">Welcome to {config.appName || 'Nexo Share'}</h1>

                {!twoFactorRequired ? (
                    <>
                        <input className="w-full bg-black border border-neutral-700 text-white rounded-lg p-4 mb-4 focus:border-purple-500 outline-none transition" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
                        <input className="w-full bg-black border border-neutral-700 text-white rounded-lg p-4 mb-4 focus:border-purple-500 outline-none transition" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
                        <button className="w-full bg-purple-600 hover:bg-purple-700 text-white p-4 rounded-lg font-bold transition shadow-lg shadow-purple-900/20 text-lg btn-press mb-4">Login</button>

                        {config.allowPasskeys && (
                            <button type="button" onClick={handlePasskeyLogin} className="w-full bg-neutral-800 hover:bg-neutral-700 text-white p-4 rounded-lg font-bold transition shadow-lg text-lg btn-press mb-4 flex items-center justify-center gap-2">
                                <Shield className="w-5 h-5" /> Passkey Login
                            </button>
                        )}

                        {config.allowPasswordReset && (config.smtpHost || config.smtpConfigured) && (
                            <button type="button" onClick={() => setShowResetRequest(true)} className="w-full text-neutral-400 hover:text-purple-400 text-sm transition">
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
                                    className="w-full bg-black border border-neutral-700 text-white rounded-lg p-4 mb-4 focus:border-purple-500 outline-none transition text-center text-xl font-mono uppercase placeholder-neutral-600"
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
                                    className="w-full bg-black border border-neutral-700 text-white rounded-lg p-4 mb-4 focus:border-purple-500 outline-none transition text-center text-2xl tracking-widest placeholder-neutral-600"
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

                        <button className="w-full bg-purple-600 hover:bg-purple-700 text-white p-4 rounded-lg font-bold transition shadow-lg shadow-purple-900/20 text-lg btn-press mb-4">Verify</button>

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

                            <button type="button" onClick={() => { setTwoFactorRequired(false); setTwoFactorCode(''); setIsBackupCode(false); }} className="text-neutral-500 hover:text-purple-400 text-sm transition">
                                Back to login
                            </button>
                        </div>
                    </>
                )}

                {config.ssoEnabled && !twoFactorRequired && (
                    <div className="mt-6 pt-6 border-t border-neutral-700 text-center">
                        <button type="button" onClick={handleSSO} className="text-purple-400 hover:text-purple-300 text-sm font-medium transition flex items-center justify-center gap-2 w-full">
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

                        <h2 className="text-2xl font-bold mb-4 text-white">Password Reset</h2>

                        {/* Koppel hier je submit functie */}
                        <form onSubmit={handleResetRequest}>
                            <input
                                className="w-full bg-black border border-neutral-700 text-white rounded-lg p-4 mb-4 focus:border-purple-500 outline-none transition placeholder-neutral-500"
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
                                    className="flex-1 bg-purple-600 hover:bg-purple-700 text-white p-3 rounded-lg font-bold transition btn-press shadow-[0_0_15px_rgba(147,51,234,0.3)]"
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

const GuestUploadPage = () => {
    const { id } = useParams();
    const [info, setInfo] = useState<any>(null);
    const [error, setError] = useState<string | null>(null); // State toevoegen
    const [password, setPassword] = useState('');
    const [unlocked, setUnlocked] = useState(false);
    const { notify, preview } = useUI();
    const [files, setFiles] = useState<UploadItem[]>([]);
    const [uploading, setUploading] = useState(false);
    const [success, setSuccess] = useState(false);
    const [progress, setProgress] = useState(0);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const folderInputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        // Fetch met error handling
        fetch(`${API_URL}/public/reverse/${id}`)
            .then(async r => {
                if (r.status === 404) { setError('Upload link not found'); return null; }
                if (r.status === 410) { setError('This upload link has expired'); return null; }
                if (!r.ok) { setError('Error loading upload page'); return null; }
                return r.json();
            })
            .then(data => {
                if (data) {
                    setInfo(data);
                    if (!data.protected) setUnlocked(true);
                }
            })
            .catch(() => setError('Network error'));

        fetch(`${API_URL}/config`).then(r => r.json()).then(data => {
            if (data.faviconUrl) {
                let link = document.querySelector("link[rel~='icon']") as HTMLLinkElement;
                if (!link) { link = document.createElement('link'); link.rel = 'icon'; document.getElementsByTagName('head')[0].appendChild(link); }
                link.href = data.faviconUrl;
            }
        });
    }, [id]);

    const verify = async () => { const res = await fetch(`${API_URL}/public/reverse/${id}/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) }); const json = await res.json(); if (json.valid) setUnlocked(true); else notify('Wrong password', "error"); };

    // Reuse logic from UploadView
    const handleDrop = async (e: any) => {
        e.preventDefault();
        const items = e.dataTransfer.items;
        if (items) {
            const promises = [];
            for (let i = 0; i < items.length; i++) {
                const item = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null;
                if (item) promises.push(traverseFileTree(item));
                else if (items[i].kind === 'file') {
                    const f = items[i].getAsFile();
                    if (f) promises.push(Promise.resolve([{ file: f, path: f.name, name: f.name, id: generateUUID(), isDirectory: false, size: f.size }]));
                }
            }
            const results = await Promise.all(promises);
            setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...results.flat()])));
        } else if (e.target.files) {
            const newFiles = Array.from(e.target.files as FileList).map((f: any) => ({
                file: f, path: f.webkitRelativePath || f.name, name: f.name, id: generateUUID(), isDirectory: false, size: f.size
            }));
            setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...newFiles])));
        }
    };

    const onPickFolder = async () => {
        try {
            // @ts-ignore
            if (window.showDirectoryPicker) {
                // @ts-ignore
                const dirHandle = await window.showDirectoryPicker();
                const items = await processHandle(dirHandle);
                setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...items])));
            } else folderInputRef.current?.click();
        } catch (err: any) { if (err.name !== 'AbortError') folderInputRef.current?.click(); }
    };

    const handleUpload = async () => {
        setUploading(true);
        setProgress(0);

        try {
            const configRes = await fetch(`${API_URL}/config`);
            const config = await configRes.json();
            const k = 1024;
            const sizeMap: any = { 'KB': k, 'MB': k * k, 'GB': k * k * k, 'TB': k * k * k * k };
            const chunkSizeVal = config.chunkSizeVal || 50;
            const chunkSizeUnit = config.chunkSizeUnit || 'MB';
            const CHUNK_SIZE = chunkSizeVal * (sizeMap[chunkSizeUnit] || sizeMap['MB']);

            // Init call
            const initRes = await axios.post(`${API_URL}/public/reverse/${id}/init`);
            if (!initRes.data.success) throw new Error('Init failed');

            const uploadableFiles = files.filter(f => !f.isDirectory && f.file);
            const uploadedFilesMeta = [];
            const totalUploadSize = uploadableFiles.reduce((acc, f) => acc + f.size, 0);
            let uploadedBytes = 0;

            for (const item of uploadableFiles) {
                const file = item.file as File;
                const fileId = generateUUID();
                const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

                for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                    const start = chunkIndex * CHUNK_SIZE;
                    const end = Math.min(start + CHUNK_SIZE, file.size);
                    const chunk = file.slice(start, end);

                    const fd = new FormData();
                    fd.append('chunk', chunk);
                    fd.append('chunkIndex', chunkIndex.toString());
                    fd.append('fileName', file.name);
                    fd.append('fileId', fileId);

                    // --- RETRY LOGICA (AUTO-HERSTEL) ---
                    let attempts = 0;
                    const maxAttempts = 10;
                    let success = false;

                    while (!success && attempts < maxAttempts) {
                        try {
                            await axios.post(`${API_URL}/public/reverse/${id}/chunk`, fd);
                            success = true;
                        } catch (err) {
                            attempts++;
                            console.warn(`Chunk ${chunkIndex} failed, retrying...`);
                            if (attempts >= maxAttempts) throw new Error(`Upload failed.`);
                            await new Promise(res => setTimeout(res, 1000 * attempts));
                        }
                    }

                    uploadedBytes += chunk.size;
                    setProgress(Math.round((uploadedBytes * 100) / totalUploadSize));
                }
                uploadedFilesMeta.push({ fileName: file.name, originalName: item.path, fileId: fileId, size: file.size, mimeType: file.type });
            }

            setProgress(99);
            await axios.post(`${API_URL}/public/reverse/${id}/finalize`, { files: uploadedFilesMeta });
            setSuccess(true);

        } catch (e: any) {
            const msg = e.response?.data?.error || e.message || 'Error during upload';
            notify(msg, "error");
        } finally {
            setUploading(false);
            setProgress(0);
        }
    };

    // Error UI renderen
    if (error) return (
        <div className="min-h-screen bg-black flex items-center justify-center p-4">
            <div className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full text-center anim-scale">
                <div className="w-16 h-16 bg-neutral-800 rounded-full flex items-center justify-center mx-auto mb-4">
                    <XCircle className="w-8 h-8 text-red-500" />
                </div>
                <h2 className="text-xl font-bold text-white mb-2">Unavailable</h2>
                <p className="text-neutral-400">{error}</p>
                <a href="/" className="mt-6 inline-block text-purple-400 hover:text-white transition text-sm font-medium">Go to home</a>
            </div>
        </div>
    );

    if (!info) return <div className="min-h-screen bg-black flex items-center justify-start pt-24 md:pt-32 text-white">Loading...</div>;
    if (success) return (
        <div className="min-h-screen bg-black flex items-center justify-start pt-24 md:pt-32 p-4 flex-col">
            <div className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 text-center max-w-md w-full anim-scale mb-8">
                <Check className="w-16 h-16 text-green-500 mx-auto mb-4" />
                <h1 className="text-2xl font-bold text-white">Thanks!</h1>
                <p className="text-neutral-400 mt-2">Your files have been sent successfully.</p>

                {/* Toon custom bericht indien aanwezig */}
                {info && info.thankYouMessage && (
                    <div className="mt-6 bg-black/50 p-4 rounded-xl border border-neutral-800 text-purple-200 italic">
                        "{info.thankYouMessage}"
                    </div>
                )}
            </div>
            <Footer />
        </div>
    );

    return (
        <div className="min-h-screen bg-black flex items-center justify-start pt-24 md:pt-32 p-4 flex-col">
            <GlobalStyles />
            <div className="bg-neutral-900 p-6 md:p-8 rounded-2xl border border-neutral-800 max-w-lg w-full anim-slide shadow-2xl mb-8">
                <div className="text-center mb-8">
                    <div className="w-16 h-16 bg-purple-600/20 rounded-2xl flex items-center justify-center mx-auto mb-4"><Upload className="w-8 h-8 text-purple-500" /></div>
                    <h1 className="text-2xl font-bold text-white">{info.name}</h1>
                    <p className="text-neutral-400">Upload files to this folder.</p>
                </div>
                {!unlocked ? (
                    <form
                        onSubmit={(e) => { e.preventDefault(); verify(); }}
                        className="space-y-4 anim-fade"
                    >
                        <input
                            className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white text-center focus:border-purple-500 outline-none transition"
                            type="password"
                            placeholder="Password required"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            autoFocus // Handig: cursor staat er direct in
                        />
                        <button
                            type="submit"
                            className="w-full bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-110 text-white p-3 rounded-lg font-bold transition-all btn-press"
                        >
                            Unlock
                        </button>
                    </form>
                ) : (
                    <div className="space-y-6 anim-fade">

                        {/* @ts-ignore */}
                        <input className="hidden" webkitdirectory="" mozdirectory="" type="file" ref={folderInputRef} onChange={(e) => {
                            if (e.target.files) {
                                const newFiles = Array.from(e.target.files as FileList).map((f: any) => ({
                                    file: f, path: f.webkitRelativePath || f.name, name: f.name, id: generateUUID(), isDirectory: false, size: f.size
                                }));
                                setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...newFiles])));
                                e.target.value = '';
                            }
                        }} />

                        <div
                            className="bg-neutral-900 border-2 border-dashed border-neutral-800 rounded-2xl md:p-10 flex flex-col items-center justify-center min-h-[250px] md:min-h-[30px] hover:border-purple-500 hover:bg-neutral-900/80 transition-all duration-300 group relative overflow-hidden"
                            onDragOver={e => e.preventDefault()}
                            onDrop={handleDrop}
                        >
                            <div className="absolute inset-0 z-0 cursor-pointer" onClick={() => fileInputRef.current?.click()} />

                            <div className="relative z-10 text-center pointer-events-none mb-4">
                                <div className="w-16 h-16 bg-gradient-to-tr from-purple-600 to-blue-600 rounded-full flex items-center justify-center mx-auto mb-4 shadow-xl group-hover:scale-110 transition-transform duration-300">
                                    <CloudUpload className="text-white w-8 h-8" />
                                </div>
                                <h3 className="text-xl font-bold text-white mb-2">Drag & Drop files</h3>
                                <p className="text-neutral-400 text-sm max-w-xs mx-auto mb-6">or click to browse from your computer</p>
                            </div>

                            <div className="relative z-20 flex gap-3 mt-0 pointer-events-auto">
                                <button onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }} className="text-xs bg-neutral-800 hover:bg-neutral-700 text-white px-3 py-2 rounded-lg transition border border-neutral-700 cursor-pointer hover:border-purple-500">Select Files</button>
                                <button onClick={(e) => { e.stopPropagation(); onPickFolder(); }} className="text-xs bg-neutral-800 hover:bg-neutral-700 text-white px-3 py-2 rounded-lg transition border border-neutral-700 flex items-center gap-2 cursor-pointer hover:border-purple-500"><FolderIcon className="w-3 h-3" /> Select Folder</button>
                            </div>
                            {info.maxSize && (
                                <div className="mt-4 px-3 py-1 rounded-full bg-neutral-800 border border-neutral-700 text-xs text-neutral-400 font-medium">
                                    Max size: {formatBytes(info.maxSize)}
                                </div>
                            )}
                        </div>

                        {/* @ts-ignore */}
                        <input ref={fileInputRef} type="file" multiple className="hidden" onChange={e => {
                            if (e.target.files) {
                                const newFiles = Array.from(e.target.files as FileList).map((f: any) => ({
                                    file: f, path: f.webkitRelativePath || f.name, name: f.name, id: generateUUID(), isDirectory: false, size: f.size
                                }));
                                setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...newFiles])));
                                e.target.value = '';
                            }
                        }} />

                        {files.length > 0 && (
                            <div className="mt-2 bg-neutral-900 rounded-2xl border border-neutral-800 overflow-hidden shadow-xl" style={{ "--indent-step": "24px" } as React.CSSProperties}>
                                <style>{`@media (max-width: 768px) { [style*="--indent-step"] { --indent-step: 12px !important; } }`}</style>
                                <div className="max-h-[300px] overflow-y-auto">
                                    {files.map((item) => {
                                        const segments = item.path.split('/');
                                        const depth = Math.max(0, segments.length - 1);
                                        // Using calc with var for responsive indent
                                        return (
                                            <div key={item.id} className={`flex justify-between items-center px-3 py-2 md:px-4 md:py-3 border-b border-neutral-800 last:border-0 hover:bg-neutral-800/50 transition gap-2 ${item.isDirectory ? 'bg-neutral-800/30' : ''}`}>
                                                <div
                                                    className="flex items-center gap-2 md:gap-4 overflow-hidden flex-1 min-w-0 cursor-pointer"
                                                    style={{ paddingLeft: `calc(${depth} * var(--indent-step, 12px))` }}
                                                    onClick={() => !item.isDirectory && item.file && preview(item.file, item.name)}
                                                >
                                                    <div className="bg-black p-2 rounded-lg flex-shrink-0 relative">
                                                        {item.isDirectory ? <FolderIcon className="w-4 h-4 text-purple-400" /> : <div className="uppercase text-xs font-bold text-purple-400">{item.name.split('.').pop()}</div>}
                                                        {depth > 0 && <div className="absolute -left-3 top-1/2 -translate-y-1/2 w-2 h-[1px] bg-neutral-600"></div>}
                                                    </div>
                                                    <div className="min-w-0 flex-1">
                                                        <p className={`text-white font-medium truncate text-sm md:text-base ${item.isDirectory ? 'text-purple-300' : ''}`}>{item.name}</p>
                                                        {!item.isDirectory && <p className="text-neutral-500 text-xs">{formatBytes(item.size)}</p>}
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    {!item.isDirectory && (
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); item.file && preview(item.file, item.name); }}
                                                            className="text-neutral-500 hover:text-white p-2 transition flex-shrink-0 hidden md:block"
                                                            title="Preview"
                                                        >
                                                            <Eye className="w-4 h-4 md:w-5 md:h-5" />
                                                        </button>
                                                    )}
                                                    <button onClick={(e) => { e.stopPropagation(); setFiles(files.filter(x => x.id !== item.id && !x.path.startsWith(item.path + '/'))) }} className="text-neutral-500 hover:text-red-400 p-2 transition flex-shrink-0"><X className="w-4 h-4 md:w-5 md:h-5" /></button>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        )}

                        {uploading && (
                            <div className="w-full bg-neutral-800 rounded-full h-2.5 overflow-hidden">
                                <div className="bg-green-500 h-2.5 rounded-full transition-all duration-300" style={{ width: `${progress}%` }}></div>
                            </div>
                        )}

                        <button onClick={handleUpload} disabled={uploading || files.length === 0} className="w-full bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg font-bold disabled:bg-neutral-800 transition btn-press shadow-lg">
                            {uploading ? `In progress (${progress}%)...` : `Send ${files.length} files`}
                        </button>
                    </div>
                )}
            </div>
            <Footer />
        </div>
    );
};

const PasswordResetPage = () => {
    const [token, setToken] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [success, setSuccess] = useState(false);
    const { notify } = useUI();

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const t = params.get('token');
        if (t) {
            setToken(t);
            // Verify token
            fetch(`${API_URL}/auth/password-reset/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: t })
            }).then(res => {
                if (!res.ok) {
                    notify('Invalid or expired reset link', 'error');
                }
            });
        } else {
            notify('No reset token found', 'error');
        }
    }, []);

    const handleSubmit = async (e: any) => {
        e.preventDefault();

        if (newPassword !== confirmPassword) {
            notify('Passwords do not match', 'error');
            return;
        }

        if (newPassword.length < 8) {
            notify('Password must be at least 8 characters', 'error');
            return;
        }

        if (!/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
            notify('Password must contain at least 1 lowercase letter, 1 uppercase letter and 1 number', 'error');
            return;
        }

        const res = await fetch(`${API_URL}/auth/password-reset/complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, password: newPassword })
        });

        const data = await res.json();

        if (res.ok) {
            setSuccess(true);
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else {
            notify(data.error || 'Reset failed', 'error');
        }
    };

    if (success) {
        return (
            <div className="min-h-screen bg-black flex items-center justify-center p-4">
                <div className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full text-center">
                    <div className="bg-green-500/20 text-green-400 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                        <Check className="w-8 h-8" />
                    </div>
                    <h2 className="text-2xl font-bold text-white mb-2">Password reset!</h2>
                    <p className="text-neutral-400">You will be redirected to the login page...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-black flex items-center justify-center p-4">
            <GlobalStyles />
            <form onSubmit={handleSubmit} className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full">
                <h2 className="text-2xl font-bold text-white mb-6 text-center">Set New Password</h2>
                <div className="space-y-4">
                    <div>
                        <label className="block text-neutral-400 text-sm font-bold mb-2">New Password</label>
                        <input type="password" className="w-full bg-black border border-neutral-700 text-white rounded-lg p-3 focus:border-purple-500 outline-none" placeholder="At least 8 characters" value={newPassword} onChange={e => setNewPassword(e.target.value)} required />
                    </div>
                    <div>
                        <label className="block text-neutral-400 text-sm font-bold mb-2">Confirm Password</label>
                        <input type="password" className="w-full bg-black border border-neutral-700 text-white rounded-lg p-3 focus:border-purple-500 outline-none" placeholder="Repeat Password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} required />
                    </div>
                    <button type="submit" className="w-full bg-purple-600 hover:bg-purple-700 text-white p-3 rounded-lg font-bold transition btn-press">
                        Reset Password
                    </button>
                </div>
            </form>
        </div>
    );
};

const DownloadPage = () => {
    const { id } = useParams();
    const [data, setData] = useState<any>(null);
    const [viewFiles, setViewFiles] = useState<UploadItem[]>([]); // New state for transformed files
    const [error, setError] = useState<string | null>(null);
    const [password, setPassword] = useState('');
    const { notify, preview } = useUI();

    useEffect(() => {
        // We passen de fetch aan om errors af te vangen
        fetch(`${API_URL}/public/shares/${id}`)
            .then(async r => {
                if (r.status === 404) { setError('Share not found'); return null; }
                if (r.status === 410) { setError('This share is no longer available (expired or limit reached)'); return null; }
                if (!r.ok) { setError('An error occurred'); return null; }
                return r.json();
            })
            .then(d => {
                if (d) {
                    setData(d);
                    // Transform backend files to UploadItem format
                    const backendFiles = d.files || [];
                    const mapped: UploadItem[] = backendFiles.map((f: any) => ({
                        file: null,
                        path: f.original_name, // Backend path e.g. Folder/File.txt
                        name: f.original_name.split('/').pop() || f.original_name,
                        id: f.id,
                        isDirectory: false,
                        size: f.size
                    }));
                    setViewFiles(sortFiles(synthesizeDirectoryItems(mapped)));
                }
            })
            .catch(() => setError('Network error'));

        fetch(`${API_URL}/config`).then(r => r.json()).then(fetchedConfig => {
            if (fetchedConfig.faviconUrl) {
                let link = document.querySelector("link[rel~='icon']") as HTMLLinkElement;
                if (!link) { link = document.createElement('link'); link.rel = 'icon'; document.getElementsByTagName('head')[0].appendChild(link); }
                link.href = fetchedConfig.faviconUrl;
            }
        });
    }, [id]);

    const verify = async () => {
        const res = await fetch(`${API_URL}/shares/${id}/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) });
        const json = await res.json();
        if (json.valid) {
            setData({ ...data, files: json.files, protected: false });
            // Also update viewFiles
            const mapped: UploadItem[] = (json.files || []).map((f: any) => ({
                file: null,
                path: f.original_name,
                name: f.original_name.split('/').pop() || f.original_name,
                id: f.id,
                isDirectory: false,
                size: f.size
            }));
            setViewFiles(sortFiles(synthesizeDirectoryItems(mapped)));
        } else notify('Wrong password', "error");
    };

    // Error Scherm
    if (error) return (
        <div className="min-h-screen bg-black flex items-center justify-center p-4">
            <div className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full text-center anim-scale">
                <div className="w-16 h-16 bg-neutral-800 rounded-full flex items-center justify-center mx-auto mb-4">
                    <FileQuestion className="w-8 h-8 text-neutral-500" />
                </div>
                <h2 className="text-xl font-bold text-white mb-2">Unavailable</h2>
                <p className="text-neutral-400">{error}</p>
                <a href="/" className="mt-6 inline-block text-purple-400 hover:text-white transition text-sm font-medium">Go to home</a>
            </div>
        </div>
    );

    if (!data) return <div className="min-h-screen bg-black flex items-center justify-center text-white"><Loader2 className="w-8 h-8 animate-spin text-purple-500" /></div>;

    return (
        <div className="min-h-screen bg-black flex items-center justify-start pt-24 md:pt-32 p-4 flex-col">
            <GlobalStyles />
            <div className="bg-neutral-900 rounded-2xl p-6 md:p-8 max-w-lg w-full border border-neutral-800 shadow-2xl anim-scale mb-8">
                <div className="text-center mb-8">
                    <div className="w-16 h-16 bg-purple-600/20 rounded-2xl flex items-center justify-center mx-auto mb-4"><Download className="text-purple-500 w-8 h-8" /></div>
                    <h1 className="text-2xl font-bold text-white mb-1">{data.name}</h1>
                    <p className="text-neutral-400 text-sm">Shared with {data.appName || 'Nexo Share'}</p>
                </div>
                {data.protected ? (
                    <form
                        onSubmit={(e) => { e.preventDefault(); verify(); }}
                        className="text-center space-y-4 anim-fade"
                    >
                        <div className="bg-yellow-500/10 text-yellow-500 p-3 rounded-lg text-sm mb-4 border border-yellow-500/20">
                            This download is protected with a password.
                        </div>
                        <input
                            className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white text-center outline-none focus:border-purple-500 transition"
                            type="password"
                            placeholder="Enter password"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            autoFocus
                        />
                        <button
                            type="submit"
                            className="bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-110 text-white px-6 py-3 rounded-lg font-bold w-full transition-all btn-press"
                        >
                            Unlock
                        </button>
                    </form>
                ) : (
                    <div className="anim-fade">
                        {data.message && (
                            <div className="bg-black/50 p-4 rounded-xl border border-neutral-800 mb-6 text-neutral-300 text-sm italic relative">
                                <span className="absolute -top-3 left-4 bg-neutral-900 px-2 text-xs text-purple-400 font-bold uppercase">Message</span>
                                <div dangerouslySetInnerHTML={{
                                    __html: DOMPurify.sanitize(data.message, {
                                        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'br', 'p'],
                                        ALLOWED_ATTR: []
                                    })
                                }} />
                            </div>
                        )}

                        <div className="mb-6 max-h-[400px] overflow-y-auto bg-black/50 rounded-lg border border-neutral-800" style={{ "--indent-step": "24px" } as React.CSSProperties}>
                            <style>{`@media (max-width: 768px) { [style*="--indent-step"] { --indent-step: 12px !important; } }`}</style>
                            {viewFiles.map((item) => {
                                const segments = item.path.split('/');
                                const depth = Math.max(0, segments.length - 1);

                                return (
                                    <div key={item.id} className={`flex justify-between items-center px-3 py-2 md:px-4 md:py-3 border-b border-neutral-800 last:border-0 hover:bg-neutral-800/50 transition gap-2 ${item.isDirectory ? 'bg-neutral-800/30' : ''}`}>
                                        {/* Klik op naam = Preview */}
                                        <div
                                            className="flex items-center gap-2 md:gap-4 overflow-hidden flex-1 min-w-0 cursor-pointer group"
                                            style={{ paddingLeft: `calc(${depth} * var(--indent-step, 12px))` }}
                                            onClick={() => !item.isDirectory && preview(`${API_URL}/shares/${id}/files/${item.id}`, item.name)}
                                        >
                                            <div className="bg-black p-2 rounded-lg flex-shrink-0 relative group-hover:bg-neutral-700 transition">
                                                {item.isDirectory ? <FolderIcon className="w-4 h-4 text-purple-400" /> : <div className="uppercase text-xs font-bold text-purple-400 min-w-[2.5rem] w-auto text-center">{item.name.split('.').pop()}</div>}
                                                {depth > 0 && <div className="absolute -left-3 top-1/2 -translate-y-1/2 w-2 h-[1px] bg-neutral-600"></div>}
                                            </div>
                                            <div className="min-w-0 flex-1">
                                                <p className={`text-neutral-200 font-medium truncate text-sm md:text-base ${item.isDirectory ? 'text-purple-300' : 'group-hover:text-purple-300 transition'}`}>{item.name}</p>
                                                {!item.isDirectory && <p className="text-neutral-500 text-xs">{formatBytes(item.size)}</p>}
                                            </div>
                                        </div>

                                        {!item.isDirectory && (
                                            <div className="flex items-center gap-2">
                                                <button
                                                    onClick={() => preview(`${API_URL}/shares/${id}/files/${item.id}`, item.name)}
                                                    className="text-neutral-400 hover:text-white p-2 rounded hover:bg-neutral-800 transition hidden md:block"
                                                    title="Preview"
                                                >
                                                    <Eye className="w-4 h-4" />
                                                </button>
                                                <a
                                                    href={`${API_URL}/shares/${encodeURIComponent(id!)}/files/${encodeURIComponent(item.id)}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="text-purple-400 hover:text-white p-2 rounded hover:bg-neutral-800 transition flex-shrink-0"
                                                    title="Download"
                                                >
                                                    <Download className="w-4 h-4" />
                                                </a>
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                        <a
                            href={`${API_URL}/shares/${encodeURIComponent(id!)}/download`}
                            target="_blank"             // Opent in nieuw tabblad
                            rel="noopener noreferrer"
                            className="block w-full bg-gradient-to-br from-purple-600 to-blue-600 hover:brightness-90 text-center text-white font-bold py-3 rounded-lg transition btn-press shadow-lg shadow-green-900/20"
                        >
                            Download everything (.zip)
                        </a>
                    </div>
                )}
            </div>
            <Footer />
        </div>
    );
};

function App() {
    const { user, token, login, logout, loading } = useAuth();
    if (loading) return <div className="bg-black min-h-screen" />;

    return (
        <BrowserRouter>
            <UIProvider>
                <Routes>
                    <Route path="/s/:id" element={<DownloadPage />} />
                    <Route path="/r/:id" element={<GuestUploadPage />} />
                    <Route path="/login" element={!user ? <LoginPage onLogin={login} /> : <Navigate to="/" />} />
                    <Route path="/reset-password" element={<PasswordResetPage />} />
                    <Route path="/*" element={user ? <Dashboard token={token} logout={logout} /> : <Navigate to="/login" />} />
                </Routes>
            </UIProvider>
        </BrowserRouter>
    );
}

export default App;