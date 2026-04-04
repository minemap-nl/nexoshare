import { useState, useEffect } from 'react';
import axios from 'axios';
import { Sparkles, Shield, ArrowRight, Check, Loader2 } from 'lucide-react';
import { API_URL } from '../api/constants';
import { useUI } from '../context/UIContext';
import { ModalPortal } from '../components/ui/ModalPortal';
import { Checkbox } from '../components/ui/Checkbox';


export function SetupWizard({ onClose }: { onClose: () => void }) {
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
                            <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center text-primary-300">
                                {step === 4 ? <Check className="w-6 h-6" /> : <Sparkles className="w-6 h-6" />}
                            </div>
                            <div>
                                <h2 className="heading-panel">Welcome to {config.appName || 'Nexo Share'}</h2>
                                <p className="text-sm text-neutral-400">First installation setup {step > 0 && `(${step}/3)`}</p>
                            </div>
                        </div>
                        {step < 4 && <button onClick={onClose} className="text-neutral-500 hover:text-white px-3 py-1 text-sm transition">Skip</button>}
                    </div>

                    {/* Content */}
                    <div className="p-8 overflow-y-auto flex-1">
                        {step === 0 && (
                            <div className="text-center py-4">
                                <Shield className="w-20 h-20 text-primary-400 mx-auto mb-6 opacity-80" />
                                <h3 className="heading-section mb-4">Let's secure your server</h3>
                                <p className="text-neutral-400 max-w-md mx-auto mb-8 leading-relaxed">
                                    We'll help you in 3 steps with basic settings, email configuration, and creating a secure admin account.
                                </p>
                                <button onClick={() => setStep(1)} className="bg-primary hover:bg-primary-700 text-white px-8 py-3 rounded-lg font-bold transition flex items-center gap-2 mx-auto shadow-lg shadow-primary-950/25">
                                    Start Setup <ArrowRight className="w-4 h-4" />
                                </button>
                            </div>
                        )}

                        {step === 1 && (
                            <div className="space-y-6 anim-slide">
                                <h3 className="heading-panel mb-2">1. Basic Settings</h3>
                                <div className="grid gap-4">
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Application Name <span className="text-red-500">*</span></label>
                                        <input className="input-field"
                                            value={config.appName || ''} onChange={e => setConfig({ ...config, appName: e.target.value })} placeholder="My Company Share" />
                                    </div>
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Public URL</label>
                                        <input className="input-field"
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
                                <h3 className="heading-panel mb-2">2. E-mail Settings (SMTP)</h3>
                                <p className="text-neutral-400 text-sm mb-4">Required for password resets and notifications. You may skip this step.</p>

                                <div className="grid grid-cols-2 gap-4">
                                    <div className="col-span-2">
                                        <label className="block text-neutral-400 text-sm mb-1">SMTP Host</label>
                                        <input className="input-field"
                                            value={config.smtpHost || ''} onChange={e => setConfig({ ...config, smtpHost: e.target.value })} placeholder="smtp.office365.com" />
                                    </div>
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Port</label>
                                        <input type="number" className="input-field"
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
                                        <input className="input-field"
                                            value={config.smtpUser || ''} onChange={e => setConfig({ ...config, smtpUser: e.target.value })} placeholder="email@company.com" />
                                    </div>
                                    <div className="col-span-2">
                                        <label className="block text-neutral-400 text-sm mb-1">Password</label>
                                        <input type="password" className="input-field"
                                            value={config.smtpPass || ''} onChange={e => setConfig({ ...config, smtpPass: e.target.value })} placeholder="••••••••" />
                                    </div>
                                    <div className="col-span-2">
                                        <label className="block text-neutral-400 text-sm mb-1">Sender Address (From)</label>
                                        <input className="input-field"
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
                                <h3 className="heading-panel mb-2">3. Create your own Admin account</h3>
                                <div className="grid gap-4 bg-black/30 p-6 rounded-xl border border-neutral-800">
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Your name</label>
                                        <input className="input-field"
                                            value={newUser.name} onChange={e => setNewUser({ ...newUser, name: e.target.value })} placeholder="Jan Jansen" />
                                    </div>
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Email Address</label>
                                        <input className="input-field"
                                            value={newUser.email} onChange={e => setNewUser({ ...newUser, email: e.target.value })} placeholder="jan@company.com" />
                                    </div>
                                    <div>
                                        <label className="block text-neutral-400 text-sm mb-1">Password</label>
                                        <input type="password" className="input-field"
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
                                <h3 className="heading-section mb-4">Done!</h3>
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
                        <div className="h-full bg-primary transition-all duration-500 ease-out" style={{ width: `${(step / 4) * 100}%` }}></div>
                    </div>
                </div>
            </div>
        </ModalPortal>
    );
};
