import { useAppConfig } from '../../context/AppConfigContext';

export function DemoBanner() {
    const { config, loading } = useAppConfig();
    if (loading || !config?.demoMode) return null;
    const minutes = typeof config.demoDataRetentionMinutes === 'number' ? config.demoDataRetentionMinutes : 2;
    const maxMb = typeof config.demoMaxFileMb === 'number' ? config.demoMaxFileMb : 25;
    return (
        <div
            role="status"
            className="sticky top-0 z-[100] w-full border-b border-cyan-800/45 bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 py-2.5 px-3 text-center text-xs font-semibold text-cyan-50/95 shadow-md sm:text-sm"
        >
            Demo environment: uploaded data and shares are removed on a short schedule (about {minutes} minutes). Email is not sent.
            Max upload per share is {maxMb} MB (same as virus-scan limit; no bypass). Account, passkey, and 2FA changes are disabled.
        </div>
    );
}
