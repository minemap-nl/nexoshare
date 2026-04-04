import type { ChangeEvent } from 'react';
import { Check, Shield } from 'lucide-react';

const COMMON_EXTENSIONS = [
    { ext: '.exe', label: 'Executables' }, { ext: '.bat', label: 'Batch Files' }, { ext: '.cmd', label: 'Command Scripts' },
    { ext: '.sh', label: 'Shell Scripts' }, { ext: '.ps1', label: 'PowerShell' }, { ext: '.vbs', label: 'VBScript' },
    { ext: '.php', label: 'PHP' }, { ext: '.pl', label: 'Perl' }, { ext: '.py', label: 'Python' },
    { ext: '.msp', label: 'Windows Patch' }, { ext: '.msi', label: 'Windows Installer' }, { ext: '.jar', label: 'Java JAR' },
    { ext: '.bin', label: 'Binary' }, { ext: '.dmg', label: 'macOS Image' }, { ext: '.pkg', label: 'macOS Package' },
    { ext: '.iso', label: 'Disk Image' }, { ext: '.img', label: 'Disk Image' }, { ext: '.deb', label: 'Debian Pkg' },
    { ext: '.rpm', label: 'RedHat Pkg' }, { ext: '.apk', label: 'Android App' }, { ext: '.xapk', label: 'Android Bundle' },
    { ext: '.ipa', label: 'iOS App' }, { ext: '.dll', label: 'Dynamic Link Lib' }, { ext: '.sys', label: 'System File' },
];

export function ExtensionSelector({
    label,
    blocked,
    onChange,
}: {
    label: string;
    blocked: string[];
    onChange: (list: string[]) => void;
}) {
    const isBlocked = (ext: string) => blocked.includes(ext.toLowerCase());

    const toggle = (ext: string) => {
        const lower = ext.toLowerCase();
        if (isBlocked(lower)) {
            onChange(blocked.filter(x => x !== lower));
        } else {
            onChange([...blocked, lower]);
        }
    };

    const commonSet = new Set(COMMON_EXTENSIONS.map(c => c.ext));
    const customExtensions = blocked.filter(x => !commonSet.has(x)).join(', ');

    const handleCustomChange = (e: ChangeEvent<HTMLInputElement>) => {
        const input = e.target.value;
        const newCustom = input.split(',').map(s => s.trim().toLowerCase()).filter(s => s.startsWith('.'));
        const currentCommon = blocked.filter(x => commonSet.has(x));
        const merged = Array.from(new Set([...currentCommon, ...newCustom]));
        onChange(merged);
    };

    return (
        <div className="bg-neutral-900/50 p-6 rounded-xl border border-neutral-800 mb-6">
            <h4 className="text-white font-bold mb-4 flex items-center gap-2"><Shield className="w-4 h-4 text-neutral-400" /> {label}</h4>
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
                    className="input-field font-mono text-sm placeholder:text-neutral-600"
                    placeholder=".xyz, .abc, .ransom"
                    value={customExtensions}
                    onChange={handleCustomChange}
                />
            </div>
        </div>
    );
}
