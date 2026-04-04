import type { ChangeEvent, ReactNode } from 'react';
import { Check } from 'lucide-react';

export function Checkbox({
    checked,
    onChange,
    label,
    className = '',
}: {
    checked: boolean;
    onChange: (e: ChangeEvent<HTMLInputElement>) => void;
    label?: ReactNode;
    className?: string;
}) {
    return (
        <label className={`flex items-center gap-3 cursor-pointer group ${className}`}>
            <div className="relative flex items-center">
                <input
                    type="checkbox"
                    className="peer sr-only"
                    checked={checked}
                    onChange={onChange}
                />
                <div
                    className={`
                w-5 h-5 rounded border transition-all duration-200 flex items-center justify-center shadow-sm
                ${checked
                    ? 'bg-primary border-primary shadow-primary-950/30'
                    : 'bg-neutral-900 border-neutral-700 group-hover:border-neutral-500'
                }
            `}
                >
                    <Check className={`w-3.5 h-3.5 text-white transition-all duration-200 stroke-[3px] ${checked ? 'scale-100 opacity-100' : 'scale-50 opacity-0'}`} />
                </div>
            </div>
            {label && <span className="text-white font-medium select-none">{label}</span>}
        </label>
    );
}
