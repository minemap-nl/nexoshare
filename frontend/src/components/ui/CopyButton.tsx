import { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { useUI } from '../../context/UIContext';

export function CopyButton({ text, className }: { text: string; className?: string }) {
    const [copied, setCopied] = useState(false);
    const { notify } = useUI();
    const copy = () => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        notify('Link is copied to your clipboard', 'success');
        setTimeout(() => setCopied(false), 2000);
    };
    return (
        <button type="button" onClick={copy} className={`${className} transition-all duration-300 flex items-center gap-2 ${copied ? 'text-green-400 bg-green-500/10' : ''}`}>
            {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copied ? 'Copied' : text}
        </button>
    );
}
