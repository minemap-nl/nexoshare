import React, { useState, useEffect, useRef } from 'react';
import { Loader2, Music } from 'lucide-react';

interface AudioPreviewProps {
    file: File | Blob | string;
}

const AudioPreview: React.FC<AudioPreviewProps> = ({ file }) => {
    const [url, setUrl] = useState<string | null>(null);
    const audioRef = useRef<HTMLAudioElement>(null);

    useEffect(() => {
        if (typeof file === 'string') {
            setUrl(file);
        } else {
            const objectUrl = URL.createObjectURL(file);
            setUrl(objectUrl);
            return () => URL.revokeObjectURL(objectUrl);
        }
    }, [file]);

    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.code === 'Space') {
                e.preventDefault();
                if (audioRef.current) {
                    audioRef.current.paused ? audioRef.current.play() : audioRef.current.pause();
                }
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, []);

    if (!url) return <div className="flex justify-center items-center h-full"><Loader2 className="w-8 h-8 animate-spin text-purple-500" /></div>;

    return (
        <div className="flex flex-col items-center justify-center h-full w-full bg-neutral-900 rounded-xl p-8">
            <div className="w-32 h-32 bg-neutral-800 rounded-full flex items-center justify-center mb-8 shadow-2xl animate-pulse">
                <Music className="w-16 h-16 text-purple-500" />
            </div>
            <audio
                src={url}
                ref={audioRef}
                controls
                className="w-full max-w-md outline-none"
                controlsList="nodownload"
            />
        </div>
    );
};

export default AudioPreview;
