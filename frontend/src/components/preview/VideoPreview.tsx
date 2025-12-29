import React, { useState, useEffect, useRef } from 'react';
import { Loader2 } from 'lucide-react';

interface VideoPreviewProps {
    file: File | Blob | string;
}

const VideoPreview: React.FC<VideoPreviewProps> = ({ file }) => {
    const [url, setUrl] = useState<string | null>(null);
    const videoRef = useRef<HTMLVideoElement>(null);

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
                if (videoRef.current) {
                    videoRef.current.paused ? videoRef.current.play() : videoRef.current.pause();
                }
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, []);

    if (!url) return <div className="flex justify-center items-center h-full"><Loader2 className="w-8 h-8 animate-spin text-purple-500" /></div>;

    return (
        <div className="flex items-center justify-center h-full w-full bg-black rounded-xl overflow-hidden">
            <video
                src={url}
                ref={videoRef}
                controls
                className="max-w-full max-h-full w-full h-auto outline-none"
                controlsList="nodownload"
                autoPlay={false}
            />
        </div>
    );
};

export default VideoPreview;
