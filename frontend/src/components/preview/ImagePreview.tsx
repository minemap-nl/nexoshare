import React, { useState, useEffect } from 'react';
import { TransformWrapper, TransformComponent } from "react-zoom-pan-pinch";
import { Loader2, ZoomIn, ZoomOut, RotateCw } from 'lucide-react';

interface ImagePreviewProps {
    file: File | Blob | string;
}

const ImagePreview: React.FC<ImagePreviewProps> = ({ file }) => {
    const [url, setUrl] = useState<string | null>(null);
    const [rotation, setRotation] = useState(0);

    useEffect(() => {
        if (typeof file === 'string') {
            setUrl(file);
        } else {
            const objectUrl = URL.createObjectURL(file);
            setUrl(objectUrl);
            return () => URL.revokeObjectURL(objectUrl);
        }
    }, [file]);

    if (!url) return <div className="flex justify-center items-center h-full"><Loader2 className="w-8 h-8 animate-spin text-purple-500" /></div>;

    return (
        <div className="flex flex-col h-full w-full">
            <div className="flex-1 overflow-hidden bg-black/50 rounded-xl relative flex items-center justify-center">
                <TransformWrapper
                    initialScale={1}
                    minScale={0.5}
                    maxScale={4}
                    centerOnInit
                >
                    {({ zoomIn, zoomOut }) => (
                        <>
                            <div className="absolute top-4 right-4 z-20 flex flex-col gap-2 bg-neutral-900/80 p-2 rounded-lg backdrop-blur-sm border border-neutral-800">
                                <button onClick={() => zoomIn()} className="p-2 hover:bg-white/10 rounded-lg text-white transition" title="Zoom In">
                                    <ZoomIn className="w-5 h-5" />
                                </button>
                                <button onClick={() => zoomOut()} className="p-2 hover:bg-white/10 rounded-lg text-white transition" title="Zoom Out">
                                    <ZoomOut className="w-5 h-5" />
                                </button>
                                <button onClick={() => setRotation(r => (r + 90) % 360)} className="p-2 hover:bg-white/10 rounded-lg text-white transition" title="Rotate">
                                    <RotateCw className="w-5 h-5" />
                                </button>
                            </div>
                            <TransformComponent wrapperClass="!w-full !h-full" contentClass="!w-full !h-full flex items-center justify-center">
                                <img
                                    src={url}
                                    alt="Preview"
                                    className="max-w-full max-h-full object-contain transition-transform duration-300"
                                    style={{ transform: `rotate(${rotation}deg)` }}
                                />
                            </TransformComponent>
                        </>
                    )}
                </TransformWrapper>
            </div>
        </div>
    );
};

export default ImagePreview;
