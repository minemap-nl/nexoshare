import React, { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { X, Download, FileText, ShieldAlert } from 'lucide-react';

import ImagePreview from './ImagePreview';
import VideoPreview from './VideoPreview';
import AudioPreview from './AudioPreview';
import TextPreview from './TextPreview';
import PDFPreview from './PDFPreview';
import ExcelPreview from './ExcelPreview';
import WordPreview from './WordPreview';
import PowerPointPreview from './PowerPointPreview';

export interface FilePreviewProps {
    file: File | Blob | string;
    name: string;
    type?: string;
    onClose: () => void;
}

const FilePreviewModal: React.FC<FilePreviewProps> = ({ file, name, type, onClose }) => {
    const modalRef = useRef<HTMLDivElement>(null);

    // Prevent body scroll and handle interactions
    useEffect(() => {
        document.body.style.overflow = 'hidden';

        // Force focus to modal
        if (modalRef.current) modalRef.current.focus();

        // Keyboard navigation - CAPTURE PHASE to override everything
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                onClose();
            }
        };

        window.addEventListener('keydown', handleKeyDown, { capture: true });
        return () => {
            document.body.style.overflow = 'unset';
            window.removeEventListener('keydown', handleKeyDown, { capture: true });
        };
    }, [onClose]);

    const getFileType = (fileName: string, mimeType?: string) => {
        const ext = fileName.split('.').pop()?.toLowerCase() || '';

        // Security: Block dangerous types from preview
        if (['html', 'htm', 'xhtml', 'svg', 'xml', 'php'].includes(ext)) return 'restricted';

        if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'].includes(ext)) return 'image';
        if (['mp4', 'webm', 'ogg', 'mov', 'avi', 'mkv'].includes(ext)) return 'video';
        if (['mp3', 'wav', 'flac', 'm4a', 'aac'].includes(ext)) return 'audio';
        if (ext === 'pdf') return 'pdf';
        if (['xlsx', 'xls', 'csv', 'ods'].includes(ext)) return 'excel';
        if (['docx', 'doc'].includes(ext)) return 'word';
        if (['pptx', 'ppt'].includes(ext)) return 'powerpoint';
        if (['txt', 'md', 'json', 'js', 'ts', 'tsx', 'jsx', 'css', 'yaml', 'yml', 'sql', 'py', 'sh', 'bat', 'env', 'log'].includes(ext)) return 'text';

        if (mimeType?.startsWith('image/')) return 'image';
        if (mimeType?.startsWith('video/')) return 'video';
        if (mimeType?.startsWith('audio/')) return 'audio';
        if (mimeType?.startsWith('text/')) return 'text';

        return 'unknown';
    };

    const fileType = getFileType(name, type);

    const renderPreview = () => {
        switch (fileType) {
            case 'restricted':
                return (
                    <div className="flex flex-col items-center justify-center h-full text-neutral-400">
                        <ShieldAlert className="w-16 h-16 mb-4 text-orange-500 opacity-80" />
                        <h3 className="text-lg font-medium text-white mb-2">Preview Restricted</h3>
                        <p className="text-center max-w-md px-4">This file type is not supported for previews due to security reasons.</p>
                        <p className="text-sm mt-4 opacity-50">Please download the file to view it.</p>
                    </div>
                );
            case 'image': return <ImagePreview file={file} />;
            case 'video': return <VideoPreview file={file} />;
            case 'audio': return <AudioPreview file={file} />;
            case 'pdf': return <PDFPreview file={file} />;
            case 'excel': return <ExcelPreview file={file} />;
            case 'word': return <WordPreview file={file} />;
            case 'powerpoint': return <PowerPointPreview file={file} />;
            case 'text': return <TextPreview file={file} fileName={name} />;
            default:
                return (
                    <div className="flex flex-col items-center justify-center h-full text-neutral-400">
                        <FileText className="w-16 h-16 mb-4 opacity-50" />
                        <p>No preview available for this file type.</p>
                        <p className="text-sm mt-2">.{name.split('.').pop()}</p>
                    </div>
                );
        }
    };

    const handleDownload = () => {
        const link = document.createElement('a');
        if (typeof file === 'string') {
            link.href = file;
        } else {
            link.href = URL.createObjectURL(file);
        }
        link.download = name;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.98, backdropFilter: "blur(0px)" }}
            animate={{ opacity: 1, scale: 1, backdropFilter: "blur(12px)" }}
            exit={{ opacity: 0, scale: 0.98, backdropFilter: "blur(0px)" }}
            transition={{ duration: 0.2, ease: "easeInOut" }}
            ref={modalRef}
            tabIndex={-1}
            className="fixed inset-0 z-[10000] bg-black/80 flex flex-col outline-none"
            onClick={onClose}
        >
            {/* Header */}
            <motion.div
                initial={{ y: -20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                exit={{ y: -20, opacity: 0 }}
                transition={{ delay: 0.1 }}
                onClick={(e) => e.stopPropagation()}
                className="flex items-center justify-between p-4 border-b border-neutral-800 bg-neutral-900/80 backdrop-blur-md"
            >
                <div className="flex items-center gap-3 overflow-hidden">
                    <div className="bg-purple-600/20 p-2 rounded-lg">
                        <FileText className="w-5 h-5 text-purple-400" />
                    </div>
                    <h2 className="text-white font-medium truncate max-w-md md:max-w-xl">{name}</h2>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={handleDownload}
                        className="p-2 hover:bg-white/10 rounded-lg text-neutral-400 hover:text-white transition group"
                        title="Download"
                    >
                        <Download className="w-5 h-5 group-hover:scale-110 transition-transform" />
                    </button>
                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-red-500/20 hover:text-red-400 rounded-lg text-neutral-400 transition"
                        title="Close"
                    >
                        <X className="w-6 h-6" />
                    </button>
                </div>
            </motion.div>

            {/* Content */}
            <div className="flex-1 overflow-hidden p-4 md:p-8 flex items-center justify-center relative">
                <motion.div
                    initial={{ scale: 0.95, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0.95, opacity: 0 }}
                    transition={{ delay: 0.15 }}
                    onClick={(e) => e.stopPropagation()}
                    className="w-full h-full max-w-6xl mx-auto shadow-2xl relative z-10"
                >
                    {renderPreview()}
                </motion.div>
            </div>
        </motion.div>
    );
};

export default FilePreviewModal;
