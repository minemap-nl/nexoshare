import React, { useState, useEffect } from 'react';
import * as XLSX from 'xlsx';
import { Loader2 } from 'lucide-react';
import DOMPurify from 'dompurify';

interface ExcelPreviewProps {
    file: File | Blob | string;
}

const ExcelPreview: React.FC<ExcelPreviewProps> = ({ file }) => {
    const [html, setHtml] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const load = async () => {
            try {
                let data;
                if (typeof file === 'string') {
                    const res = await fetch(file, { credentials: 'include' });
                    if (!res.ok) {
                        if (res.status === 401 || res.status === 403) {
                            throw new Error("Access Denied: You don't have permission to view this file.");
                        }
                        throw new Error(`Failed to load file: ${res.status} ${res.statusText}`);
                    }
                    data = await res.arrayBuffer();
                } else {
                    data = await file.arrayBuffer();
                }

                const workbook = XLSX.read(data);
                const firstSheetName = workbook.SheetNames[0];
                const worksheet = workbook.Sheets[firstSheetName];
                const htmlString = XLSX.utils.sheet_to_html(worksheet, { id: 'excel-preview-table' });

                // Sanitize HTML
                const cleanHtml = DOMPurify.sanitize(htmlString);
                setHtml(cleanHtml);
            } catch (e) {
                console.error(e);
                setError("Failed to parse Excel file.");
            } finally {
                setLoading(false);
            }
        };
        load();
    }, [file]);

    if (loading) return <div className="flex justify-center items-center h-full"><Loader2 className="w-8 h-8 animate-spin text-purple-500" /></div>;
    if (error) return <div className="flex justify-center items-center h-full text-red-400">{error}</div>;

    return (
        <div className="h-full w-full bg-white rounded-xl overflow-auto p-4 custom-scrollbar text-black">
            <style>{`
                #excel-preview-table { width: 100%; border-collapse: collapse; font-family: sans-serif; font-size: 14px; }
                #excel-preview-table td, #excel-preview-table th { border: 1px solid #ddd; padding: 4px 8px; white-space: nowrap; }
                #excel-preview-table tr:nth-child(even) { bg-color: #f9f9f9; }
                #excel-preview-table tr:hover { background-color: #f1f1f1; }
            `}</style>
            <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html || '') }} />
        </div>
    );
};

export default ExcelPreview;
