export interface UploadItem {
    file: File | null;
    path: string;
    name: string;
    id: string;
    isDirectory: boolean;
    size: number;
    uploadProgress?: number;
    uploading?: boolean;
    cancelled?: boolean;
}

export interface FileSystemHandle {
    kind: 'file' | 'directory';
    name: string;
}

export interface FileSystemFileHandle extends FileSystemHandle {
    kind: 'file';
    getFile(): Promise<File>;
}

export interface FileSystemDirectoryHandle extends FileSystemHandle {
    kind: 'directory';
    values(): AsyncIterableIterator<FileSystemHandle>;
}
