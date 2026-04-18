import { describe, expect, test } from 'bun:test';
import path from 'path';
import { isPathUnderDir, isResolvedPathInsideDir, safeUploadBaseName } from '../lib/uploadPathPolicy';

describe('uploadPathPolicy', () => {
    const tmp = path.join(process.cwd(), '___test_tmp_policy___');

    test('safeUploadBaseName keeps basename only and rejects empty / dot segments', () => {
        expect(safeUploadBaseName('../../etc/passwd')).toBe('passwd');
        expect(safeUploadBaseName('good.txt')).toBe('good.txt');
        expect(safeUploadBaseName('')).toBeNull();
        expect(safeUploadBaseName('   ')).toBeNull();
        expect(safeUploadBaseName(null)).toBeNull();
        expect(safeUploadBaseName(123 as unknown as string)).toBeNull();
        expect(safeUploadBaseName('.')).toBeNull();
        expect(safeUploadBaseName('..')).toBeNull();
    });

    test('isResolvedPathInsideDir allows only descendants of base', () => {
        const base = path.resolve(tmp, 'base');
        const child = path.join(base, 'file.part');
        const outside = path.resolve(tmp, 'other', 'x');
        expect(isResolvedPathInsideDir(base, child)).toBe(true);
        expect(isResolvedPathInsideDir(base, base)).toBe(true);
        expect(isResolvedPathInsideDir(base, outside)).toBe(false);
    });

    test('isPathUnderDir requires string under root', () => {
        const root = path.resolve(tmp, 't');
        const inside = path.join(root, 'chunk_abc');
        expect(isPathUnderDir(root, inside)).toBe(true);
        expect(isPathUnderDir(root, undefined)).toBe(false);
        expect(isPathUnderDir(root, path.join(root, '..', 'escape'))).toBe(false);
    });
});
