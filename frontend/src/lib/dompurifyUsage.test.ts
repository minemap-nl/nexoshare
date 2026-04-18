import { describe, expect, it } from 'vitest';
import DOMPurify from 'dompurify';

describe('DOMPurify (dependency smoke)', () => {
    it('removes inline handlers from markup', () => {
        const dirty = '<img src=x onerror=alert(1)><p>ok</p>';
        const clean = DOMPurify.sanitize(dirty);
        expect(clean.toLowerCase()).not.toContain('onerror');
        expect(clean).toContain('ok');
    });

    it('sanitizes a string suitable for download filename prefix', () => {
        const raw = 'My<script>App</script>';
        const clean = DOMPurify.sanitize(raw);
        expect(clean.toLowerCase()).not.toContain('script');
    });
});
