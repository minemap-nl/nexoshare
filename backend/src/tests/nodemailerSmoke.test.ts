import { describe, expect, test } from 'bun:test';
import nodemailer from 'nodemailer';

describe('nodemailer (dependency smoke)', () => {
    test('sendMail works with jsonTransport (no network)', async () => {
        const transporter = nodemailer.createTransport({ jsonTransport: true });
        const info = await transporter.sendMail({
            from: '"Test" <from@example.com>',
            to: 'to@example.com',
            subject: 'Subject',
            text: 'Body',
        });
        expect(info).toBeDefined();
    });
});
