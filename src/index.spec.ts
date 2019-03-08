import { decrypt, decryptWithKey, encrypt, encryptWithKey } from "./index";

const keys = [
    'b2516e6575e34b7e36799dea394b22af',
    'a5fb4928cd36002482e28284821ae9fe',
    '040c00a26db822f568d8a6003e337e96',
].map((item) => {
    return Buffer.from(item);
});

describe('simple-encryption', () => {
    test('encrypted values do not produce the same result', () => {
        const test = encryptWithKey(keys[0], 'test');
        const test2 = encryptWithKey(keys[0], 'test');

        // Ascertain unique
        expect(test2).not.toEqual(test);
    });

    test('invalid aad fails', () => {
        expect(() => {
            const ciphertext = encryptWithKey(keys[0], 'test', 'aad');

            decryptWithKey(keys[0], ciphertext, 'nope');
        }).toThrow();
    });

    test('valid aad succeeds', () => {
        const ciphertext = encryptWithKey(keys[0], 'test', 'aad');

        expect(decryptWithKey(keys[0], ciphertext, 'aad')).toEqual('test');
    });

    test('encryption with multiple keys uses first key', () => {
        const ciphertext = encrypt(keys, 'test');

        expect(decryptWithKey(keys[0], ciphertext)).toEqual('test');

        expect(() => {
            decryptWithKey(keys[1], ciphertext)
        }).toThrow();
    });

    test('decryption works with older keys', () => {
        const ciphertext = encryptWithKey(keys[1], 'test');

        expect(decrypt(keys, ciphertext)).toEqual('test');
    });

    test('decryption fails with different key', () => {
        const ciphertext = encryptWithKey(keys[2], 'test');
        const otherCiphertext = encryptWithKey(Buffer.from('06d4e3d7143810cc847db20153e3e090'), 'test');

        expect(() => {
            decryptWithKey(keys[1], ciphertext);
        }).toThrow();

        expect(() => {
            decrypt(keys, otherCiphertext);
        }).toThrow();
    });
});