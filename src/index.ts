import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'crypto';

/**
 * Encrypt the given plaintext, with the given key.
 *
 * @param key
 * @param plaintext
 * @param aad
 */
export function encryptWithKey(key: Buffer, plaintext: string, aad?: string): string {
    // AES requires 16 bytes of cryptographically secure random data.
    const iv = randomBytes(16);

    // Create the cipher function with the above IV.
    const cipher = createCipheriv('aes-256-gcm', key, iv);

    if (aad) {
        cipher.setAAD(Buffer.from(aad));
    }

    // Update the cipher with the string to encrypt
    let value = cipher.update(plaintext);
    value = Buffer.concat([value, cipher.final()]);

    // This next part is for Authenticated Encryption following Encrypt-then-MAC (EtM).
    // @see https://en.wikipedia.org/wiki/Authenticated_encryption#Encrypt-then-MAC_(EtM)
    //
    // For this part we generate a hmac for the IV, Encrypted Value, and the Auth Tag.
    const mac = createHmac('sha256', key)
        .update(Buffer.concat([iv, value, cipher.getAuthTag()]))
        .digest();

    // Finally we wrap this in a JSON object for easy deserialization.
    const json = JSON.stringify({
        iv: iv.toString('base64'),
        authTag: cipher.getAuthTag().toString('base64'),
        value: value.toString('base64'),
        mac: mac.toString('hex'),
    });

    // Then return that json string in base64 form. (Not for any additional security, more to indicate that this isn't intended to be modified or read)
    return Buffer.from(json).toString('base64');
}

/**
 * Encrypts data using the first key in the given list of keys
 *
 * @param keys
 * @param plaintext
 * @param aad
 */
export function encrypt(
    keys: Buffer[],
    plaintext: string,
    aad?: string,
): string {
    return encryptWithKey(keys[0], plaintext, aad);
}

/**
 * Decrypt the given ciphertext, with the given key.
 *
 * @param key
 * @param ciphertext
 * @param aad
 */
export function decryptWithKey(key: Buffer, ciphertext: string, aad?: string): string {
    // Decrypt the json object
    const json = JSON.parse(Buffer.from(ciphertext, 'base64').toString());

    // Get the IV, EncryptedValue, and AuthTag
    const iv = Buffer.from(json.iv, 'base64');
    const encryptedValue = Buffer.from(json.value, 'base64');
    const authTag = Buffer.from(json.authTag, 'base64');

    // Generate the HMAC
    // @see encrypt
    const mac = createHmac('sha256', key)
        .update(Buffer.concat([iv, encryptedValue, authTag]))
        .digest();

    // Ensure the generated mac matches the provided one.
    if (mac.toString('hex') !== json.mac) {
        throw new Error("Error: Generated mac doesn't match the given mac");
    }

    // Start decryption, and set the auth tag given.
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    if (aad) {
        decipher.setAAD(Buffer.from(aad));
    }

    let value = decipher.update(encryptedValue);
    value = Buffer.concat([value, decipher.final()]);

    // Finally return the value and everyone is happy :)
    return value.toString();
}

/**
 * Attempt to decrypt from the given set of keys
 *
 * @param keys
 * @param ciphertext
 * @param aad
 */
export function decrypt(
    keys: Buffer[],
    ciphertext: string,
    aad?: string,
): string {
    let value = '';
    let firstError = '';

    keys.forEach((key) => {
        if (value) {
            return;
        }

        try {
            value = decryptWithKey(key, ciphertext, aad);
        } catch (e) {
            if (!firstError) {
                firstError = e;
            }

            // ignore otherwise
        }
    });

    if (firstError && ! value) {
        throw firstError;
    }

    return value;
}