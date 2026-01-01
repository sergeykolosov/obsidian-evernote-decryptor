import * as forge from 'node-forge';
import { crc32 } from 'crc';
import { createHash } from 'crypto';
import { RC2_EFFECTIVE_KEY_BITS } from '../constants/crypto';

export interface DecryptRC2Result {
    text: string;  // plaintext
    crcOk: boolean;
    crcExpected: string;  // 4 hex chars
    crcActual: string;  // 4 hex chars
}

export function decryptRC2(ciphertext: string, passphrase: string): DecryptRC2Result {
    // from base64 to binary string
    const encrypted = atob(ciphertext.trim());
    
    // md5 of passphrase as binary string
    const md5Buffer = createHash('md5').update(passphrase, 'utf8').digest();
    const key = String.fromCharCode(...md5Buffer);
    
    // decrypt
    const rc2 = forge.rc2.createDecryptionCipher(key, RC2_EFFECTIVE_KEY_BITS);
    rc2.start(null);  // IV is null for ECB mode
    rc2.update(forge.util.createBuffer(encrypted, 'raw'));
    const success = rc2.finish((blockSize: number, buffer: any, decrypt: boolean) => buffer);
    if (!success) {
        throw new Error('RC2 decryption failed');
    }
    const decrypted = rc2.output.getBytes();
    
    // validate CRC32
    if (decrypted.length < 4) {
        throw new Error('Decrypted text too short (no CRC header)');
    }

    const crcHeader = decrypted.substring(0, 4);
    const body = decrypted.substring(4);

    let expectedCrc: number;
    try {
        expectedCrc = parseInt(crcHeader, 16);
    } catch (err) {
        throw new Error(`Invalid CRC header: ${crcHeader}`);
    }

    const bodyBuffer = Buffer.from(body, 'binary');
    const crc32Value = crc32(bodyBuffer);

    // use upper 16 bits of CRC32
    const crcHi = (crc32Value >>> 16) & 0xFFFF;
    const crcHiXor = (((crc32Value ^ 0xFFFFFFFF) >>> 0) >>> 16) & 0xFFFF;
    
    const crcOk = expectedCrc === crcHi || expectedCrc === crcHiXor;
    const crcActual = crcHi.toString(16).padStart(4, '0').toUpperCase();
    
    return {
        text: body,
        crcOk,
        crcExpected: crcHeader.toUpperCase(),
        crcActual
    };
}
