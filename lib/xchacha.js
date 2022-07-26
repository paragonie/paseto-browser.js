import { needs, readInt32BE, write32le } from './util.js'
import * as chacha from './chacha.js'

function hchachaCtx(key, nonce) {
    needs(key.length === 32, 'Invalid key size')
    needs(nonce.length === 16, 'Invalid nonce length')
    return (new Uint8Array([
        0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
        0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b,
    ].concat([...key, ...nonce])))
}

/**
 * @param {Uint8Array} nonce
 * @param {Uint8Array} key
 * @returns {Uint8Array}
 */
export function hchacha20(nonce, key) {
    const ctx = hchachaCtx(key, nonce)
    let x0 = readInt32BE(ctx, 0)
    let x1 = readInt32BE(ctx, 1 << 2)
    let x2 = readInt32BE(ctx, 2 << 2)
    let x3 = readInt32BE(ctx, 3 << 2)
    let x4 = readInt32BE(ctx, 4 << 2)
    let x5 = readInt32BE(ctx, 5 << 2)
    let x6 = readInt32BE(ctx, 6 << 2)
    let x7 = readInt32BE(ctx, 7 << 2)
    let x8 = readInt32BE(ctx, 8 << 2)
    let x9 = readInt32BE(ctx, 9 << 2)
    let x10 = readInt32BE(ctx, 10 << 2)
    let x11 = readInt32BE(ctx, 11 << 2)
    let x12 = readInt32BE(ctx, 12 << 2)
    let x13 = readInt32BE(ctx, 13 << 2)
    let x14 = readInt32BE(ctx, 14 << 2)
    let x15 = readInt32BE(ctx, 15 << 2)

    for (let i = 0; i < 10; i++) {
        [x0, x4, x8, x12] = chacha.quarterRound(x0, x4, x8, x12);
        [x1, x5, x9, x13] = chacha.quarterRound(x1, x5, x9, x13);
        [x2, x6, x10, x14] = chacha.quarterRound(x2, x6, x10, x14);
        [x3, x7, x11, x15] = chacha.quarterRound(x3, x7, x11, x15);

        [x0, x5, x10, x15] = chacha.quarterRound(x0, x5, x10, x15);
        [x1, x6, x11, x12] = chacha.quarterRound(x1, x6, x11, x12);
        [x2, x7, x8, x13] = chacha.quarterRound(x2, x7, x8, x13);
        [x3, x4, x9, x14] = chacha.quarterRound(x3, x4, x9, x14);
    }

    const out = new Uint8Array(32)
    write32le(out, x0, 0)
    write32le(out, x1, 1 << 2)
    write32le(out, x2, 2 << 2)
    write32le(out, x3, 3 << 2)
    write32le(out, x12, 4 << 2)
    write32le(out, x13, 5 << 2)
    write32le(out, x14, 6 << 2)
    write32le(out, x15, 7 << 2)
    return out
}

/**
 *
 * @param {number} length
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @returns {Uint8Array}
 */
export function stream(length, key, nonce, counter = 1) {
    let outnonce = new nonce.slice(16, 24)
    return chacha.stream(
        length,
        outnonce,
        hchacha20(nonce.slice(0, 16), key),
        counter
    )
}

/**
 *
 * @param {Uint8Array} message
 * @param {Uint8Array} nonce
 * @param {Uint8Array} key
 * @param {number} counter
 * @returns {Uint8Array}
 */
export function streamXorIc(message, nonce, key, counter = 1) {
    needs(key.length === 32, 'Key must be 32 bytes')
    needs(nonce.length === 24, 'Nonce must be 32 bytes')
    let outnonce = new nonce.slice(16, 24)
    return chacha.streamXorIc(
        message,
        outnonce,
        hchacha20(nonce.slice(0, 16), key),
        counter
    )
}

/**
 *
 * @param {number} length
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @returns {Uint8Array}
 */
export function ietfStream(length, key, nonce, counter = 1) {
    let outnonce = new Uint8Array(12)
    outnonce.set(nonce.slice(16, 24), 0)
    return chacha.ietfStream(
        length,
        outnonce,
        hchacha20(nonce.slice(0, 16), key),
        counter
    )
}

/**
 *
 * @param {Uint8Array} message
 * @param {Uint8Array} nonce
 * @param {Uint8Array} key
 * @param {number} counter
 * @returns {Uint8Array}
 */
export function ietfStreamXorIc(message, nonce, key, counter = 1) {
    needs(key.length === 32, `Key must be 32 bytes; ${key.length} provided`)
    needs(nonce.length === 24, 'Nonce must be 24 bytes')
    const outnonce = new Uint8Array(12)
    outnonce.set(nonce.slice(16, 24), 4)
    return chacha.ietfStreamXorIc(
        message,
        outnonce,
        hchacha20(nonce.slice(0, 16), key),
        counter
    )
}

export function encrypt(message, nonce, key, counter = 1) {
    return ietfStreamXorIc(message, nonce, key, counter)
}

export function decrypt(message, nonce, key, counter = 1) {
    return ietfStreamXorIc(message, nonce, key, counter)
}
