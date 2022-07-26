import { le32, le64, needs, load32le, readInt32BE, write32le } from './util.js'

/**
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
function add(a, b)
{
    return ((a + b) & 0xffffffff) >>> 0;
}

/**
 *
 * @param {number} v
 * @param {number} n
 * @returns {number}
 */
function rotate(v, n)
{
    v &= 0xffffffff;
    n &= 31;
    return (
        (
            (v << n) | (v >>> (32 - n))
        )
    ) >>> 0;
}

/**
 *
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
function xor(a, b)
{
    return ((a ^ b) & 0xffffffff) >>> 0;
}

/**
 *
 * @param {number} a
 * @param {number} b
 * @param {number} c
 * @param {number} d
 * @returns {number[]}
 */
export function quarterRound(a, b, c, d)
{
    // a = PLUS(a,b); d = ROTATE(XOR(d,a),16);
    a = (a + b) & 0xffffffff;
    d = rotate(d ^ a, 16);

    // c = PLUS(c,d); b = ROTATE(XOR(b,c),12);
    c = (c + d) & 0xffffffff;
    b = rotate(b ^ c, 12);

    // a = PLUS(a,b); d = ROTATE(XOR(d,a), 8);
    a = (a + b) & 0xffffffff;
    d = rotate(d ^ a, 8);

    // c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);
    c = (c + d) & 0xffffffff;
    b = rotate(b ^ c, 7);
    return [a >>> 0, b >>> 0, c >>> 0, d >>> 0];
}

/**
 *
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @returns {Uint8Array}
 */
function chachaCtx(key, nonce, counter = 0) {
    needs(key.length === 32, 'Invalid key size')
    needs(nonce.length === 8, 'Invalid nonce length')
    counter = le64(counter)
    return new Uint8Array([
        0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
        0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b,
    ].concat([...key, ...counter, ...nonce]))
}

/**
 *
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @returns {Uint8Array}
 */
function chachaIetfCtx(key, nonce, counter = 0) {
    needs(key.length === 32, 'Invalid key size')
    needs(nonce.length === 12, 'Invalid nonce length')
    counter = le32(counter)
    return new Uint8Array([
        0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
        0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b,
    ].concat([...key, ...counter, ...nonce]))
}

/**
 *
 * @param {Uint8Array} ctx
 * @param {Uint8Array} message
 * @returns {Uint8Array}
 */
export function chacha20(ctx, message)
{
    let j0 = readInt32BE(ctx, 0)
    let j1 = readInt32BE(ctx, 1 << 2)
    let j2 = readInt32BE(ctx, 2 << 2)
    let j3 = readInt32BE(ctx, 3 << 2)
    let j4 = readInt32BE(ctx, 4 << 2)
    let j5 = readInt32BE(ctx, 5 << 2)
    let j6 = readInt32BE(ctx, 6 << 2)
    let j7 = readInt32BE(ctx, 7 << 2)
    let j8 = readInt32BE(ctx, 8 << 2)
    let j9 = readInt32BE(ctx, 9 << 2)
    let j10 = readInt32BE(ctx, 10 << 2)
    let j11 = readInt32BE(ctx, 11 << 2)
    let j12 = readInt32BE(ctx, 12 << 2)
    let j13 = readInt32BE(ctx, 13 << 2)
    let j14 = readInt32BE(ctx, 14 << 2)
    let j15 = readInt32BE(ctx, 15 << 2)

    let x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;

    let start = 0;
    let end;
    let len = message.length;
    let cipher = new Uint8Array(len);
    let chunk = new Uint8Array(64);

    while (start < len) {
        end = start + 64 >= len
            ? len
            : start + 64
        chunk.fill(0, 0)
        let j = 0
        for (let i = start; i < end; i++) {
            chunk[j++] = message[i]
        }

        x0 =   j0;   x1 = j1;   x2 = j2;   x3 = j3;
        x4 =   j4;   x5 = j5;   x6 = j6;   x7 = j7;
        x8 =   j8;   x9 = j9; x10 = j10; x11 = j11;
        x12 = j12; x13 = j13; x14 = j14; x15 = j15;

        for (let i = 0; i < 10; i++) {
            [x0, x4, x8, x12] = quarterRound(x0, x4, x8, x12);
            [x1, x5, x9, x13] = quarterRound(x1, x5, x9, x13);
            [x2, x6, x10, x14] = quarterRound(x2, x6, x10, x14);
            [x3, x7, x11, x15] = quarterRound(x3, x7, x11, x15);

            [x0, x5, x10, x15] = quarterRound(x0, x5, x10, x15);
            [x1, x6, x11, x12] = quarterRound(x1, x6, x11, x12);
            [x2, x7, x8, x13] = quarterRound(x2, x7, x8, x13);
            [x3, x4, x9, x14] = quarterRound(x3, x4, x9, x14)
        }
        x0 = add(x0, j0)
        x1 = add(x1, j1)
        x2 = add(x2, j2)
        x3 = add(x3, j3)
        x4 = add(x4, j4)
        x5 = add(x5, j5)
        x6 = add(x6, j6)
        x7 = add(x7, j7)
        x8 = add(x8, j8)
        x9 = add(x9, j9)
        x10 = add(x10, j10)
        x11 = add(x11, j11)
        x12 = add(x12, j12)
        x13 = add(x13, j13)
        x14 = add(x14, j14)
        x15 = add(x15, j15)

        x0 = xor(x0, load32le(chunk.slice(0, 4)))
        x1 = xor(x1, load32le(chunk.slice(4, 8)))
        x2 = xor(x2, load32le(chunk.slice(8, 12)))
        x3 = xor(x3, load32le(chunk.slice(12, 16)))
        x4 = xor(x4, load32le(chunk.slice(16, 20)))
        x5 = xor(x5, load32le(chunk.slice(20, 24)))
        x6 = xor(x6, load32le(chunk.slice(24, 28)))
        x7 = xor(x7, load32le(chunk.slice(28, 32)))
        x8 = xor(x8, load32le(chunk.slice(32, 36)))
        x9 = xor(x9, load32le(chunk.slice(36, 40)))
        x10 = xor(x10, load32le(chunk.slice(40, 44)))
        x11 = xor(x11, load32le(chunk.slice(44, 48)))
        x12 = xor(x12, load32le(chunk.slice(48, 52)))
        x13 = xor(x13, load32le(chunk.slice(52, 56)))
        x14 = xor(x14, load32le(chunk.slice(56, 60)))
        x15 = xor(x15, load32le(chunk.slice(60, 64)))

        cipher = write32le(cipher, x0, start)
        cipher = write32le(cipher, x1, start + 4)
        cipher = write32le(cipher, x2, start + 8)
        cipher = write32le(cipher, x3, start + 12)
        cipher = write32le(cipher, x4, start + 16)
        cipher = write32le(cipher, x5, start + 20)
        cipher = write32le(cipher, x6, start + 24)
        cipher = write32le(cipher, x7, start + 28)
        cipher = write32le(cipher, x8, start + 32)
        cipher = write32le(cipher, x9, start + 36)
        cipher = write32le(cipher, x10, start + 40)
        cipher = write32le(cipher, x11, start + 44)
        cipher = write32le(cipher, x12, start + 48)
        cipher = write32le(cipher, x13, start + 52)
        cipher = write32le(cipher, x14, start + 56)
        cipher = write32le(cipher, x15, start + 60)

        j12++;
        start += 64;
    }
    return cipher.slice(0, len);
}

/**
 *
 * @param {number} len
 * @param {Uint8Array} nonce
 * @param {Uint8Array} key
 * @param {number} counter
 * @returns {Uint8Array}
 */
export function stream(len, nonce, key, counter = 1) {
    needs(len >= 0, 'Length cannot be negative')
    needs(key.length === 32, `Key must be 32 bytes; ${key.length} provided`)
    needs(nonce.length === 8, 'Nonce must be 8 bytes')
    return chacha20(chachaCtx(key, nonce, counter), new Uint8Array(len))
}

/**
 *
 * @param {Uint8Array} message
 * @param {Uint8Array} nonce
 * @param {Uint8Array} key
 * @param {number} counter
 * @returns {Uint8Array}
 */
export function streamXorIc(message, nonce, key, counter) {
    needs(key.length === 32, `Key must be 32 bytes; ${key.length} provided`)
    needs(nonce.length === 8, 'Nonce must be 8 bytes')
    return chacha20(chachaCtx(key, nonce, counter), message)
}

/**
 *
 * @param {number} len
 * @param {Uint8Array} nonce
 * @param {Uint8Array} key
 * @param {number} counter
 * @returns {Uint8Array}
 */
export function ietfStream(len, nonce, key, counter = 1) {
    needs(len >= 0, 'Length cannot be negative')
    needs(key.length === 32, `Key must be 32 bytes; ${key.length} provided`)
    needs(nonce.length === 12, 'Nonce must be 12 bytes')
    return chacha20(chachaIetfCtx(key, nonce, counter), new Uint8Array(len))
}

/**
 *
 * @param {Uint8Array} message
 * @param {Uint8Array} nonce
 * @param {Uint8Array} key
 * @param {number} counter
 * @returns {Uint8Array}
 */
export function ietfStreamXorIc(message, nonce, key, counter) {
    needs(key.length === 32, `Key must be 32 bytes; ${key.length} provided`)
    needs(nonce.length === 12, 'Nonce must be 12 bytes')
    return chacha20(chachaIetfCtx(key, nonce, counter), message)
}
