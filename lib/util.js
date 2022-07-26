import {timingSafeEqual, randomBytes} from 'crypto'

const byteToHex = [];
for (let n = 0; n <= 0xff; ++n)
{
    const hexOctet = n.toString(16).padStart(2, "0");
    byteToHex.push(hexOctet);
}

const b64u_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
const b64u_lookup = new Uint8Array(256);
for (let i = 0; i < b64u_chars.length; i++) {
    b64u_lookup[b64u_chars.charCodeAt(i)] = i
}

/**
 *
 * @param {string} base64
 * @param {boolean} as_uint8array
 * @returns {string|Uint8Array}
 */
export function b64u_dec(base64, as_uint8array = false) {
    let bufferLength = base64.length * 0.75,
        len = base64.length, i, p = 0,
        encoded1, encoded2, encoded3, encoded4;

    const bytes = new Uint8Array(bufferLength)
    for (i = 0; i < len; i+=4) {
        encoded1 = b64u_lookup[base64.charCodeAt(i)]
        encoded2 = b64u_lookup[base64.charCodeAt(i+1)]
        encoded3 = b64u_lookup[base64.charCodeAt(i+2)]
        encoded4 = b64u_lookup[base64.charCodeAt(i+3)]

        bytes[p++] = (encoded1 << 2) | (encoded2 >> 4)
        bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2)
        bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63)
    }
    if (as_uint8array) {
        return bytes
    }
    return (new TextDecoder()).decode(bytes)
}

/**
 *
 * @ref https://stackoverflow.com/q/12710001
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function b64u_enc(bytes) {
    let i, len = bytes.length, base64 = "";
    for (i = 0; i < len; i+=3) {
        base64 += b64u_chars[bytes[i] >> 2];
        base64 += b64u_chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        base64 += b64u_chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
        base64 += b64u_chars[bytes[i + 2] & 63];
    }
    if ((len % 3) === 2) {
        return base64.substring(0, base64.length - 1);
    } else if (len % 3 === 1) {
        return base64.substring(0, base64.length - 2);
    }
    return base64
}

/**
 *
 * @param {Uint8Array} mixed
 * @returns {string}
 */
export function from_u8(mixed) {
    if (typeof mixed === 'string') {
        return mixed
    } else if (mixed instanceof Uint8Array) {
        return (new TextDecoder()).decode(mixed)
    }
    throw new Error(`Unsupported type: ${typeof mixed}`)
}

/**
 *
 * @param {string} hexString
 * @returns {Uint8Array}
 */
export function hex_to_u8(hexString) {
    if (hexString.length === 0) {
        return new Uint8Array([])
    }
    if ((hexString.length & 1) === 1) {
        hexString = '0' + hexString
    }
    const buf = new Uint8Array(hexString.length >>> 1)
    for (let i = 0, j = 0; i < hexString.length; i += 2, j++) {
        buf[j] = parseInt(hexString.slice(i, i + 2), 16)
    }
    return buf
}

/**
 *
 * @param {number} num
 * @returns {Uint8Array}
 */
export function le32(num) {
    needs(Number.isSafeInteger(num), 'Number too large for JavaScript to safely process')
    const low =  (num & 0xffffffff)
    const out = new Uint8Array(4)
    out[0] =  low          & 0xff
    out[1] =  (low >>>  8) & 0xff
    out[2] =  (low >>> 16) & 0xff
    out[3] =  (low >>> 24) & 0xff
    return out
}

/**
 *
 * @param {number} num
 * @returns {Uint8Array}
 */
export function le64(num) {
    needs(Number.isSafeInteger(num), 'Number too large for JavaScript to safely process')

    const high = (num / 0x100000000)|0
    const low =  (num & 0x0ffffffff)
    const out = new Uint8Array(8)
    out[0] =  low          & 0xff
    out[1] =  (low >>>  8) & 0xff
    out[2] =  (low >>> 16) & 0xff
    out[3] =  (low >>> 24) & 0xff
    out[4] = high          & 0xff
    out[5] = (high >>>  8) & 0xff
    out[6] = (high >>> 16) & 0xff
    out[7] = (high >>> 24) & 0xff
    return out
}

/**
 *
 * @param {Uint8Array} buf
 * @returns {number}
 */
export function load32le(buf) {
    return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24)
}

/**
 *
 * @param {Uint8Array} ctx
 * @param {number} offset
 * @returns {number}
 */
export function readInt32BE(ctx, offset) {
    return load32le(ctx.slice(offset, offset + 4))
}

/**
 *
 * @param {Uint8Array} output
 * @param {number} num
 * @param {number} start
 * @returns {*}
 */
export function write32le(output, num, start) {
    if (start >= output.length)
        return output;
    output[start    ] = (num         & 0xff)
    if (start + 1 >= output.length)
        return output;
    output[start + 1] = ((num >>>  8) & 0xff)
    if (start + 2 >= output.length)
        return output;
    output[start + 2] = ((num >>> 16) & 0xff)
    if (start + 3 >= output.length)
        return output;
    output[start + 3] = ((num >>> 24) & 0xff)
    return output
}

/**
 *
 * @param {boolean} condition
 * @param {string} message
 */
export function needs(condition, message= 'An unknown error occurred') {
    if (!condition) throw new Error(message)
}

/**
 *
 * @param {Uint8Array|string} pieces
 * @returns {Uint8Array}
 * @constructor
 */
export function PAE(...pieces) {
    let out = le64(pieces.length)
    for (let piece of pieces) {
        let p = to_u8(piece)
        needs(p instanceof Uint8Array, 'Only string and Uint8Array is allowed')
        let len = le64(p.length)
        out = new Uint8Array([ ...out, ...len, ...p ])
    }
    return out
}

/**
 *
 * @param {number }num
 * @returns {Uint8Array}
 */
export function random_bytes(num = 0) {
    const buf = new Uint8Array(num)
    if (typeof window !== 'undefined') {
        if (window.crypto && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(buf)
            return buf
        }
        if (typeof window.msCrypto === 'object' && typeof window.msCrypto.getRandomValues === 'export function') {
            window.msCrypto.getRandomValues(buf)
            return buf
        }
    }
    if (randomBytes) {
        const rand = randomBytes(num)
        buf.set(rand, 0)
        return buf
    }
    throw new Error('No secure random number generator available')
}

/**
 *
 * @param {string|number|Uint8Array} mixed
 * @param {boolean} tolerate_integers
 * @returns {Uint8Array}
 */
export function to_u8(mixed, tolerate_integers = false) {
    if (mixed instanceof Uint8Array) {
        return mixed
    } else if (typeof mixed === 'string') {
        return (new TextEncoder()).encode(mixed)
    } else if (mixed instanceof Number && tolerate_integers) {
        return le64(mixed)
    }
    throw new Error(`Unsupported type: ${typeof mixed}`)
}

/**
 *
 * @param {Uint8Array} arrs
 * @returns {Uint8Array}
 */
export function u8_concat(...arrs) {
    let len = 0
    for (const arr of arrs) {
        if (arr.length)
            len += arr.length
    }
    const u8 = new Uint8Array(len)
    let start = 0
    for (const arr of arrs) {
        u8.set(arr, start)
        start += arr.length
    }
    return u8
}

/**
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function u8_equal(a, b) {
    if (typeof timingSafeEqual === 'undefined') {
        needs(a instanceof Uint8Array, 'Must be Uint8Array')
        needs(b instanceof Uint8Array, 'Must be Uint8Array')
        if (a.length !== b.length) {
            return false
        }
        let d = 0
        for (let i = 0; i < a.length; i++) {
            d |= (a[i] ^ b[i])
        }
        return d === 0
    }
    return timingSafeEqual(to_u8(a), to_u8(b))
}

/**
 *
 * @param {Uint8Array} uint8arr
 * @returns {string}
 */
export function u8_to_hex(uint8arr) {
    const output = []
    for (let i = 0; i < uint8arr.length; i++) {
        output.push(byteToHex[uint8arr[i]])
    }
    return output.join('')
}
