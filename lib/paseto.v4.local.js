import { blake2bInit, blake2bUpdate, blake2bFinal } from './blakejs/blake2b.js'
import { ietfStreamXorIc as xchacha20 } from './xchacha.js'
import { b64u_dec, b64u_enc, from_u8, needs, PAE, random_bytes, to_u8, u8_concat, u8_equal } from './util.js'

const V4_LOCAL = 'v4.local.'

const encoder = new TextEncoder()
const V4_LOCAL_U8 = encoder.encode(V4_LOCAL)
const PASETO_V4_ENC_KEY = encoder.encode('paseto-encryption-key')
const PASETO_V4_AUTH_KEY = encoder.encode('paseto-auth-key-for-aead')

export class PasetoV4Local
{
    constructor(bytes) {
        needs(bytes instanceof Uint8Array, "Input must be a Uint8Array")
        needs(bytes.length === 32, "Key must be 32 bytes")
        this.bytes = bytes
    }

    /**
     * @returns {PasetoV4Local}
     */
    static generate() {
        const random = random_bytes(32)
        return new PasetoV4Local(random)
    }

    /**
     *
     * @param {string} token
     * @param {string} implicit
     * @returns {Promise<object>}
     */
    async decode(token, implicit = '') {
        return JSON.parse(await this.decrypt(token, implicit))
    }

    /**
     *
     * @param {string|object} claims
     * @param {string|object} footer
     * @param {string} implicit
     * @returns {Promise<string>}
     */
    async encode(claims, footer = '', implicit = '') {
        if (typeof footer === 'object') {
            footer = JSON.stringify(footer)
        }
        if (typeof footer === 'string') {
            footer = to_u8(footer)
        }
        return this.encrypt(JSON.stringify(claims), footer, implicit)
    }

    /**
     *
     * @param {string} token
     * @param {Uint8Array} expected
     * @returns {Promise<boolean>}
     */
    async assertFooter(token, expected) {
        const pieces = token.split('.')
        needs(pieces.length === 4, "No footer provided")
        const stored = b64u_dec(pieces[3], expected instanceof Uint8Array)
        return u8_equal(stored, expected)
    }

    /**
     *
     * @param {string} token
     * @param {boolean} as_object
     * @returns {string|Uint8Array|object}
     */
    static getFooter(token, as_object = false) {
        const pieces = token.split('.')
        needs(pieces.length === 4, "No footer provided")
        const stored = b64u_dec(pieces[3], as_object)
        if (as_object) {
            return JSON.parse(from_u8(stored))
        }
        return stored
    }

    /**
     * @returns {Uint8Array}
     */
    getKey() {
        return this.bytes
    }

    /**
     *
     * @param {string} message
     * @param {Uint8Array} footer
     * @param {string} implicit
     * @returns {Promise<string>}
     */
    async encrypt(message, footer = '', implicit = '') {
        const n = random_bytes(32)
        let state

        state = blake2bInit(56, this.bytes)
        blake2bUpdate(state, PASETO_V4_ENC_KEY)
        blake2bUpdate(state, n)
        const tmp = blake2bFinal(state)
        const Ek = tmp.slice(0, 32)
        const n2 = tmp.slice(32)

        state = blake2bInit(32, this.bytes)
        blake2bUpdate(state, PASETO_V4_AUTH_KEY)
        blake2bUpdate(state, n)
        const Ak = blake2bFinal(state)

        const c = await xchacha20(to_u8(message), n2, Ek, 0)

        state = blake2bInit(32, Ak)
        blake2bUpdate(state, PAE(V4_LOCAL_U8, n, c, footer, implicit))
        const t = blake2bFinal(state)

        const payload = b64u_enc(u8_concat(n, c, t))
        if (footer.length > 0) {
            return [V4_LOCAL.slice(0, 8), payload, b64u_enc(footer)].join('.')
        }
        return [V4_LOCAL.slice(0, 8), payload].join('.')
    }

    /**
     *
     * @param {string} token
     * @param {string} implicit
     * @returns {Promise<string>}
     */
    async decrypt(token, implicit = '') {
        const {n, c, t, footer} = await this.decompose(token)
        let state

        state = blake2bInit(56, this.bytes)
        blake2bUpdate(state, PASETO_V4_ENC_KEY)
        blake2bUpdate(state, n)
        const tmp = blake2bFinal(state)
        const Ek = tmp.slice(0, 32)
        const n2 = tmp.slice(32)

        state = blake2bInit(32, this.bytes)
        blake2bUpdate(state, PASETO_V4_AUTH_KEY)
        blake2bUpdate(state, n)
        const Ak = blake2bFinal(state)

        state = blake2bInit(32, Ak)
        blake2bUpdate(state, PAE(V4_LOCAL_U8, n, c, footer, implicit))
        const t2 = blake2bFinal(state)

        needs(u8_equal(t, t2), 'Invalid tag')
        const pt = await xchacha20(c, n2, Ek, 0)
        return (new TextDecoder()).decode(pt)
    }

    /**
     * @param {string} token
     * @returns {Promise<{epk: Uint8Array, tag: Uint8Array, edk: Uint8Array, footer: Uint8Array}>}
     */
    async decompose(token) {
        const header = to_u8(token.slice(0, 9))
        needs(u8_equal(header, V4_LOCAL_U8), 'Invalid token')
        const tokenPieces = token.split('.')
        const payload = b64u_dec(tokenPieces[2], true)
        const l = payload.length
        return {
            n: payload.slice(0, 32),
            c: payload.slice(32, l - 32),
            t: payload.slice(l - 32),
            footer: tokenPieces.length > 3
                ? b64u_dec(tokenPieces[3])
                : new Uint8Array(0)
        }
    }
}

if (typeof window !== 'undefined') {
    window.PasetoV4Local = PasetoV4Local
}
