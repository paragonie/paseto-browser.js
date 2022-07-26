import * as nacl from 'tweetnacl'
import { b64u_dec, b64u_enc, from_u8, needs, PAE, to_u8, u8_concat, u8_equal } from './util.js'

const V4_PUBLIC = 'v4.public.'
const V4_PUBLIC_U8 = new TextEncoder().encode(V4_PUBLIC)

export class PasetoV4Public {
    constructor(pk, sk = null) {
        needs(pk instanceof Uint8Array, "Input must be a Uint8Array")
        needs(pk.length === 32, "Public Key must be 32 bytes")
        this.pk = pk
        if (sk) {
            needs(sk instanceof Uint8Array, "Input must be a Uint8Array")
            needs(sk.length === 64, "Secret Key must be 64 bytes")
            this.sk = sk
        } else {
            this.sk = null
        }
    }

    /**
     * @returns {Uint8Array}
     */
    getSecretKey() {
        return this.sk
    }

    /**
     * @returns {Uint8Array}
     */
    getPublicKey() {
        return this.pk
    }

    /**
     * @returns {PasetoV4Public}
     */
    static generate() {
        const keypair = nacl.default.sign.keyPair()
        return new PasetoV4Public(keypair.publicKey, keypair.secretKey)
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
     *
     * @param {string} token
     * @param {string} implicit
     * @returns {Promise<object>}
     */
    async decode(token, implicit = '') {
        return JSON.parse(await this.verify(token, implicit))
    }

    /**
     *
     * @param {string|object} claims
     * @param {string|object} footer
     * @param {string} implicit
     * @returns {Promise<string>}
     */
    async encode(claims, footer = '', implicit = '') {
        needs(this.sk, 'Cannot sign: No secret key was provided')
        if (typeof footer === 'object') {
            footer = JSON.stringify(footer)
        }
        if (typeof footer === 'string') {
            footer = to_u8(footer)
        }
        return this.sign(JSON.stringify(claims), footer, implicit)
    }

    /**
     *
     * @param {string|Uint8Array} message
     * @param {string} footer
     * @param {string} implicit
     * @returns {Promise<string>}
     */
    async sign(message, footer = '', implicit = '') {
        needs(this.sk, 'Cannot sign: No secret key was provided')

        const msg_u8 = to_u8(message)

        const m2 = PAE(
            V4_PUBLIC_U8,
            msg_u8,
            to_u8(footer),
            to_u8(implicit)
        )
        const sig = nacl.default.sign.detached(m2, this.sk)
        const payload = b64u_enc(u8_concat(msg_u8, sig))
        if (footer.length > 0) {
            return [V4_PUBLIC.slice(0, 9), payload, b64u_enc(footer)].join('.')
        }
        return [V4_PUBLIC.slice(0, 9), payload].join('.')
    }

    /**
     *
     * @param {string} token
     * @param {string} implicit
     * @returns {Promise<string>}
     */
    async verify(token, implicit = '') {
        const {msg, sig, footer} = await this.decompose(token)
        const m2 = PAE(
            V4_PUBLIC_U8,
            msg,
            to_u8(footer),
            to_u8(implicit)
        )
        needs(nacl.default.sign.detached.verify(m2, sig, this.pk), 'Invalid signature')
        return (new TextDecoder()).decode(msg)
    }

    /**
     * @param {string} token
     * @returns {Promise<{epk: Uint8Array, tag: Uint8Array, edk: Uint8Array, footer: Uint8Array}>}
     */
    async decompose(token) {
        const header = to_u8(token.slice(0, 10))
        needs(u8_equal(header, V4_PUBLIC_U8), 'Invalid token')
        const tokenPieces = token.split('.')
        const payload = b64u_dec(tokenPieces[2], true)
        const l = payload.length
        return {
            msg: payload.slice(0, l - 64),
            sig: payload.slice(l - 64),
            footer: tokenPieces.length > 3
                ? b64u_dec(tokenPieces[3])
                : new Uint8Array(0)
        }
    }
}

if (typeof window !== 'undefined') {
    window.PasetoV4Public = PasetoV4Public
}
