import * as nacl from 'tweetnacl'
import { PasetoV4Local } from "./paseto.v4.local.js"
import { blake2b } from './blakejs/blake2b.js'
import { ietfStreamXorIc as xchacha20 } from './xchacha.js'
import { b64u_dec, b64u_enc, needs, to_u8, u8_concat, u8_equal } from './util.js'
import { convertPublicKey, convertSecretKey } from './ed2curve.js'

const K4_SEAL = 'k4.seal.'
const encoder = new TextEncoder()
const K4_SEAL_U8 = encoder.encode(K4_SEAL)

const PREFIX_ENCRYPT = new Uint8Array([0x01])
const PREFIX_AUTH = new Uint8Array([0x02])

export class PaserkK4Seal
{
    constructor(xpk, xsk = null) {
        needs(xpk instanceof Uint8Array, "Input must be a Uint8Array")
        needs(xpk.length === 32, "Public Key must be 32 bytes")
        this.xpk = xpk
        if (xsk) {
            needs(xsk instanceof Uint8Array, "Input must be a Uint8Array")
            needs(xsk.length === 32, "Secret Key must be 64 bytes")
            this.xsk = xsk
        } else {
            this.xsk = null
        }
    }

    /**
     *
     * @param {PasetoV4Public} v4pub
     * @returns {PaserkK4Seal}
     */
    static fromV4Public(v4pub) {
        return PaserkK4Seal.fromEdwardsKeys(v4pub.pk, v4pub.sk)
    }

    /**
     *
     * @param {Uint8Array} pk
     * @param {Uint8Array} sk
     * @returns {PaserkK4Seal}
     */
    static fromEdwardsKeys(pk, sk = null) {
        needs(pk instanceof Uint8Array, "Input must be a Uint8Array")
        needs(pk.length === 32, "Public Key must be 32 bytes")
        const xpk = convertPublicKey(pk)
        if (sk) {
            needs(sk instanceof Uint8Array, "Input must be a Uint8Array")
            needs(sk.length === 64, "Secret Key must be 64 bytes")
            return new PaserkK4Seal(xpk, convertSecretKey(sk))
        }
        return new PaserkK4Seal(xpk, null)
    }

    /**
     * @returns {PaserkK4Seal}
     */
    static generate() {
        const kp = nacl.default.sign.keyPair()
        return PaserkK4Seal.fromEdwardsKeys(kp.publicKey, kp.secretKey)
    }

    /**
     *
     * @param {PasetoV4Local} v4local
     * @returns {Promise<string>}
     */
    async wrap(v4local) {
        const ephemeral = nacl.default.box.keyPair()
        const epk = ephemeral.publicKey.slice()
        const xk = nacl.default.scalarMult(ephemeral.secretKey, this.xpk)

        const Ek = blake2b(
            u8_concat(PREFIX_ENCRYPT, K4_SEAL_U8, xk, epk, this.xpk),
            null,
            32
        )
        const Ak = blake2b(
            u8_concat(PREFIX_AUTH, K4_SEAL_U8, xk, epk, this.xpk),
            null,
            32
        )
        const nonce = blake2b(
            u8_concat(epk, this.xpk),
            null,
            24
        )

        const edk = xchacha20(v4local.getKey(), nonce, Ek, 0)
        const tag = blake2b(
            u8_concat(K4_SEAL_U8, epk, edk),
            Ak,
            32
        )
        return K4_SEAL + b64u_enc(u8_concat(tag, epk, edk))
    }

    /**
     *
     * @param {string} paserk
     * @returns {Promise<PasetoV4Local>}
     */
    async unwrap(paserk) {
        needs(this.xsk, 'Cannot unwrap: No secret key was provided')

        const {tag, epk, edk} = await this.decompose(paserk)
        const xk = nacl.default.scalarMult(this.xsk, epk)

        const Ak = blake2b(
            u8_concat(PREFIX_AUTH, K4_SEAL_U8, xk, epk, this.xpk),
            null,
            32
        )
        const t2 = blake2b(
            u8_concat(K4_SEAL_U8, epk, edk),
            Ak,
            32
        )
        needs(u8_equal(tag, t2), 'Invalid auth tag')

        const nonce = blake2b(
            u8_concat(epk, this.xpk),
            null,
            24
        )
        const Ek = blake2b(
            u8_concat(PREFIX_ENCRYPT, K4_SEAL_U8, xk, epk, this.xpk),
            null,
            32
        )

        return new PasetoV4Local(xchacha20(edk, nonce, Ek, 0))
    }

    /**
     * @param {string} token
     * @returns {Promise<{epk: Uint8Array, tag: Uint8Array, edk: Uint8Array}>}
     */
    async decompose(token) {
        const header = to_u8(token.slice(0, 8))
        needs(u8_equal(header, K4_SEAL_U8), 'Invalid token')
        const tokenPieces = token.split('.')
        needs(tokenPieces.length === 3, 'Invalid token')
        const decoded = b64u_dec(tokenPieces[2], true)
        needs(decoded.length === 96, 'Invalid payload length')
        return {
            tag: decoded.slice(0, 32),
            epk: decoded.slice(32, 64),
            edk: decoded.slice(64)
        }
    }
}

if (typeof window !== 'undefined') {
    window.PaserkK4Seal = PaserkK4Seal
}
