import * as crypto from 'crypto'
import { describe, it } from 'mocha'
import { expect } from 'chai'
import { b64u_dec, b64u_enc, le64, needs, PAE, u8_concat, u8_equal} from '../lib/util.js'

const b64u_mapping = [
    ['', new Uint8Array([])],
    ['QQ', new Uint8Array([0x41])],
    ['QUI', new Uint8Array([0x41, 0x42])],
    ['QUJD', new Uint8Array([0x41, 0x42, 0x43])],
    ['QUJDRA', new Uint8Array([0x41, 0x42, 0x43, 0x44])],
    ['QUJDREU', new Uint8Array([0x41, 0x42, 0x43, 0x44, 0x45])]
]

const le64_mapping = [
    [0, new Uint8Array(8)],
    [1, new Uint8Array([1,0,0,0,0,0,0,0])],
    [255, new Uint8Array([255,0,0,0,0,0,0,0])],
    [256, new Uint8Array([0,1,0,0,0,0,0,0])],
    [65535, new Uint8Array([255,255,0,0,0,0,0,0])],
    [65537, new Uint8Array([1,0,1,0,0,0,0,0])],
    [Number.MAX_SAFE_INTEGER, new Uint8Array([255,255,255,255,255,255,31,0])],
]

const pae_mapping = [
    [[], new Uint8Array(8)],
    [[''], new Uint8Array([1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0])],
    [['abc'], new Uint8Array([1,0,0,0,0,0,0,0, 3,0,0,0,0,0,0,0, 0x61,0x62,0x63])],
]

describe('PASETO Utility Test', () => {
    it('base64url decode', async function() {
        for (let map of b64u_mapping) {
            let decoded = b64u_dec(map[0], true)
            expect(crypto.timingSafeEqual(decoded, map[1])).to.be.equal(true)
        }
    })

    it('base64url encode', async function() {
        for (let map of b64u_mapping) {
            expect(map[0]).to.be.equal(b64u_enc(map[1]))
        }
    })

    it('le64', function () {
        for (let map of le64_mapping) {
            let packed = le64(map[0])
            expect(crypto.timingSafeEqual(packed, map[1])).to.be.equal(true)
        }
    })

    it('needs', function() {
        expect(() => {needs(true)}).to.not.throw()
        expect(() => {needs(false)}).to.throw()
    })

    it('PAE', function () {
        for (let map of pae_mapping) {
            let out = PAE(...map[0])
            expect(crypto.timingSafeEqual(out, map[1])).to.be.equal(true)
        }
    })

    it('u8_concat', function () {
        const a = Uint8Array.from([0x61, 0x62])
        const b = Uint8Array.from([0x63, 0x64, 0x65])
        const c = Uint8Array.from([0x41, 0x42, 0x43])
        const vec = Uint8Array.from([0x61, 0x62, 0x63, 0x64, 0x65, 0x41, 0x42, 0x43])

        const out = u8_concat(a, b, c)
        expect(u8_equal(vec, out)).to.be.equal(true)
    })
})
