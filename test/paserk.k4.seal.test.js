import { PasetoV4Local } from '../lib/paseto.v4.local.js'
import { PaserkK4Seal } from '../lib/paserk.k4.seal.js'
import * as nacl from 'tweetnacl'
import { describe, it } from 'mocha'
import { expect } from 'chai'
import {hex_to_u8, u8_equal, u8_to_hex} from '../lib/util.js'
import * as fs from 'fs'
import * as path from 'path'

let base = path.dirname(import.meta.url)
if (base.slice(0,8) === 'file:///') {
    base = base.slice(8).replace(/\//g, '\\')
}

describe('PASERK k4.seal Test', () => {
    it('constructor', async function () {
        const keypair = nacl.default.box.keyPair()
        const paserk = new PaserkK4Seal(keypair.publicKey, keypair.secretKey)

        expect(paserk.xpk.length).to.be.equal(32)
        expect(paserk.xsk.length).to.be.equal(32)
    })

    it('fromEdwardsKeys', async function () {
        const keypair = nacl.default.sign.keyPair()
        const paserk = PaserkK4Seal.fromEdwardsKeys(keypair.publicKey, keypair.secretKey)

        expect(paserk.xpk.length).to.be.equal(32)
        expect(paserk.xsk.length).to.be.equal(32)
    })

    it('wrap/unwrap', async function () {
        const keypair = nacl.default.box.keyPair()
        const k4seal = new PaserkK4Seal(keypair.publicKey, keypair.secretKey)

        const paseto = PasetoV4Local.generate()
        const paserk = await k4seal.wrap(paseto)
        const unwrap = await k4seal.unwrap(paserk)

        expect(u8_equal(unwrap.getKey(), paseto.getKey())).to.be.equal(true)
    })

    it('test vectors', async function () {
        const decoder = new TextDecoder()
        const testVectorFile = await fs.promises.readFile(
            path.join(base, 'test-vectors', 'v4.json')
        )
        const testVectors = JSON.parse(decoder.decode(testVectorFile))
        for (let test of testVectors.tests) {
            if (typeof test['sealing-public-key'] === 'undefined') {
                continue
            }
            let failed = false
            try {
                let handler = new PaserkK4Seal(
                    hex_to_u8(test['sealing-public-key']),
                    hex_to_u8(test['sealing-secret-key'])
                )
                let parsed = await handler.unwrap(test['paserk'])
                expect(u8_to_hex(parsed)).to.be.equal(test['unsealed'])
                if (test['expect-fail'])
                    console.log(test.name + ' was expected to fail but did not')
            } catch (e) {
                failed = true
                if (!test['expect-fail']) {
                    console.log("This was not expected to fail, but did: ")
                    console.error(e)
                }
            }
            expect(test['expect-fail']).to.be.equal(failed, test.name + ' expect fail')
        }
    })
})
