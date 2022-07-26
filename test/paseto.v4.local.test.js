import * as crypto from 'crypto'
import { describe, it } from 'mocha'
import { expect } from 'chai'
import { PasetoV4Local } from "../lib/paseto.v4.local.js"
import * as fs from 'fs'
import * as path from 'path'
import { hex_to_u8, u8_to_hex } from '../lib/util.js'

let base = path.dirname(import.meta.url)
if (base.slice(0,8) === 'file:///') {
    if (process.platform === "win32") {
        base = base.slice(8).replace(/\//g, '\\')
    } else {
        base = base.slice(7)
    }
}

const random = crypto.randomBytes(32)

describe('PASETO v4.local Test', () => {
    it('constructor success', async function() {
        const v4local = new PasetoV4Local(random)
        expect(v4local instanceof PasetoV4Local).to.be.equal(true)
        expect(v4local.bytes).to.be.equal(random)
    })

    it('encode()', async function() {
        const v4local = PasetoV4Local.generate()
        const encoded = await v4local.encode({'exp': '2039-12-31T00:00:00+00:00'})
        const decoded = await v4local.decode(encoded)
        expect(decoded.exp).to.be.equal('2039-12-31T00:00:00+00:00')
    })


    it('test vectors', async function () {
        const decoder = new TextDecoder()
        const testVectorFile = await fs.promises.readFile(
            path.join(base, 'test-vectors', 'v4.json')
        )
        const testVectors = JSON.parse(decoder.decode(testVectorFile))
        for (let test of testVectors.tests) {
            if (typeof test['key'] === 'undefined') {
                continue
            }
            let failed = false
            try {
                let handler = new PasetoV4Local(
                    hex_to_u8(test['key'])
                )
                let parsed = await handler.decode(
                    test['token'],
                    test['implicit-assertion'] || ''
                )
                if (typeof parsed === 'object') {
                    let payload = JSON.parse(test.payload)
                    for (let k in parsed) {
                        expect(parsed[k]).to.be.equal(payload[k])
                    }
                }
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
