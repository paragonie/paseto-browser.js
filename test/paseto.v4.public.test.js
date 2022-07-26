import { describe, it } from 'mocha'
import { expect } from 'chai'
import { PasetoV4Public } from '../lib/paseto.v4.public.js'
import {hex_to_u8, u8_to_hex} from '../lib/util.js'
import * as fs from 'fs'
import * as path from 'path'

let base = path.dirname(import.meta.url)
if (base.slice(0,8) === 'file:///') {
    base = base.slice(8).replace(/\//g, '\\')
}

describe('PASETO v4.public Test', () => {
    it('constructor success', async function() {
        const v4public = PasetoV4Public.generate()
        expect(v4public instanceof PasetoV4Public).to.be.equal(true)
    })

    it('encode()', async function() {
        const v4public = PasetoV4Public.generate()
        const encoded = await v4public.encode({'exp': '2039-12-31T00:00:00+00:00'})
        const decoded = await v4public.decode(encoded)
        expect(decoded.exp).to.be.equal('2039-12-31T00:00:00+00:00')
    })

    it('test vectors', async function () {
        const decoder = new TextDecoder()
        const testVectorFile = await fs.promises.readFile(
            path.join(base, 'test-vectors', 'v4.json')
        )
        const testVectors = JSON.parse(decoder.decode(testVectorFile))
        for (let test of testVectors.tests) {
            if (typeof test['public-key'] === 'undefined') {
                continue
            }
            let failed = false
            try {
                let handler = new PasetoV4Public(
                    hex_to_u8(test['public-key']),
                    hex_to_u8(test['secret-key'])
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
