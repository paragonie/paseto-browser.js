import { describe, it } from 'mocha'
import { expect } from 'chai'
import { u8_equal, u8_to_hex } from '../lib/util.js'
import * as chacha from '../lib/chacha.js'

describe('ChaCha20', () => {
    it('ietfStream', async function () {
        let key = Uint8Array.from([
            0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        let nonce = Uint8Array.from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])

        const stream = chacha.ietfStream(64, nonce, key, 2)
        expect(
            '72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca' +
            '13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096'
        ).to.be.equal(
            u8_to_hex(stream)
        )
    })

    it('encryptBytes', async function () {
        const pt = (new TextEncoder()).encode(
            'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to'
        )
        const ct = Uint8Array.from([
            0xa3,  0xfb,  0xf0,  0x7d,  0xf3,  0xfa,  0x2f,  0xde,  0x4f,  0x37,  0x6c,  0xa2,  0x3e,  0x82,  0x73,  0x70,
            0x41,  0x60,  0x5d,  0x9f,  0x4f,  0x4f,  0x57,  0xbd,  0x8c,  0xff,  0x2c,  0x1d,  0x4b,  0x79,  0x55,  0xec,
            0x2a,  0x97,  0x94,  0x8b,  0xd3,  0x72,  0x29,  0x15,  0xc8,  0xf3,  0xd3,  0x37,  0xf7,  0xd3,  0x70,  0x05,
            0x0e,  0x9e,  0x96,  0xd6,  0x47,  0xb7,  0xc3,  0x9f,  0x56,  0xe0,  0x31,  0xca,  0x5e,  0xb6,  0x25,  0x0d,
            0x40,  0x42,  0xe0,  0x27,  0x85,  0xec,  0xec,  0xfa,  0x4b,  0x4b,  0xb5,  0xe8,  0xea,  0xd0,  0x44,  0x0e,
            0x20,  0xb6,  0xe8,  0xdb,  0x09,  0xd8,  0x81,  0xa7,  0xc6,  0x13,  0x2f,  0x42,  0x0e,  0x52,  0x79,  0x50,
            0x42,  0xbd,  0xfa,  0x77,  0x73,  0xd8,  0xa9,  0x05,  0x14,  0x47,  0xb3,  0x29,  0x1c,  0xe1,  0x41,  0x1c,
            0x68,  0x04,  0x65,  0x55,  0x2a,  0xa6,  0xc4,  0x05,  0xb7,  0x76,  0x4d,  0x5e,  0x87,  0xbe,  0xa8,  0x5a,
            0xd0,  0x0f,  0x84,  0x49,  0xed,  0x8f,  0x72,  0xd0,  0xd6,  0x62,  0xab,  0x05,  0x26,  0x91,  0xca,  0x66,
            0x42,  0x4b,  0xc8,  0x6d,  0x2d,  0xf8,  0x0e,  0xa4,  0x1f,  0x43,  0xab,  0xf9,  0x37,  0xd3,  0x25,  0x9d,
            0xc4,  0xb2,  0xd0,  0xdf,  0xb4,  0x8a,  0x6c,  0x91,  0x39,  0xdd,  0xd7,  0xf7,  0x69,  0x66,  0xe9,  0x28,
            0xe6,  0x35,  0x55,  0x3b,  0xa7,  0x6c,  0x5c,  0x87,  0x9d,  0x7b,  0x35,  0xd4,  0x9e,  0xb2,  0xe6,  0x2b,
            0x08,  0x71,  0xcd,  0xac,  0x63,  0x89,  0x39,  0xe2,  0x5e,  0x8a,  0x1e,  0x0e,  0xf9,  0xd5,  0x28,  0x0f,
            0xa8,  0xca,  0x32,  0x8b,  0x35,  0x1c,  0x3c,  0x76,  0x59,  0x89,  0xcb,  0xcf,  0x3d,  0xaa,  0x8b,  0x6c,
            0xcc,  0x3a,  0xaf,  0x9f,  0x39,  0x79,  0xc9,  0x2b,  0x37,  0x20,  0xfc,  0x88,  0xdc,  0x95,  0xed,  0x84,
            0xa1,  0xbe,  0x05,  0x9c,  0x64,  0x99,  0xb9,  0xfd,  0xa2,  0x36,  0xe7,  0xe8,  0x18,  0xb0,  0x4b,  0x0b,
            0xc3,  0x9c,  0x1e,  0x87,  0x6b,  0x19,  0x3b,  0xfe,  0x55,  0x69,  0x75,  0x3f,  0x88,  0x12,  0x8c,  0xc0,
            0x8a,  0xaa,  0x9b,  0x63,  0xd1,  0xa1,  0x6f,  0x80,  0xef,  0x25,  0x54,  0xd7,  0x18,  0x9c,  0x41,  0x1f,
            0x58,  0x69,  0xca,  0x52,  0xc5,  0xb8,  0x3f,  0xa3,  0x6f,  0xf2,  0x16,  0xb9,  0xc1,  0xd3,  0x00,  0x62,
            0xbe,  0xbc,  0xfd,  0x2d,  0xc5,  0xbc,  0xe0,  0x91,  0x19,  0x34,  0xfd,  0xa7,  0x9a,  0x86,  0xf6,  0xe6,
            0x98,  0xce,  0xd7,  0x59,  0xc3,  0xff,  0x9b,  0x64,  0x77,  0x33,  0x8f,  0x3d,  0xa4,  0xf9,  0xcd,  0x85,
            0x14,  0xea,  0x99,  0x82,  0xcc,  0xaf,  0xb3,  0x41,  0xb2,  0x38,  0x4d,  0xd9,  0x02,  0xf3,  0xd1,  0xab,
            0x7a,  0xc6,  0x1d,  0xd2,  0x9c,  0x6f,  0x21,  0xba,  0x5b,  0x86,  0x2f,  0x37,  0x30,  0xe3,  0x7c,  0xfd,
            0xc4,  0xfd,  0x80,  0x6c,  0x22,  0xf2,  0x21,
        ])
        const key = Uint8Array.from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ])
        const nonce = Uint8Array.from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ])

        const out = chacha.ietfStreamXorIc(pt, nonce, key, 1)
        if (!u8_equal(out, ct)) {
            console.log(
                '- ' + u8_to_hex(ct),
                '+ ' + u8_to_hex(out)
            )
        }
        expect(u8_equal(out, ct)).to.be.equal(true)
    })
})
