import { terser } from "rollup-plugin-terser"

export default [
    {
        input: 'lib/paseto.v4.local.js',
        output: {
            name: 'paseto.v4.local',
            file: 'dist/paseto.v4.local.js',
            sourcemap: 'dist/paseto.v4.local.map',
            format: 'umd',
            globals: ['crypto'],
        },
        external: ['crypto'],
        plugins: [terser()]
    },
    {
        input: 'lib/paseto.v4.public.js',
        output: {
            name: 'paseto.v4.public',
            file: 'dist/paseto.v4.public.js',
            sourcemap: 'dist/paseto.v4.public.map',
            format: 'umd',
            globals: ['crypto', 'tweetnacl']
        },
        plugins: [terser()]
    },
    {
        input: 'lib/paserk.k4.seal.js',
        output: {
            name: 'paserk.k4.seal',
            file: 'dist/paserk.k4.seal.js',
            sourcemap: 'dist/paserk.k4.seal.map',
            format: 'umd',
            globals: ['crypto', 'tweetnacl'],
        },
        external: ['crypto'],
        plugins: [terser()]
    },
]