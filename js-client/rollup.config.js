import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';

export default [
    {
        input: 'src/lnn.js',
        output: {
            name: "lightnion.bundle",
            file: 'dist/lightnion.bundle.js',
            format: 'iife',
            sourcemap: true
        },
        plugins: [
            resolve({
                browser: true,
                preferBuiltins: false
            }),
            commonjs()
        ],
    }
];