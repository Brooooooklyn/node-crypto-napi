const crypto = require('./target/debug/node_crypto_napi.node')

const Hasher = crypto.createHasher()
const hasher = new Hasher('sha256')
const buf = Buffer.from('Hello world!!')
console.log(hasher.digest(buf))
const { createHash } = require('crypto')

const nativeHasher = createHash('sha256')
nativeHasher.update(buf)
console.log(nativeHasher.digest('hex'))