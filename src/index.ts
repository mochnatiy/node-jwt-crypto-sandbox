import jwt from 'jsonwebtoken'
// import * as forge from 'node-forge'
import type { VerifyKeyObjectInput } from 'crypto'
import * as crypto from 'crypto'
import * as fs from 'fs'
// import * as jose from 'jose'
import pkg from 'node-jose'

const receivedToken = fs.readFileSync('src/ddToken.txt', { encoding: 'utf8' })

const decodedJwt = jwt.decode(receivedToken, { complete: true })
// const joseDecodedJwt = jose.decodeJwt(receivedToken)

const certificateContent:string = decodedJwt.header.x5c[0]
// const alg:string = decodedJwt.header.alg

// const signature:string = decodedJwt.signature

const formattedCertificateContent = certificateContent.
  split(/(.{64})/).
  filter(x => x).
  join('\r\n')

const pemFormattedCertificateContent = 
  '-----BEGIN CERTIFICATE-----\r\n' +
  formattedCertificateContent +
  '\r\n' +
  '-----END CERTIFICATE-----\r\n'

console.log({ pemFormattedCertificateContent })

// const certificateAsDer = forge.util.decode64(formattedCertificateContent)
// const certificateAsAsn1 = forge.asn1.fromDer(certificateAsDer)

// Doesn't work because OID is not RSA
// const certificate = forge.pki.certificateFromPem(pemFormattedCertificateContent)
// const certificate = forge.pki.certificateFromAsn1(certificateAsAsn1)

const certificate = new crypto.X509Certificate(pemFormattedCertificateContent)
const publicKey = certificate.publicKey

// 1.2.840.10045.2.1 - ec
console.log({ Curves: crypto.getCurves() })
console.log({ Const: crypto.constants })

const publicKeyAsPem = publicKey.export({ format: 'pem', type: 'spki' })

// Doesn't work due to lack of bp256r1 supports, fork actually does.
jwt.verify(receivedToken, publicKeyAsPem, { algorithms: ['BP256R1'] }, (error, payload) => {
  console.log({ error, payload })
})

// JOSE fork verification
// console.log('--------- JOSE fork verification ---------')
// const { payload } = await jose.jwtVerify(receivedToken, publicKey)
// console.log({ payload })

// node-crypto Manual verification, all variables are prefixed with m
console.log('--------- Manual verification ---------')
const mBase64Signature = receivedToken.split('.')[2]
if (!mBase64Signature)
  throw new Error('Signature is missing')

const mBase64Payload = receivedToken.split('.')[1]
const mBase64Header = receivedToken.split('.')[0]

const mSignature = Uint8Array.from(Buffer.from(mBase64Signature, 'base64url'))
const mPubKey = { dsaEncoding: 'ieee-p1363', key: publicKey } as VerifyKeyObjectInput
const mData = Uint8Array.from(Buffer.from([mBase64Header, mBase64Payload].join('.'), 'base64url'))
const mAlg = 'sha256'

let isVerified = false
crypto.verify(mAlg, mData, mPubKey, mSignature, (error, result) => {
  isVerified = result
  console.log({ error })
})
console.log({ isVerified })

// Node-jose
// Token encryption
console.log('--------------- IDP TOKEN ENC ---------------------')
const { JWS, JWK, JWE } = pkg

const token = {
  "tokenKey": "_Q7LnV5oyO4BHZqTXfkhEgW0BeIdvMYDyeJ6zTICJZ0",
  "codeVerifier":"T_47B7QsF-QrI6KtMdnp7Jv6HqBRrCW69WXmcu6wM4K7pSzkiqp8Aex2JZeTsbdD32Cby41lK5ki624-nt9hL6Fu-hOYQtgQtv0VyuT1IIn-Zmb0o4SjMzwAW_VPZ8rs"
}

const encryptionKey = { kid: 'puk_idp_enc',
  use: 'enc',
  kty: 'EC',
  enc: 'A256GCM',
  crv: 'BP-256',
  x: 'pkU8LlTZsoGTloO7yjIkV626aGtwpelJ2Wrx7fZtOTo',
  y: 'VliGWQLNtyGuQFs9nXbWdE9O9PFtxb42miy4yaCkCi8',
}

const ecPublicKey = await JWK.asKey(encryptionKey)
const jwe = await JWE.createEncrypt({ format: 'compact' }, ecPublicKey)
  .update(JSON.stringify(token))
  .final()

console.log({ jwe })
// const challengeToken = fs.readFileSync('src/challengeToken.txt', { encoding: 'utf8' })

// const jweHeader = challengeToken.split('.')[0]
// const keyAsJson = Buffer.from(jweHeader, 'base64url').toString()

// Signature verification
console.log('--------------- IDP SIGN VER ---------------------')
const ddPublicKey = Buffer.from(publicKeyAsPem)
const ddPublicKeyAsJwk = await JWK.asKey(ddPublicKey, "pem")
const ddVerifier = await JWS.createVerify(ddPublicKeyAsJwk)

const ddVerifyResult = await ddVerifier.verify(receivedToken)
console.log({ ddVerifyResult })


console.log('--------------- TEST SIGN VER ---------------------')
const testToken = fs.readFileSync('src/testToken.txt', { encoding: 'utf8' })
const testPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----`

const testPubKeyAsUintArray = Buffer.from(testPubKey)
const testPubKeyAsJwk = await JWK.asKey(testPubKeyAsUintArray, "pem")
const testVerifier = await JWS.createVerify(testPubKeyAsJwk)
const verifyResult = await testVerifier.verify(testToken)
console.log({ verifyResult })


// Curve-ID: brainpoolP256r1

// p = A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377

// A = 7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9

// B = 26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6

// x = 8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262

// y = 547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997

// q = A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7

// h = 1

