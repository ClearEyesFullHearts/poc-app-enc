import crypto from 'node:crypto';

const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'secp521r1',
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// console.log("Private key:\n",privateKey.toString('base64url'));
// console.log("Public key:\n",publicKey.toString('base64url'));

// console.log("Public key length:", publicKey.length)

// console.log('ipCNW7hmk3LcqQsEAUbh3KrrB9SrwmnZFkDa7-uCNorNMbioY1RjFEkIqTqKak_lFpqU6pOl91DHnkFfQcICkKJ9Ag2u3OCvP-F4ixwAuIk'.length)

const publicHeader = '-----BEGIN PUBLIC KEY-----';
const publicFooter = '-----END PUBLIC KEY-----';
const trimmedPK = publicKey.replace(/\n/g, '');
const pemContentPublicKey = trimmedPK.substring(publicHeader.length, trimmedPK.length - publicFooter.length);

console.log("Public key length:\n", Buffer.from(pemContentPublicKey, 'base64').toString('base64url').length);

// const privateHeader = '-----BEGIN PRIVATE KEY-----';
// const privateFooter = '-----END PRIVATE KEY-----';
// const trimmedSK = privateKey.replace(/\n/g, '');
// const pemContentPrivateKey = trimmedSK.substring(privateHeader.length, trimmedSK.length - privateFooter.length);

// console.log("Private key url:\n", Buffer.from(pemContentPrivateKey, 'base64').toString('base64url'));
// console.log("Public key url:\n", Buffer.from(pemContentPublicKey, 'base64').toString('base64url'));
// const alice = crypto.createECDH('prime256v1');
// alice.generateKeys();        

// const bob = crypto.createECDH('prime256v1');
// bob.generateKeys();
// const spk = bob.getPublicKey();
// console.log('pk size', spk.length)

// const tss = alice.computeSecret(spk);

// console.log(tss.length)

// const data = crypto.randomBytes(256);
// const hmac = crypto.createHmac('sha512', tss);
// hmac.update(data);
// console.log(hmac.digest().length)

// import crypto from 'node:crypto';
// import fs from 'node:fs';

// const modulo = 4096;
// const keyPair = crypto.generateKeyPairSync('rsa', {
//     modulusLength: modulo,
//     publicKeyEncoding: {
//       type: 'spki',
//       format: 'pem',
//     },
//     privateKeyEncoding: {
//       type: 'pkcs8',
//       format: 'pem',
//     },
//   }
// );


// const {
//   publicKey,
//   privateKey,
// } = keyPair;

// const publicHeader = '-----BEGIN PUBLIC KEY-----';
// const publicFooter = '-----END PUBLIC KEY-----';
// const trimmedPK = publicKey.replace(/\n/g, '');
// const pemContentPublicKey = trimmedPK.substring(publicHeader.length, trimmedPK.length - publicFooter.length);

// const privateHeader = '-----BEGIN PRIVATE KEY-----';
// const privateFooter = '-----END PRIVATE KEY-----';
// const trimmedSK = privateKey.replace(/\n/g, '');
// const pemContentPrivateKey = trimmedSK.substring(privateHeader.length, trimmedSK.length - privateFooter.length);


// console.log('pk', pemContentPublicKey);
// console.log('sk', pemContentPrivateKey);

// fs.writeFileSync('rsaSK.pem', privateKey)
// fs.writeFileSync('rsaPK.pem', publicKey)
// fs.writeFileSync('rsaSK.pem', Buffer.from(pemContentPrivateKey, 'base64').toString('base64url'))
// fs.writeFileSync('rsaPK.pem', Buffer.from(pemContentPublicKey, 'base64').toString('base64url'))