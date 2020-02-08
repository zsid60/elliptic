// jscs:disable maximumLineLength
const EC = require('elliptic').ec;
const BN = require('bn.js');
const crypto = require('crypto');

var ec = new EC('secp256k1');

const n = new BN('be95faed2ce5554ea4a7e51342635c75bad4e50fd81281d83a8276ed483f4bc8', 16);
const key = ec.keyFromPrivate(n);

const msg = 'Hello this is test message 0';
const h = crypto.createHash('sha256').update(msg).digest();

console.log('debug');
let sig = key.sign(h);
console.log('Signature: ' + JSON.stringify(sig));

let hnum = ec._truncateToN(new BN(h, 16));
// h as a num should =  83fe0b85e7a80eb179e32ba7511c77ee6c39df9cfc638c3dc96b11a52d076d3d
// 256 bits

let nonce = sig.s.invm(ec.n).mul(sig.r.mul(key.getPrivate()).iadd(hnum)).umod(ec.n);
console.log('\nnonce: ' + nonce.toString(16, 32));

// nonce for h0: bef30f03b37ae6d91ac683d532b0f6b6aa407eb2da923e0df917ad21d929f336
// has a bit length of 256

