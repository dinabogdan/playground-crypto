'use strict';

const crypto = require('crypto');
const base32 = require('thirty-two');

const SECRET_KEY = Buffer.from("bf3c199c2470cb477d907b1e0917c17bbf3c199c2470cb477d907b1e0917c17b", "hex");
const IV = Buffer.from(crypto.randomBytes(16), "hex");


function encrypt(plainText) {
    const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, IV);
    let cipherText = cipher.update(plainText, 'utf8', 'base64');
    cipherText += cipher.final('base64');
    return cipherText;
}

function decrypt(cipherText) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', SECRET_KEY, IV);
    let plainText = decipher.update(cipherText, 'base64', 'utf8');
    plainText += decipher.final('utf8');
    return plainText;
}

var randomBytes = crypto.randomBytes(16);
console.log('Random bytes: ' + randomBytes);

var code = base32.encode(randomBytes);
console.log('Encoded base32 code is: ' + code);

var cipherText = encrypt(code);
console.log('Ciphertext is: ' + cipherText);

var plainText = decrypt(cipherText);
console.log('Plaintext is: ' + plainText);

var decoded = base32.decode(plainText);
console.log('Decoded code is: ' + decoded);
