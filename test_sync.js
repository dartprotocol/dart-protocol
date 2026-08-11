const crypto = require('crypto');

function writeUInt24BE(buf, val, offset) {
    buf[offset] = (val >> 16) & 0xFF;
    buf[offset + 1] = (val >> 8) & 0xFF;
    buf[offset + 2] = val & 0xFF;
}

const TYPE_SYNC = 0x03;
const convId = 1;
const senderId = 123;
const highestSeq = 2;

const convKey = Buffer.alloc(32, 0x11);
const NONCE = Buffer.alloc(12, 0x33); // fixed nonce for a deterministic cross-language check

// New 17-byte header: type(1) | convId(2) | senderId(2) | nonce(12).
const header = Buffer.alloc(17);
header.writeUInt8(TYPE_SYNC, 0);
header.writeUInt16BE(convId, 1);
header.writeUInt16BE(senderId, 3);
NONCE.copy(header, 5);

const payloadRust = Buffer.alloc(3);
writeUInt24BE(payloadRust, highestSeq, 0);

const cipher = crypto.createCipheriv('aes-256-gcm', convKey, NONCE);
cipher.setAAD(header);
const encrypted = Buffer.concat([cipher.update(payloadRust), cipher.final(), cipher.getAuthTag()]);

const rustBuf = Buffer.concat([header, encrypted]);
console.log("Rust Buf:", rustBuf.toString('hex'));

// Node decode
const headerDec = rustBuf.subarray(0, 17);
const nonceDec = rustBuf.subarray(5, 17);
const encryptedPayloadDec = rustBuf.subarray(17, rustBuf.length - 16);
const tagDec = rustBuf.subarray(rustBuf.length - 16);

const decipher = crypto.createDecipheriv('aes-256-gcm', convKey, nonceDec);
decipher.setAAD(headerDec);
decipher.setAuthTag(tagDec);

const payloadDec = Buffer.concat([decipher.update(encryptedPayloadDec), decipher.final()]);
const decodedHighestSeq = payloadDec.readUIntBE(0, 3);

console.log("Decoded HighestSeq:", decodedHighestSeq);
