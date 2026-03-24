## AES encryption library for ZeppOS.

To import use:

> import CryptoJS from '../lib/aes.js';

### How to encrypt:
```
const pin = 'custom pin' //123456
const data_to_encrypt = 'your text'
const encrypted = CryptoJS.AES.encrypt(data_to_encrypt, pin);
const payload = {
    words: encrypted.words,
    sigBytes: encrypted.sigBytes
};
this.fetchData(JSON.stringify(payload));
```

### How to decrypt:
```
const decrypted = CryptoJS.AES.decrypt(encryptedWordArray, pin);
const decrypted_text = decrypted.toString(CryptoJS.enc.Utf8);
```
