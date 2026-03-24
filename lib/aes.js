var CryptoJS = CryptoJS || (function (Math, undefined) {
    var C = {};
    var C_lib = C.lib = {};
    var Base = C_lib.Base = {
        extend: function (overrides) {
            var subtype = function () { };
            subtype.prototype = this;
            var instance = new subtype();
            if (overrides) instance.mixIn(overrides);
            if (!instance.hasOwnProperty('init')) {
                instance.init = function () { instance.$super.init.apply(this, arguments); };
            }
            instance.init.prototype = instance;
            instance.$super = this;
            return instance;
        },
        create: function () {
            var instance = this.extend();
            instance.init.apply(instance, arguments);
            return instance;
        },
        mixIn: function (overrides) {
            for (var name in overrides) {
                if (overrides.hasOwnProperty(name)) {
                    this[name] = overrides[name];
                }
            }
        }
    };
    var WordArray = C_lib.WordArray = Base.extend({
        init: function (words, sigBytes) {
            words = this.words = words || [];
            this.sigBytes = sigBytes != undefined ? sigBytes : words.length * 4;
        },
        toString: function (encoder) { return (encoder || Utf8).stringify(this); }
    });
    var C_enc = C.enc = {};
    var Utf8 = C_enc.Utf8 = {
        stringify: function (wordArray) {
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;
            var str = [];
            for (var i = 0; i < sigBytes; i++) {
                var byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                str.push(String.fromCharCode(byte));
            }
            return str.join('');
        },
        parse: function (str) {
            var strLen = str.length;
            var words = [];
            for (var i = 0; i < strLen; i++) {
                words[i >>> 2] |= (str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
            }
            return WordArray.create(words, strLen);
        }
    };
    var C_algo = C.algo = {};
    var Cipher = C_lib.Cipher = Base.extend({
        init: function (key) { this._key = key; this._doReset(); },
        _createHelper: function (cipher) {
            return {
                encrypt: function (message, key) {
                    var m = (typeof message == 'string') ? Utf8.parse(message) : message;
                    var k = (typeof key == 'string') ? Utf8.parse(key) : key;

                    // Klucz zawsze 16 bajtów
                    while (k.words.length < 4) k.words.push(0);
                    k.sigBytes = 16;

                    var aes = cipher.create(k);

                    // PĘTLA: Szyfrujemy każdy blok 16-bajtowy (4 słowa)
                    // To pozwoli na notatki o dowolnej długości!
                    for (var i = 0; i < m.words.length; i += 4) {
                        // Jeśli ostatni blok jest za krótki, uzupełniamy zerami
                        while (m.words.length < i + 4) m.words.push(0);
                        aes.encryptBlock(m.words, i);
                    }
                    return m;
                },
                decrypt: function (wordArray, key) {
                    var k = (typeof key == 'string') ? Utf8.parse(key) : key;

                    while (k.words.length < 4) k.words.push(0);
                    k.sigBytes = 16;

                    var aes = cipher.create(k);

                    // PĘTLA: Deszyfrujemy każdy blok 16-bajtowy
                    for (var i = 0; i < wordArray.words.length; i += 4) {
                        aes.decryptBlock(wordArray.words, i);
                    }
                    return wordArray;
                }
            };
        }
    });
    var BlockCipher = C_lib.BlockCipher = Cipher.extend({ _doReset: function () { } });
    return C;
}(Math));

(function () {
    var C = CryptoJS;
    var C_lib = C.lib;
    var BlockCipher = C_lib.BlockCipher;
    var C_algo = C.algo;
    var SBOX = [], INV_SBOX = [], SUB_MIX_0 = [], SUB_MIX_1 = [], SUB_MIX_2 = [], SUB_MIX_3 = [], INV_SUB_MIX_0 = [], INV_SUB_MIX_1 = [], INV_SUB_MIX_2 = [], INV_SUB_MIX_3 = [];
    (function () {
        var d = []; for (var i = 0; i < 256; i++) d[i] = i < 128 ? i << 1 : (i << 1) ^ 0x11b;
        var x = 0, xi = 0;
        for (var i = 0; i < 256; i++) {
            var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4); sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63; SBOX[x] = sx; INV_SBOX[sx] = x;
            var x2 = d[x], x4 = d[x2], x8 = d[x4];
            var t = (d[sx] * 0x101) ^ (sx * 0x1010100); SUB_MIX_0[x] = (t << 24) | (t >>> 8); SUB_MIX_1[x] = (t << 16) | (t >>> 16); SUB_MIX_2[x] = (t << 8) | (t >>> 24); SUB_MIX_3[x] = t;
            var t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100); INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8); INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16); INV_SUB_MIX_2[sx] = (t << 8) | (t >>> 24); INV_SUB_MIX_3[sx] = t;
            if (!x) { x = xi = 1; } else { x = x2 ^ d[d[d[x8 ^ x2]]]; xi ^= d[d[xi]]; }
        }
    }());
    var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    var AES = C_algo.AES = BlockCipher.extend({
        _doReset: function () {
            var key = this._key; var keyWords = key.words; var keySize = key.sigBytes / 4;
            var nRounds = this._nRounds = keySize + 6; var ksRows = (nRounds + 1) * 4; var keySchedule = this._keySchedule = [];
            for (var ksRow = 0; ksRow < ksRows; ksRow++) {
                if (ksRow < keySize) { keySchedule[ksRow] = keyWords[ksRow]; } else {
                    var t = keySchedule[ksRow - 1]; if (!(ksRow % keySize)) { t = (t << 8) | (t >>> 24); t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff]; t ^= RCON[(ksRow / keySize) | 0] << 24; }
                    else if (keySize > 6 && ksRow % keySize == 4) { t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff]; }
                    keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
                }
            }
            var invKeySchedule = this._invKeySchedule = [];
            for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
                var ksRow = ksRows - invKsRow; var t = (invKsRow % 4) ? keySchedule[ksRow] : keySchedule[ksRow - 4];
                if (invKsRow < 4 || ksRow <= 4) { invKeySchedule[invKsRow] = t; } else { invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^ INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]]; }
            }
        },
        encryptBlock: function (M, offset) { this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX); },
        decryptBlock: function (M, offset) { var t = M[offset + 1]; M[offset + 1] = M[offset + 3]; M[offset + 3] = t; this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX); var t = M[offset + 1]; M[offset + 1] = M[offset + 3]; M[offset + 3] = t; },
        _doCryptBlock: function (M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
            var nRounds = this._nRounds; var s0 = M[offset] ^ keySchedule[0], s1 = M[offset + 1] ^ keySchedule[1], s2 = M[offset + 2] ^ keySchedule[2], s3 = M[offset + 3] ^ keySchedule[3];
            var ksRow = 4; for (var round = 1; round < nRounds; round++) {
                var t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
                var t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
                var t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
                var t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];
                s0 = t0; s1 = t1; s2 = t2; s3 = t3;
            }
            var t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
            var t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
            var t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
            var t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];
            M[offset] = t0; M[offset + 1] = t1; M[offset + 2] = t2; M[offset + 3] = t3;
        }
    });
    C.AES = BlockCipher._createHelper(AES);
}());

export default CryptoJS;