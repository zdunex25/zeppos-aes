const UTF8 = {
    stringify: function (wordArray) {
        var words = wordArray.words;
        var sigBytes = wordArray.sigBytes;
        var str = '';
        for (var i = 0; i < sigBytes; i++) {
            var byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            str += String.fromCharCode(byte);
        }
        return decodeURIComponent(escape(str));
    },
    parse: function (str) {
        var strUtf8 = unescape(encodeURIComponent(str));
        var len = strUtf8.length;
        var words = [];
        for (var i = 0; i < len; i++) {
            words[i >>> 2] |= (strUtf8.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
        }
        return { words: words, sigBytes: len };
    }
};

export default UTF8;