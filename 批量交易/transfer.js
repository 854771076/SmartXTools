var Wallet = new Object()
Wallet.Hex2Bytes = function(str) {
    var pos = 0;
    var len = str.length;
    if (len % 2 != 0) {
        return null;
    }
    len /= 2;
    var hexA = new Array();
    for (var i = 0; i < len; i++) {
        var s = str.substr(pos, 2);
        var v = parseInt(s, 16);
        if (v >= 127) v = v - 255 - 1
        hexA.push(v);
        pos += 2;
    }

    var uintarr = new Uint8Array(hexA.length);
    for (var i = 0; i < hexA.length; i++) {
        uintarr[i] = hexA[i];
    }
    return uintarr;
};

Wallet.Bytes2Hex = function(arr) {
    var uintarr = new Uint8Array(arr.length);
    for (var i = 0; i < arr.length; i++) {
        uintarr[i] = arr[i];
    }

    var str = "";
    for (var i = 0; i < uintarr.length; i++) {
        var tmp = uintarr[i].toString(16);
        if (tmp.length == 1) {
            tmp = "0" + tmp;
        }
        str += tmp;
    }
    return str;
};

Wallet.Str2Hex = function(str) {
    if (str === "")
        return "";
    var array = Wallet.Str2Bytes(str);
    return Wallet.Bytes2Hex(array);
};

Wallet.Byte2Str = function(arr) {
    return Base58.encode(arr);
};

Wallet.Str2Bytes = function(str) {
    var ch, st, re = [];
    for (var i = 0; i < str.length; i++) {
        ch = str.charCodeAt(i); // get char   
        st = []; // set up "stack"  
        do {
            st.push(ch & 0xFF); // push byte to stack  
            ch = ch >> 8; // shift value down by 1 byte  
        }
        while (ch);
        // add stack contents to result  
        // done because chars have "wrong" endianness  
        re = re.concat(st.reverse());
    }
    // return an array of bytes  
    return re;
};

Wallet.ToAddress = function(publicKey) {
    var publicKeyHex = Wallet.Bytes2Hex(publicKey);
    // ToAddress
    var sha256 = new Hashes.SHA256().hex(publicKeyHex);
    var rmd160 = new Hashes.RMD160().hex(sha256);
    rmd160 = Wallet.Hex2Bytes(rmd160);

    var temp = new Uint8Array(21);
    temp[0] = 1;
    for (var i = 0; i < 20; i++) {
        temp[i + 1] = rmd160[i];
    }

    var data = Wallet.Bytes2Hex(temp);
    // Base58CheckEncode
    var hash1 = new Hashes.SHA256().hex(data);
    var hash2 = new Hashes.SHA256().hex(hash1);
    hash2 = Wallet.Hex2Bytes(hash2);

    var buffer = new Uint8Array(25);
    for (var i = 0; i < temp.length; i++) {
        buffer[i] = temp[i];
    }
    for (var i = 0; i < 4; i++) {
        buffer[21 + i] = hash2[i];
    }
    var b58 = Base58.encode(buffer);

    return b58;
};

Wallet.CheckAddress = function(address) {
    try {
        var decode58 = Base58.decodeArray(address);
        var encode58 = Base58.encode(decode58);

        var temp = new Uint8Array(decode58.length - 4);
        for (var i = 0; i < temp.length; i++) {
            temp[i] = decode58[i];
        }
        var data = Wallet.Bytes2Hex(temp);
        var hash1 = new Hashes.SHA256().hex(data);
        var hash2 = new Hashes.SHA256().hex(hash1);
        hash2 = Wallet.Hex2Bytes(hash2);

        for (var i = 0; i < 4; i++) {
            if (decode58[21 + i] != hash2[i]) {
                return false;
            }
        }
        return true;
    } catch {}
    return false;
}


Wallet.CreateKeyPair = function(randomText) {
    var seed = EncryptUtils.generateSeed();

    var temp = Wallet.Byte2Str(seed) + "#" + randomText;
    temp = Wallet.Str2Hex(temp)
    var sha256 = new Hashes.SHA256().hex(temp);

    temp = Wallet.Hex2Bytes(sha256)
    for (var i = 0; i < seed.length; i++) {
        seed[i] = temp[i];
    }
    var KeyPair = EncryptUtils.generateKeyPairSeed(seed);
    KeyPair.randomSeed = seed;
    return KeyPair;
};

//
Wallet.ImportKeyPair = function(mnemonicWord) {
    var seed = Wallet.Hex2Bytes(mnemonicWord);
    var numArr = new Uint8Array(32);
    for (var i = 0; i < seed.length; i++) {
        numArr[i] = seed[i];
    }
    var KeyPair = EncryptUtils.generateKeyPairSeed(numArr);
    KeyPair.randomSeed = seed;
    return KeyPair;
};


//
Wallet.GetMnemonicWord = function(KeyPair) {
    return Wallet.Bytes2Hex(KeyPair.randomSeed);
};

//
Wallet.sign = function(data, keyPair) {
    var dataBytes = Wallet.Hex2Bytes(data)
    var sign = EncryptUtils.sign(keyPair.privateKey, dataBytes);
    var buffer = new Uint8Array(sign.length + keyPair.publicKey.length);
    for (var i = 0; i < sign.length; i++) {
        buffer[i] = sign[i];
    }
    for (var i = 0; i < keyPair.publicKey.length; i++) {
        buffer[i + sign.length] = keyPair.publicKey[i];
    }
    return buffer;
};

Wallet.verify = function(sign, data, address) {
    var dataBytes = Wallet.Hex2Bytes(data)
    var buffer = new Uint8Array(sign.length - 32);
    var publicKey = new Uint8Array(32);
    for (var i = 0; i < buffer.length; i++) {
        buffer[i] = sign[i];
    }
    for (var i = 0; i < keyPair.publicKey.length; i++) {
        publicKey[i] = sign[i + buffer.length];
    }

    if (EncryptUtils.verify(dataBytes, sign, keyPair.publicKey)) {
        if (Wallet.ToAddress(keyPair.publicKey) == address) {
            return true;
        }
    }
    return false;
};

//
Wallet.Save = function(index, KeyPair, password) {
    if (password != null) {
        var MnemonicWord = Wallet.GetMnemonicWord(KeyPair)
        var ciphertext = CryptoJS.AES.encrypt(MnemonicWord, password).toString(); // Encrypt

        localStorage.setItem("KeyPair.MnemonicWord_" + index, ciphertext);
    }
};

//
Wallet.Load = function(index, password) {
    if (password != null) {
        var ciphertext = localStorage.getItem("KeyPair.MnemonicWord_" + index);
        if (ciphertext != null && ciphertext != "") {
            var bytes = CryptoJS.AES.decrypt(ciphertext, password); // Decrypt
            var MnemonicWord = bytes.toString(CryptoJS.enc.Utf8);
            return Wallet.ImportKeyPair(MnemonicWord);
        }
    }
    return null;
};

Wallet.Clear = function() {
    for (var index = 1; index < 100; index++) {
        localStorage.removeItem("KeyPair.MnemonicWord_" + index);
    }
    localStorage.removeItem("PasswordHash");
    sessionStorage.removeItem("wallet_password");
};

Wallet.LoadFromAddress = function(addressIn, password) {
    var addressKeyPair = null;
    for (var index = 1; index < 100; index++) {
        var KeyPair = Wallet.Load(index, password);
        if (KeyPair == null)
            break;

        var address = Wallet.ToAddress(KeyPair.publicKey);
        if (address == addressIn) {
            addressKeyPair = KeyPair
        }
    }
    return addressKeyPair;
}

Wallet.GetCount = function(password) {
    var index = 1;
    for (; index < 100; index++) {
        var KeyPair = Wallet.Load(index, password);
        if (KeyPair == null)
            break;
    }
    return index;
}

//
Wallet.Test = function() {
    var keyPair = Wallet.ImportKeyPair("aa306f7fad8f12dad3e7b90ee15af0b39e9eccd1aad2e757de2d5ad74b42b67a");
    var data = "e33b68cd7ad3dc29e623e399a46956d54c1861c5cd1e5039b875811d2ca4447d";
    console.warn(data);

    console.warn(Wallet.GetMnemonicWord(keyPair));
    console.warn(Wallet.Bytes2Hex(keyPair.publicKey));
    console.warn(Wallet.Bytes2Hex(keyPair.privateKey));
    console.warn(Wallet.ToAddress(keyPair.publicKey));

    var sign = Wallet.sign(data, keyPair)
    console.warn(Wallet.Bytes2Hex(sign));


};

function Res(prekey, data) {
    var keyPair = Wallet.ImportKeyPair(prekey);
    var sign = Wallet.sign(data, keyPair)
    return Wallet.Bytes2Hex(sign)

};

function getHashdata(data1, data2) {
    var timestamp = (new Date().getTime())
    return [timestamp, new Hashes.SHA256().hex(data1 + timestamp + data2)]
}
BaseX = function(ALPHABET) {
    var ALPHABET_MAP = {}
    var BASE = ALPHABET.length
    var LEADER = ALPHABET.charAt(0)

    // pre-compute lookup table
    for (var i = 0; i < ALPHABET.length; i++) {
        ALPHABET_MAP[ALPHABET.charAt(i)] = i
    }

    /**
     * @param {(Buffer|number[])} source
     * @return {string}
     */
    function encode(source) {
        if (source.length === 0) return ''

        var digits = [0]
        for (var i = 0; i < source.length; ++i) {
            var carry = (digits[0] << 8) + source[i]
            digits[0] = carry % BASE
            carry = (carry / BASE) | 0

            for (var j = 1; j < digits.length; ++j) {
                carry += digits[j] << 8
                digits[j] = carry % BASE
                carry = (carry / BASE) | 0
            }

            while (carry > 0) {
                digits.push(carry % BASE)
                carry = (carry / BASE) | 0
            }
        }

        // deal with leading zeros
        for (var k = 0; source[k] === 0 && k < source.length - 1; ++k) {
            digits.push(0)
        }

        // convert digits to a string
        for (var ii = 0, jj = digits.length - 1; ii <= jj; ++ii, --jj) {
            var tmp = ALPHABET[digits[ii]]
            digits[ii] = ALPHABET[digits[jj]]
            digits[jj] = tmp
        }

        return digits.join('')
    }

    /**
     * @param {string} string
     * @return {number[]}
     */
    function decode(string) {
        if (string.length === 0) return []

        var bytes = [0]
        for (var i = 0; i < string.length; i++) {
            var value = ALPHABET_MAP[string[i]]
            if (value === undefined) throw new Error('Non-base' + BASE + ' character')

            var carry = bytes[0] * BASE + value
            bytes[0] = carry & 0xff
            carry >>= 8

            for (var j = 1; j < bytes.length; ++j) {
                carry += bytes[j] * BASE
                bytes[j] = carry & 0xff
                carry >>= 8
            }

            while (carry > 0) {
                bytes.push(carry & 0xff)
                carry >>= 8
            }
        }

        // deal with leading zeros
        for (var k = 0; string[k] === LEADER && k < string.length - 1; ++k) {
            bytes.push(0)
        }

        return bytes.reverse()
    }

    return {
        encode: encode,
        decode: decode
    }
};

var bs58alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
var bs58 = BaseX(bs58alphabet);

Base58 = {
    encode: function(source) {
        if (typeof source == 'string') {
            var buffer = [];
            for (var i = 0; i < source.length; i++) {
                buffer.push(source.charCodeAt(i));
            }

            return this.encode(buffer);
        }

        return bs58.encode(source);
    },
    decode: function(source) {
        return String.fromCharCode.apply(source, bs58.decode(source));
    },
    decodeArray: function(source) {
        return bs58.decode(source);
    }
};

var EncryptUtils = new Object()
    /*
     * import the dependencies for ed25519 and base58
     * use: need them before this!
     * */

/**
 * generate the byte[] KeyPair use ed25519
 */
EncryptUtils.generateKeyPairByte = function() {
    var keyPair = nacl.sign.keyPair();
    var pk = keyPair.publicKey;
    var sk = keyPair.secretKey.slice(0, 32);
    return { publicKey: pk, privateKey: sk };
};

/**
 * generate generateSeed
 */
EncryptUtils.generateSeed = function() {
    var numArr = new Uint8Array(32);
    for (var i = 0; i < numArr.length; i++) {
        numArr[i] = Math.random() * 255;
    }
    return numArr;
};

/**
 * generate the base58 encode KeyPair use ed25519
 */
EncryptUtils.generateKeyPair = function() {
    var keyPair = nacl.sign.keyPair();
    var pk = Base58.encode(keyPair.publicKey);
    var sk = Base58.encode(keyPair.secretKey.slice(0, 32));
    return { publicKey: pk, privateKey: sk };
};

EncryptUtils.Bytes2Hex = function(arr) {
    var str = "";
    for (var i = 0; i < arr.length; i++) {
        var tmp = arr[i].toString(16);
        if (tmp.length == 1) {
            tmp = "0" + tmp;
        }
        str += tmp;
    }
    return str;
};

/**
 * generate the base58 encode KeyPair use ed25519
 */
EncryptUtils.generateKeyPairSeed = function(seed) {
    var keyPair = nacl.sign.keyPair.fromSeed(seed);
    var pk = keyPair.publicKey;
    var sk = keyPair.secretKey;
    return { publicKey: pk, privateKey: sk };
};

/**
 * get the publickey from privateKey
 * @param {Object} privateKey
 */
EncryptUtils.getPublicKeyByPrivateKey = function(privateKey) {
    var secretKey = privateKey.slice(0, 32)
    var secretKeyUnit8Array = new Uint8Array(32);
    secretKeyUnit8Array.set(secretKey)
    var keyPair = nacl.sign.keyPair.fromSeed(secretKeyUnit8Array);
    return keyPair.publicKey;
};

/**
 * sign the msg with privateKey
 * @param {Object} msg
 * @param {Object} secretKey
 */
EncryptUtils.sign = function(privateKey, msg) {
    /*----------- convert the privateKey(base58 32) to secretKey(Uint8Array 64) ----------*/
    var secretKeyFull = privateKey;
    /*----------- convert the msg(string) to msg(Uint8Array ) ---------*/
    var msgByte = msg;
    var msgUnit8Array = new Uint8Array(msgByte.length);
    msgUnit8Array.set(msgByte);
    var signedMsg = nacl.sign.detached(msgUnit8Array, secretKeyFull);
    return signedMsg;
};

/**
 * sig msg verify
 * @param {Object} msg
 * @param {Object} sig
 * @param {Object} publicKey
 */
EncryptUtils.verify = function(msg, sig, publicKey) {
    var msgByte = msg;
    var sigByte = sig;
    var publicKeyByte = publicKey;
    var publicKeyUnit8Array = new Uint8Array(publicKeyByte.length);
    var sigByteUnit8Array = new Uint8Array(sigByte.length);
    var msgByteUnit8Array = new Uint8Array(msgByte.length);

    publicKeyUnit8Array.set(publicKeyByte);
    sigByteUnit8Array.set(sigByte);
    msgByteUnit8Array.set(msgByte);

    return nacl.sign.detached.verify(msgByteUnit8Array, sigByteUnit8Array, publicKeyUnit8Array);
};

/**
 * string to byte
 * @param {Object} str
 */
EncryptUtils.stringToBytes = function(str) {
    var ch, st, re = [];
    for (var i = 0; i < str.length; i++) {
        ch = str.charCodeAt(i); // get char   
        st = []; // set up "stack"  
        do {
            st.push(ch & 0xFF); // push byte to stack  
            ch = ch >> 8; // shift value down by 1 byte  
        }
        while (ch);
        // add stack contents to result  
        // done because chars have "wrong" endianness  
        re = re.concat(st.reverse());
    }
    // return an array of bytes  
    return re;
};

var nacl = new Object()


// Ported in 2014 by Dmitry Chestnykh and Devi Mandiri.
// Public domain.
//
// Implementation derived from TweetNaCl version 20140427.
// See for details: http://tweetnacl.cr.yp.to/

var gf = function(init) {
    var i, r = new Float64Array(16);
    if (init)
        for (i = 0; i < init.length; i++) r[i] = init[i];
    return r;
};

//  Pluggable, initialized in high-level API below.
var randombytes = function( /* x, n */ ) { throw new Error('no PRNG'); };

var _0 = new Uint8Array(16);
var _9 = new Uint8Array(32);
_9[0] = 9;

var gf0 = gf(),
    gf1 = gf([1]),
    _121665 = gf([0xdb41, 1]),
    D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]),
    D2 = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]),
    X = gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]),
    Y = gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]),
    I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);

function ts64(x, i, h, l) {
    x[i] = (h >> 24) & 0xff;
    x[i + 1] = (h >> 16) & 0xff;
    x[i + 2] = (h >> 8) & 0xff;
    x[i + 3] = h & 0xff;
    x[i + 4] = (l >> 24) & 0xff;
    x[i + 5] = (l >> 16) & 0xff;
    x[i + 6] = (l >> 8) & 0xff;
    x[i + 7] = l & 0xff;
}

function vn(x, xi, y, yi, n) {
    var i, d = 0;
    for (i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i];
    return (1 & ((d - 1) >>> 8)) - 1;
}

function crypto_verify_16(x, xi, y, yi) {
    return vn(x, xi, y, yi, 16);
}

function crypto_verify_32(x, xi, y, yi) {
    return vn(x, xi, y, yi, 32);
}

function core_salsa20(o, p, k, c) {
    var j0 = c[0] & 0xff | (c[1] & 0xff) << 8 | (c[2] & 0xff) << 16 | (c[3] & 0xff) << 24,
        j1 = k[0] & 0xff | (k[1] & 0xff) << 8 | (k[2] & 0xff) << 16 | (k[3] & 0xff) << 24,
        j2 = k[4] & 0xff | (k[5] & 0xff) << 8 | (k[6] & 0xff) << 16 | (k[7] & 0xff) << 24,
        j3 = k[8] & 0xff | (k[9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24,
        j4 = k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24,
        j5 = c[4] & 0xff | (c[5] & 0xff) << 8 | (c[6] & 0xff) << 16 | (c[7] & 0xff) << 24,
        j6 = p[0] & 0xff | (p[1] & 0xff) << 8 | (p[2] & 0xff) << 16 | (p[3] & 0xff) << 24,
        j7 = p[4] & 0xff | (p[5] & 0xff) << 8 | (p[6] & 0xff) << 16 | (p[7] & 0xff) << 24,
        j8 = p[8] & 0xff | (p[9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24,
        j9 = p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24,
        j10 = c[8] & 0xff | (c[9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24,
        j11 = k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24,
        j12 = k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24,
        j13 = k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24,
        j14 = k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24,
        j15 = c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24;

    var x0 = j0,
        x1 = j1,
        x2 = j2,
        x3 = j3,
        x4 = j4,
        x5 = j5,
        x6 = j6,
        x7 = j7,
        x8 = j8,
        x9 = j9,
        x10 = j10,
        x11 = j11,
        x12 = j12,
        x13 = j13,
        x14 = j14,
        x15 = j15,
        u;

    for (var i = 0; i < 20; i += 2) {
        u = x0 + x12 | 0;
        x4 ^= u << 7 | u >>> (32 - 7);
        u = x4 + x0 | 0;
        x8 ^= u << 9 | u >>> (32 - 9);
        u = x8 + x4 | 0;
        x12 ^= u << 13 | u >>> (32 - 13);
        u = x12 + x8 | 0;
        x0 ^= u << 18 | u >>> (32 - 18);

        u = x5 + x1 | 0;
        x9 ^= u << 7 | u >>> (32 - 7);
        u = x9 + x5 | 0;
        x13 ^= u << 9 | u >>> (32 - 9);
        u = x13 + x9 | 0;
        x1 ^= u << 13 | u >>> (32 - 13);
        u = x1 + x13 | 0;
        x5 ^= u << 18 | u >>> (32 - 18);

        u = x10 + x6 | 0;
        x14 ^= u << 7 | u >>> (32 - 7);
        u = x14 + x10 | 0;
        x2 ^= u << 9 | u >>> (32 - 9);
        u = x2 + x14 | 0;
        x6 ^= u << 13 | u >>> (32 - 13);
        u = x6 + x2 | 0;
        x10 ^= u << 18 | u >>> (32 - 18);

        u = x15 + x11 | 0;
        x3 ^= u << 7 | u >>> (32 - 7);
        u = x3 + x15 | 0;
        x7 ^= u << 9 | u >>> (32 - 9);
        u = x7 + x3 | 0;
        x11 ^= u << 13 | u >>> (32 - 13);
        u = x11 + x7 | 0;
        x15 ^= u << 18 | u >>> (32 - 18);

        u = x0 + x3 | 0;
        x1 ^= u << 7 | u >>> (32 - 7);
        u = x1 + x0 | 0;
        x2 ^= u << 9 | u >>> (32 - 9);
        u = x2 + x1 | 0;
        x3 ^= u << 13 | u >>> (32 - 13);
        u = x3 + x2 | 0;
        x0 ^= u << 18 | u >>> (32 - 18);

        u = x5 + x4 | 0;
        x6 ^= u << 7 | u >>> (32 - 7);
        u = x6 + x5 | 0;
        x7 ^= u << 9 | u >>> (32 - 9);
        u = x7 + x6 | 0;
        x4 ^= u << 13 | u >>> (32 - 13);
        u = x4 + x7 | 0;
        x5 ^= u << 18 | u >>> (32 - 18);

        u = x10 + x9 | 0;
        x11 ^= u << 7 | u >>> (32 - 7);
        u = x11 + x10 | 0;
        x8 ^= u << 9 | u >>> (32 - 9);
        u = x8 + x11 | 0;
        x9 ^= u << 13 | u >>> (32 - 13);
        u = x9 + x8 | 0;
        x10 ^= u << 18 | u >>> (32 - 18);

        u = x15 + x14 | 0;
        x12 ^= u << 7 | u >>> (32 - 7);
        u = x12 + x15 | 0;
        x13 ^= u << 9 | u >>> (32 - 9);
        u = x13 + x12 | 0;
        x14 ^= u << 13 | u >>> (32 - 13);
        u = x14 + x13 | 0;
        x15 ^= u << 18 | u >>> (32 - 18);
    }
    x0 = x0 + j0 | 0;
    x1 = x1 + j1 | 0;
    x2 = x2 + j2 | 0;
    x3 = x3 + j3 | 0;
    x4 = x4 + j4 | 0;
    x5 = x5 + j5 | 0;
    x6 = x6 + j6 | 0;
    x7 = x7 + j7 | 0;
    x8 = x8 + j8 | 0;
    x9 = x9 + j9 | 0;
    x10 = x10 + j10 | 0;
    x11 = x11 + j11 | 0;
    x12 = x12 + j12 | 0;
    x13 = x13 + j13 | 0;
    x14 = x14 + j14 | 0;
    x15 = x15 + j15 | 0;

    o[0] = x0 >>> 0 & 0xff;
    o[1] = x0 >>> 8 & 0xff;
    o[2] = x0 >>> 16 & 0xff;
    o[3] = x0 >>> 24 & 0xff;

    o[4] = x1 >>> 0 & 0xff;
    o[5] = x1 >>> 8 & 0xff;
    o[6] = x1 >>> 16 & 0xff;
    o[7] = x1 >>> 24 & 0xff;

    o[8] = x2 >>> 0 & 0xff;
    o[9] = x2 >>> 8 & 0xff;
    o[10] = x2 >>> 16 & 0xff;
    o[11] = x2 >>> 24 & 0xff;

    o[12] = x3 >>> 0 & 0xff;
    o[13] = x3 >>> 8 & 0xff;
    o[14] = x3 >>> 16 & 0xff;
    o[15] = x3 >>> 24 & 0xff;

    o[16] = x4 >>> 0 & 0xff;
    o[17] = x4 >>> 8 & 0xff;
    o[18] = x4 >>> 16 & 0xff;
    o[19] = x4 >>> 24 & 0xff;

    o[20] = x5 >>> 0 & 0xff;
    o[21] = x5 >>> 8 & 0xff;
    o[22] = x5 >>> 16 & 0xff;
    o[23] = x5 >>> 24 & 0xff;

    o[24] = x6 >>> 0 & 0xff;
    o[25] = x6 >>> 8 & 0xff;
    o[26] = x6 >>> 16 & 0xff;
    o[27] = x6 >>> 24 & 0xff;

    o[28] = x7 >>> 0 & 0xff;
    o[29] = x7 >>> 8 & 0xff;
    o[30] = x7 >>> 16 & 0xff;
    o[31] = x7 >>> 24 & 0xff;

    o[32] = x8 >>> 0 & 0xff;
    o[33] = x8 >>> 8 & 0xff;
    o[34] = x8 >>> 16 & 0xff;
    o[35] = x8 >>> 24 & 0xff;

    o[36] = x9 >>> 0 & 0xff;
    o[37] = x9 >>> 8 & 0xff;
    o[38] = x9 >>> 16 & 0xff;
    o[39] = x9 >>> 24 & 0xff;

    o[40] = x10 >>> 0 & 0xff;
    o[41] = x10 >>> 8 & 0xff;
    o[42] = x10 >>> 16 & 0xff;
    o[43] = x10 >>> 24 & 0xff;

    o[44] = x11 >>> 0 & 0xff;
    o[45] = x11 >>> 8 & 0xff;
    o[46] = x11 >>> 16 & 0xff;
    o[47] = x11 >>> 24 & 0xff;

    o[48] = x12 >>> 0 & 0xff;
    o[49] = x12 >>> 8 & 0xff;
    o[50] = x12 >>> 16 & 0xff;
    o[51] = x12 >>> 24 & 0xff;

    o[52] = x13 >>> 0 & 0xff;
    o[53] = x13 >>> 8 & 0xff;
    o[54] = x13 >>> 16 & 0xff;
    o[55] = x13 >>> 24 & 0xff;

    o[56] = x14 >>> 0 & 0xff;
    o[57] = x14 >>> 8 & 0xff;
    o[58] = x14 >>> 16 & 0xff;
    o[59] = x14 >>> 24 & 0xff;

    o[60] = x15 >>> 0 & 0xff;
    o[61] = x15 >>> 8 & 0xff;
    o[62] = x15 >>> 16 & 0xff;
    o[63] = x15 >>> 24 & 0xff;
}

function core_hsalsa20(o, p, k, c) {
    var j0 = c[0] & 0xff | (c[1] & 0xff) << 8 | (c[2] & 0xff) << 16 | (c[3] & 0xff) << 24,
        j1 = k[0] & 0xff | (k[1] & 0xff) << 8 | (k[2] & 0xff) << 16 | (k[3] & 0xff) << 24,
        j2 = k[4] & 0xff | (k[5] & 0xff) << 8 | (k[6] & 0xff) << 16 | (k[7] & 0xff) << 24,
        j3 = k[8] & 0xff | (k[9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24,
        j4 = k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24,
        j5 = c[4] & 0xff | (c[5] & 0xff) << 8 | (c[6] & 0xff) << 16 | (c[7] & 0xff) << 24,
        j6 = p[0] & 0xff | (p[1] & 0xff) << 8 | (p[2] & 0xff) << 16 | (p[3] & 0xff) << 24,
        j7 = p[4] & 0xff | (p[5] & 0xff) << 8 | (p[6] & 0xff) << 16 | (p[7] & 0xff) << 24,
        j8 = p[8] & 0xff | (p[9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24,
        j9 = p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24,
        j10 = c[8] & 0xff | (c[9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24,
        j11 = k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24,
        j12 = k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24,
        j13 = k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24,
        j14 = k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24,
        j15 = c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24;

    var x0 = j0,
        x1 = j1,
        x2 = j2,
        x3 = j3,
        x4 = j4,
        x5 = j5,
        x6 = j6,
        x7 = j7,
        x8 = j8,
        x9 = j9,
        x10 = j10,
        x11 = j11,
        x12 = j12,
        x13 = j13,
        x14 = j14,
        x15 = j15,
        u;

    for (var i = 0; i < 20; i += 2) {
        u = x0 + x12 | 0;
        x4 ^= u << 7 | u >>> (32 - 7);
        u = x4 + x0 | 0;
        x8 ^= u << 9 | u >>> (32 - 9);
        u = x8 + x4 | 0;
        x12 ^= u << 13 | u >>> (32 - 13);
        u = x12 + x8 | 0;
        x0 ^= u << 18 | u >>> (32 - 18);

        u = x5 + x1 | 0;
        x9 ^= u << 7 | u >>> (32 - 7);
        u = x9 + x5 | 0;
        x13 ^= u << 9 | u >>> (32 - 9);
        u = x13 + x9 | 0;
        x1 ^= u << 13 | u >>> (32 - 13);
        u = x1 + x13 | 0;
        x5 ^= u << 18 | u >>> (32 - 18);

        u = x10 + x6 | 0;
        x14 ^= u << 7 | u >>> (32 - 7);
        u = x14 + x10 | 0;
        x2 ^= u << 9 | u >>> (32 - 9);
        u = x2 + x14 | 0;
        x6 ^= u << 13 | u >>> (32 - 13);
        u = x6 + x2 | 0;
        x10 ^= u << 18 | u >>> (32 - 18);

        u = x15 + x11 | 0;
        x3 ^= u << 7 | u >>> (32 - 7);
        u = x3 + x15 | 0;
        x7 ^= u << 9 | u >>> (32 - 9);
        u = x7 + x3 | 0;
        x11 ^= u << 13 | u >>> (32 - 13);
        u = x11 + x7 | 0;
        x15 ^= u << 18 | u >>> (32 - 18);

        u = x0 + x3 | 0;
        x1 ^= u << 7 | u >>> (32 - 7);
        u = x1 + x0 | 0;
        x2 ^= u << 9 | u >>> (32 - 9);
        u = x2 + x1 | 0;
        x3 ^= u << 13 | u >>> (32 - 13);
        u = x3 + x2 | 0;
        x0 ^= u << 18 | u >>> (32 - 18);

        u = x5 + x4 | 0;
        x6 ^= u << 7 | u >>> (32 - 7);
        u = x6 + x5 | 0;
        x7 ^= u << 9 | u >>> (32 - 9);
        u = x7 + x6 | 0;
        x4 ^= u << 13 | u >>> (32 - 13);
        u = x4 + x7 | 0;
        x5 ^= u << 18 | u >>> (32 - 18);

        u = x10 + x9 | 0;
        x11 ^= u << 7 | u >>> (32 - 7);
        u = x11 + x10 | 0;
        x8 ^= u << 9 | u >>> (32 - 9);
        u = x8 + x11 | 0;
        x9 ^= u << 13 | u >>> (32 - 13);
        u = x9 + x8 | 0;
        x10 ^= u << 18 | u >>> (32 - 18);

        u = x15 + x14 | 0;
        x12 ^= u << 7 | u >>> (32 - 7);
        u = x12 + x15 | 0;
        x13 ^= u << 9 | u >>> (32 - 9);
        u = x13 + x12 | 0;
        x14 ^= u << 13 | u >>> (32 - 13);
        u = x14 + x13 | 0;
        x15 ^= u << 18 | u >>> (32 - 18);
    }

    o[0] = x0 >>> 0 & 0xff;
    o[1] = x0 >>> 8 & 0xff;
    o[2] = x0 >>> 16 & 0xff;
    o[3] = x0 >>> 24 & 0xff;

    o[4] = x5 >>> 0 & 0xff;
    o[5] = x5 >>> 8 & 0xff;
    o[6] = x5 >>> 16 & 0xff;
    o[7] = x5 >>> 24 & 0xff;

    o[8] = x10 >>> 0 & 0xff;
    o[9] = x10 >>> 8 & 0xff;
    o[10] = x10 >>> 16 & 0xff;
    o[11] = x10 >>> 24 & 0xff;

    o[12] = x15 >>> 0 & 0xff;
    o[13] = x15 >>> 8 & 0xff;
    o[14] = x15 >>> 16 & 0xff;
    o[15] = x15 >>> 24 & 0xff;

    o[16] = x6 >>> 0 & 0xff;
    o[17] = x6 >>> 8 & 0xff;
    o[18] = x6 >>> 16 & 0xff;
    o[19] = x6 >>> 24 & 0xff;

    o[20] = x7 >>> 0 & 0xff;
    o[21] = x7 >>> 8 & 0xff;
    o[22] = x7 >>> 16 & 0xff;
    o[23] = x7 >>> 24 & 0xff;

    o[24] = x8 >>> 0 & 0xff;
    o[25] = x8 >>> 8 & 0xff;
    o[26] = x8 >>> 16 & 0xff;
    o[27] = x8 >>> 24 & 0xff;

    o[28] = x9 >>> 0 & 0xff;
    o[29] = x9 >>> 8 & 0xff;
    o[30] = x9 >>> 16 & 0xff;
    o[31] = x9 >>> 24 & 0xff;
}

function crypto_core_salsa20(out, inp, k, c) {
    core_salsa20(out, inp, k, c);
}

function crypto_core_hsalsa20(out, inp, k, c) {
    core_hsalsa20(out, inp, k, c);
}

var sigma = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]);
// "expand 32-byte k"

function crypto_stream_salsa20_xor(c, cpos, m, mpos, b, n, k) {
    var z = new Uint8Array(16),
        x = new Uint8Array(64);
    var u, i;
    for (i = 0; i < 16; i++) z[i] = 0;
    for (i = 0; i < 8; i++) z[i] = n[i];
    while (b >= 64) {
        crypto_core_salsa20(x, z, k, sigma);
        for (i = 0; i < 64; i++) c[cpos + i] = m[mpos + i] ^ x[i];
        u = 1;
        for (i = 8; i < 16; i++) {
            u = u + (z[i] & 0xff) | 0;
            z[i] = u & 0xff;
            u >>>= 8;
        }
        b -= 64;
        cpos += 64;
        mpos += 64;
    }
    if (b > 0) {
        crypto_core_salsa20(x, z, k, sigma);
        for (i = 0; i < b; i++) c[cpos + i] = m[mpos + i] ^ x[i];
    }
    return 0;
}

function crypto_stream_salsa20(c, cpos, b, n, k) {
    var z = new Uint8Array(16),
        x = new Uint8Array(64);
    var u, i;
    for (i = 0; i < 16; i++) z[i] = 0;
    for (i = 0; i < 8; i++) z[i] = n[i];
    while (b >= 64) {
        crypto_core_salsa20(x, z, k, sigma);
        for (i = 0; i < 64; i++) c[cpos + i] = x[i];
        u = 1;
        for (i = 8; i < 16; i++) {
            u = u + (z[i] & 0xff) | 0;
            z[i] = u & 0xff;
            u >>>= 8;
        }
        b -= 64;
        cpos += 64;
    }
    if (b > 0) {
        crypto_core_salsa20(x, z, k, sigma);
        for (i = 0; i < b; i++) c[cpos + i] = x[i];
    }
    return 0;
}

function crypto_stream(c, cpos, d, n, k) {
    var s = new Uint8Array(32);
    crypto_core_hsalsa20(s, n, k, sigma);
    var sn = new Uint8Array(8);
    for (var i = 0; i < 8; i++) sn[i] = n[i + 16];
    return crypto_stream_salsa20(c, cpos, d, sn, s);
}

function crypto_stream_xor(c, cpos, m, mpos, d, n, k) {
    var s = new Uint8Array(32);
    crypto_core_hsalsa20(s, n, k, sigma);
    var sn = new Uint8Array(8);
    for (var i = 0; i < 8; i++) sn[i] = n[i + 16];
    return crypto_stream_salsa20_xor(c, cpos, m, mpos, d, sn, s);
}

/*
 * Port of Andrew Moon's Poly1305-donna-16. Public domain.
 * https://github.com/floodyberry/poly1305-donna
 */

var poly1305 = function(key) {
    this.buffer = new Uint8Array(16);
    this.r = new Uint16Array(10);
    this.h = new Uint16Array(10);
    this.pad = new Uint16Array(8);
    this.leftover = 0;
    this.fin = 0;

    var t0, t1, t2, t3, t4, t5, t6, t7;

    t0 = key[0] & 0xff | (key[1] & 0xff) << 8;
    this.r[0] = (t0) & 0x1fff;
    t1 = key[2] & 0xff | (key[3] & 0xff) << 8;
    this.r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
    t2 = key[4] & 0xff | (key[5] & 0xff) << 8;
    this.r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
    t3 = key[6] & 0xff | (key[7] & 0xff) << 8;
    this.r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
    t4 = key[8] & 0xff | (key[9] & 0xff) << 8;
    this.r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
    this.r[5] = ((t4 >>> 1)) & 0x1ffe;
    t5 = key[10] & 0xff | (key[11] & 0xff) << 8;
    this.r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
    t6 = key[12] & 0xff | (key[13] & 0xff) << 8;
    this.r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
    t7 = key[14] & 0xff | (key[15] & 0xff) << 8;
    this.r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
    this.r[9] = ((t7 >>> 5)) & 0x007f;

    this.pad[0] = key[16] & 0xff | (key[17] & 0xff) << 8;
    this.pad[1] = key[18] & 0xff | (key[19] & 0xff) << 8;
    this.pad[2] = key[20] & 0xff | (key[21] & 0xff) << 8;
    this.pad[3] = key[22] & 0xff | (key[23] & 0xff) << 8;
    this.pad[4] = key[24] & 0xff | (key[25] & 0xff) << 8;
    this.pad[5] = key[26] & 0xff | (key[27] & 0xff) << 8;
    this.pad[6] = key[28] & 0xff | (key[29] & 0xff) << 8;
    this.pad[7] = key[30] & 0xff | (key[31] & 0xff) << 8;
};

poly1305.prototype.blocks = function(m, mpos, bytes) {
    var hibit = this.fin ? 0 : (1 << 11);
    var t0, t1, t2, t3, t4, t5, t6, t7, c;
    var d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;

    var h0 = this.h[0],
        h1 = this.h[1],
        h2 = this.h[2],
        h3 = this.h[3],
        h4 = this.h[4],
        h5 = this.h[5],
        h6 = this.h[6],
        h7 = this.h[7],
        h8 = this.h[8],
        h9 = this.h[9];

    var r0 = this.r[0],
        r1 = this.r[1],
        r2 = this.r[2],
        r3 = this.r[3],
        r4 = this.r[4],
        r5 = this.r[5],
        r6 = this.r[6],
        r7 = this.r[7],
        r8 = this.r[8],
        r9 = this.r[9];

    while (bytes >= 16) {
        t0 = m[mpos + 0] & 0xff | (m[mpos + 1] & 0xff) << 8;
        h0 += (t0) & 0x1fff;
        t1 = m[mpos + 2] & 0xff | (m[mpos + 3] & 0xff) << 8;
        h1 += ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
        t2 = m[mpos + 4] & 0xff | (m[mpos + 5] & 0xff) << 8;
        h2 += ((t1 >>> 10) | (t2 << 6)) & 0x1fff;
        t3 = m[mpos + 6] & 0xff | (m[mpos + 7] & 0xff) << 8;
        h3 += ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
        t4 = m[mpos + 8] & 0xff | (m[mpos + 9] & 0xff) << 8;
        h4 += ((t3 >>> 4) | (t4 << 12)) & 0x1fff;
        h5 += ((t4 >>> 1)) & 0x1fff;
        t5 = m[mpos + 10] & 0xff | (m[mpos + 11] & 0xff) << 8;
        h6 += ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
        t6 = m[mpos + 12] & 0xff | (m[mpos + 13] & 0xff) << 8;
        h7 += ((t5 >>> 11) | (t6 << 5)) & 0x1fff;
        t7 = m[mpos + 14] & 0xff | (m[mpos + 15] & 0xff) << 8;
        h8 += ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
        h9 += ((t7 >>> 5)) | hibit;

        c = 0;

        d0 = c;
        d0 += h0 * r0;
        d0 += h1 * (5 * r9);
        d0 += h2 * (5 * r8);
        d0 += h3 * (5 * r7);
        d0 += h4 * (5 * r6);
        c = (d0 >>> 13);
        d0 &= 0x1fff;
        d0 += h5 * (5 * r5);
        d0 += h6 * (5 * r4);
        d0 += h7 * (5 * r3);
        d0 += h8 * (5 * r2);
        d0 += h9 * (5 * r1);
        c += (d0 >>> 13);
        d0 &= 0x1fff;

        d1 = c;
        d1 += h0 * r1;
        d1 += h1 * r0;
        d1 += h2 * (5 * r9);
        d1 += h3 * (5 * r8);
        d1 += h4 * (5 * r7);
        c = (d1 >>> 13);
        d1 &= 0x1fff;
        d1 += h5 * (5 * r6);
        d1 += h6 * (5 * r5);
        d1 += h7 * (5 * r4);
        d1 += h8 * (5 * r3);
        d1 += h9 * (5 * r2);
        c += (d1 >>> 13);
        d1 &= 0x1fff;

        d2 = c;
        d2 += h0 * r2;
        d2 += h1 * r1;
        d2 += h2 * r0;
        d2 += h3 * (5 * r9);
        d2 += h4 * (5 * r8);
        c = (d2 >>> 13);
        d2 &= 0x1fff;
        d2 += h5 * (5 * r7);
        d2 += h6 * (5 * r6);
        d2 += h7 * (5 * r5);
        d2 += h8 * (5 * r4);
        d2 += h9 * (5 * r3);
        c += (d2 >>> 13);
        d2 &= 0x1fff;

        d3 = c;
        d3 += h0 * r3;
        d3 += h1 * r2;
        d3 += h2 * r1;
        d3 += h3 * r0;
        d3 += h4 * (5 * r9);
        c = (d3 >>> 13);
        d3 &= 0x1fff;
        d3 += h5 * (5 * r8);
        d3 += h6 * (5 * r7);
        d3 += h7 * (5 * r6);
        d3 += h8 * (5 * r5);
        d3 += h9 * (5 * r4);
        c += (d3 >>> 13);
        d3 &= 0x1fff;

        d4 = c;
        d4 += h0 * r4;
        d4 += h1 * r3;
        d4 += h2 * r2;
        d4 += h3 * r1;
        d4 += h4 * r0;
        c = (d4 >>> 13);
        d4 &= 0x1fff;
        d4 += h5 * (5 * r9);
        d4 += h6 * (5 * r8);
        d4 += h7 * (5 * r7);
        d4 += h8 * (5 * r6);
        d4 += h9 * (5 * r5);
        c += (d4 >>> 13);
        d4 &= 0x1fff;

        d5 = c;
        d5 += h0 * r5;
        d5 += h1 * r4;
        d5 += h2 * r3;
        d5 += h3 * r2;
        d5 += h4 * r1;
        c = (d5 >>> 13);
        d5 &= 0x1fff;
        d5 += h5 * r0;
        d5 += h6 * (5 * r9);
        d5 += h7 * (5 * r8);
        d5 += h8 * (5 * r7);
        d5 += h9 * (5 * r6);
        c += (d5 >>> 13);
        d5 &= 0x1fff;

        d6 = c;
        d6 += h0 * r6;
        d6 += h1 * r5;
        d6 += h2 * r4;
        d6 += h3 * r3;
        d6 += h4 * r2;
        c = (d6 >>> 13);
        d6 &= 0x1fff;
        d6 += h5 * r1;
        d6 += h6 * r0;
        d6 += h7 * (5 * r9);
        d6 += h8 * (5 * r8);
        d6 += h9 * (5 * r7);
        c += (d6 >>> 13);
        d6 &= 0x1fff;

        d7 = c;
        d7 += h0 * r7;
        d7 += h1 * r6;
        d7 += h2 * r5;
        d7 += h3 * r4;
        d7 += h4 * r3;
        c = (d7 >>> 13);
        d7 &= 0x1fff;
        d7 += h5 * r2;
        d7 += h6 * r1;
        d7 += h7 * r0;
        d7 += h8 * (5 * r9);
        d7 += h9 * (5 * r8);
        c += (d7 >>> 13);
        d7 &= 0x1fff;

        d8 = c;
        d8 += h0 * r8;
        d8 += h1 * r7;
        d8 += h2 * r6;
        d8 += h3 * r5;
        d8 += h4 * r4;
        c = (d8 >>> 13);
        d8 &= 0x1fff;
        d8 += h5 * r3;
        d8 += h6 * r2;
        d8 += h7 * r1;
        d8 += h8 * r0;
        d8 += h9 * (5 * r9);
        c += (d8 >>> 13);
        d8 &= 0x1fff;

        d9 = c;
        d9 += h0 * r9;
        d9 += h1 * r8;
        d9 += h2 * r7;
        d9 += h3 * r6;
        d9 += h4 * r5;
        c = (d9 >>> 13);
        d9 &= 0x1fff;
        d9 += h5 * r4;
        d9 += h6 * r3;
        d9 += h7 * r2;
        d9 += h8 * r1;
        d9 += h9 * r0;
        c += (d9 >>> 13);
        d9 &= 0x1fff;

        c = (((c << 2) + c)) | 0;
        c = (c + d0) | 0;
        d0 = c & 0x1fff;
        c = (c >>> 13);
        d1 += c;

        h0 = d0;
        h1 = d1;
        h2 = d2;
        h3 = d3;
        h4 = d4;
        h5 = d5;
        h6 = d6;
        h7 = d7;
        h8 = d8;
        h9 = d9;

        mpos += 16;
        bytes -= 16;
    }
    this.h[0] = h0;
    this.h[1] = h1;
    this.h[2] = h2;
    this.h[3] = h3;
    this.h[4] = h4;
    this.h[5] = h5;
    this.h[6] = h6;
    this.h[7] = h7;
    this.h[8] = h8;
    this.h[9] = h9;
};

poly1305.prototype.finish = function(mac, macpos) {
    var g = new Uint16Array(10);
    var c, mask, f, i;

    if (this.leftover) {
        i = this.leftover;
        this.buffer[i++] = 1;
        for (; i < 16; i++) this.buffer[i] = 0;
        this.fin = 1;
        this.blocks(this.buffer, 0, 16);
    }

    c = this.h[1] >>> 13;
    this.h[1] &= 0x1fff;
    for (i = 2; i < 10; i++) {
        this.h[i] += c;
        c = this.h[i] >>> 13;
        this.h[i] &= 0x1fff;
    }
    this.h[0] += (c * 5);
    c = this.h[0] >>> 13;
    this.h[0] &= 0x1fff;
    this.h[1] += c;
    c = this.h[1] >>> 13;
    this.h[1] &= 0x1fff;
    this.h[2] += c;

    g[0] = this.h[0] + 5;
    c = g[0] >>> 13;
    g[0] &= 0x1fff;
    for (i = 1; i < 10; i++) {
        g[i] = this.h[i] + c;
        c = g[i] >>> 13;
        g[i] &= 0x1fff;
    }
    g[9] -= (1 << 13);

    mask = (c ^ 1) - 1;
    for (i = 0; i < 10; i++) g[i] &= mask;
    mask = ~mask;
    for (i = 0; i < 10; i++) this.h[i] = (this.h[i] & mask) | g[i];

    this.h[0] = ((this.h[0]) | (this.h[1] << 13)) & 0xffff;
    this.h[1] = ((this.h[1] >>> 3) | (this.h[2] << 10)) & 0xffff;
    this.h[2] = ((this.h[2] >>> 6) | (this.h[3] << 7)) & 0xffff;
    this.h[3] = ((this.h[3] >>> 9) | (this.h[4] << 4)) & 0xffff;
    this.h[4] = ((this.h[4] >>> 12) | (this.h[5] << 1) | (this.h[6] << 14)) & 0xffff;
    this.h[5] = ((this.h[6] >>> 2) | (this.h[7] << 11)) & 0xffff;
    this.h[6] = ((this.h[7] >>> 5) | (this.h[8] << 8)) & 0xffff;
    this.h[7] = ((this.h[8] >>> 8) | (this.h[9] << 5)) & 0xffff;

    f = this.h[0] + this.pad[0];
    this.h[0] = f & 0xffff;
    for (i = 1; i < 8; i++) {
        f = (((this.h[i] + this.pad[i]) | 0) + (f >>> 16)) | 0;
        this.h[i] = f & 0xffff;
    }

    mac[macpos + 0] = (this.h[0] >>> 0) & 0xff;
    mac[macpos + 1] = (this.h[0] >>> 8) & 0xff;
    mac[macpos + 2] = (this.h[1] >>> 0) & 0xff;
    mac[macpos + 3] = (this.h[1] >>> 8) & 0xff;
    mac[macpos + 4] = (this.h[2] >>> 0) & 0xff;
    mac[macpos + 5] = (this.h[2] >>> 8) & 0xff;
    mac[macpos + 6] = (this.h[3] >>> 0) & 0xff;
    mac[macpos + 7] = (this.h[3] >>> 8) & 0xff;
    mac[macpos + 8] = (this.h[4] >>> 0) & 0xff;
    mac[macpos + 9] = (this.h[4] >>> 8) & 0xff;
    mac[macpos + 10] = (this.h[5] >>> 0) & 0xff;
    mac[macpos + 11] = (this.h[5] >>> 8) & 0xff;
    mac[macpos + 12] = (this.h[6] >>> 0) & 0xff;
    mac[macpos + 13] = (this.h[6] >>> 8) & 0xff;
    mac[macpos + 14] = (this.h[7] >>> 0) & 0xff;
    mac[macpos + 15] = (this.h[7] >>> 8) & 0xff;
};

poly1305.prototype.update = function(m, mpos, bytes) {
    var i, want;

    if (this.leftover) {
        want = (16 - this.leftover);
        if (want > bytes)
            want = bytes;
        for (i = 0; i < want; i++)
            this.buffer[this.leftover + i] = m[mpos + i];
        bytes -= want;
        mpos += want;
        this.leftover += want;
        if (this.leftover < 16)
            return;
        this.blocks(this.buffer, 0, 16);
        this.leftover = 0;
    }

    if (bytes >= 16) {
        want = bytes - (bytes % 16);
        this.blocks(m, mpos, want);
        mpos += want;
        bytes -= want;
    }

    if (bytes) {
        for (i = 0; i < bytes; i++)
            this.buffer[this.leftover + i] = m[mpos + i];
        this.leftover += bytes;
    }
};

function crypto_onetimeauth(out, outpos, m, mpos, n, k) {
    var s = new poly1305(k);
    s.update(m, mpos, n);
    s.finish(out, outpos);
    return 0;
}

function crypto_onetimeauth_verify(h, hpos, m, mpos, n, k) {
    var x = new Uint8Array(16);
    crypto_onetimeauth(x, 0, m, mpos, n, k);
    return crypto_verify_16(h, hpos, x, 0);
}

function crypto_secretbox(c, m, d, n, k) {
    var i;
    if (d < 32) return -1;
    crypto_stream_xor(c, 0, m, 0, d, n, k);
    crypto_onetimeauth(c, 16, c, 32, d - 32, c);
    for (i = 0; i < 16; i++) c[i] = 0;
    return 0;
}

function crypto_secretbox_open(m, c, d, n, k) {
    var i;
    var x = new Uint8Array(32);
    if (d < 32) return -1;
    crypto_stream(x, 0, 32, n, k);
    if (crypto_onetimeauth_verify(c, 16, c, 32, d - 32, x) !== 0) return -1;
    crypto_stream_xor(m, 0, c, 0, d, n, k);
    for (i = 0; i < 32; i++) m[i] = 0;
    return 0;
}

function set25519(r, a) {
    var i;
    for (i = 0; i < 16; i++) r[i] = a[i] | 0;
}

function car25519(o) {
    var i, v, c = 1;
    for (i = 0; i < 16; i++) {
        v = o[i] + c + 65535;
        c = Math.floor(v / 65536);
        o[i] = v - c * 65536;
    }
    o[0] += c - 1 + 37 * (c - 1);
}

function sel25519(p, q, b) {
    var t, c = ~(b - 1);
    for (var i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

function pack25519(o, n) {
    var i, j, b;
    var m = gf(),
        t = gf();
    for (i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i] = t[i] & 0xff;
        o[2 * i + 1] = t[i] >> 8;
    }
}

function neq25519(a, b) {
    var c = new Uint8Array(32),
        d = new Uint8Array(32);
    pack25519(c, a);
    pack25519(d, b);
    return crypto_verify_32(c, 0, d, 0);
}

function par25519(a) {
    var d = new Uint8Array(32);
    pack25519(d, a);
    return d[0] & 1;
}

function unpack25519(o, n) {
    var i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

function A(o, a, b) {
    for (var i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

function Z(o, a, b) {
    for (var i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

function M(o, a, b) {
    var v, c,
        t0 = 0,
        t1 = 0,
        t2 = 0,
        t3 = 0,
        t4 = 0,
        t5 = 0,
        t6 = 0,
        t7 = 0,
        t8 = 0,
        t9 = 0,
        t10 = 0,
        t11 = 0,
        t12 = 0,
        t13 = 0,
        t14 = 0,
        t15 = 0,
        t16 = 0,
        t17 = 0,
        t18 = 0,
        t19 = 0,
        t20 = 0,
        t21 = 0,
        t22 = 0,
        t23 = 0,
        t24 = 0,
        t25 = 0,
        t26 = 0,
        t27 = 0,
        t28 = 0,
        t29 = 0,
        t30 = 0,
        b0 = b[0],
        b1 = b[1],
        b2 = b[2],
        b3 = b[3],
        b4 = b[4],
        b5 = b[5],
        b6 = b[6],
        b7 = b[7],
        b8 = b[8],
        b9 = b[9],
        b10 = b[10],
        b11 = b[11],
        b12 = b[12],
        b13 = b[13],
        b14 = b[14],
        b15 = b[15];

    v = a[0];
    t0 += v * b0;
    t1 += v * b1;
    t2 += v * b2;
    t3 += v * b3;
    t4 += v * b4;
    t5 += v * b5;
    t6 += v * b6;
    t7 += v * b7;
    t8 += v * b8;
    t9 += v * b9;
    t10 += v * b10;
    t11 += v * b11;
    t12 += v * b12;
    t13 += v * b13;
    t14 += v * b14;
    t15 += v * b15;
    v = a[1];
    t1 += v * b0;
    t2 += v * b1;
    t3 += v * b2;
    t4 += v * b3;
    t5 += v * b4;
    t6 += v * b5;
    t7 += v * b6;
    t8 += v * b7;
    t9 += v * b8;
    t10 += v * b9;
    t11 += v * b10;
    t12 += v * b11;
    t13 += v * b12;
    t14 += v * b13;
    t15 += v * b14;
    t16 += v * b15;
    v = a[2];
    t2 += v * b0;
    t3 += v * b1;
    t4 += v * b2;
    t5 += v * b3;
    t6 += v * b4;
    t7 += v * b5;
    t8 += v * b6;
    t9 += v * b7;
    t10 += v * b8;
    t11 += v * b9;
    t12 += v * b10;
    t13 += v * b11;
    t14 += v * b12;
    t15 += v * b13;
    t16 += v * b14;
    t17 += v * b15;
    v = a[3];
    t3 += v * b0;
    t4 += v * b1;
    t5 += v * b2;
    t6 += v * b3;
    t7 += v * b4;
    t8 += v * b5;
    t9 += v * b6;
    t10 += v * b7;
    t11 += v * b8;
    t12 += v * b9;
    t13 += v * b10;
    t14 += v * b11;
    t15 += v * b12;
    t16 += v * b13;
    t17 += v * b14;
    t18 += v * b15;
    v = a[4];
    t4 += v * b0;
    t5 += v * b1;
    t6 += v * b2;
    t7 += v * b3;
    t8 += v * b4;
    t9 += v * b5;
    t10 += v * b6;
    t11 += v * b7;
    t12 += v * b8;
    t13 += v * b9;
    t14 += v * b10;
    t15 += v * b11;
    t16 += v * b12;
    t17 += v * b13;
    t18 += v * b14;
    t19 += v * b15;
    v = a[5];
    t5 += v * b0;
    t6 += v * b1;
    t7 += v * b2;
    t8 += v * b3;
    t9 += v * b4;
    t10 += v * b5;
    t11 += v * b6;
    t12 += v * b7;
    t13 += v * b8;
    t14 += v * b9;
    t15 += v * b10;
    t16 += v * b11;
    t17 += v * b12;
    t18 += v * b13;
    t19 += v * b14;
    t20 += v * b15;
    v = a[6];
    t6 += v * b0;
    t7 += v * b1;
    t8 += v * b2;
    t9 += v * b3;
    t10 += v * b4;
    t11 += v * b5;
    t12 += v * b6;
    t13 += v * b7;
    t14 += v * b8;
    t15 += v * b9;
    t16 += v * b10;
    t17 += v * b11;
    t18 += v * b12;
    t19 += v * b13;
    t20 += v * b14;
    t21 += v * b15;
    v = a[7];
    t7 += v * b0;
    t8 += v * b1;
    t9 += v * b2;
    t10 += v * b3;
    t11 += v * b4;
    t12 += v * b5;
    t13 += v * b6;
    t14 += v * b7;
    t15 += v * b8;
    t16 += v * b9;
    t17 += v * b10;
    t18 += v * b11;
    t19 += v * b12;
    t20 += v * b13;
    t21 += v * b14;
    t22 += v * b15;
    v = a[8];
    t8 += v * b0;
    t9 += v * b1;
    t10 += v * b2;
    t11 += v * b3;
    t12 += v * b4;
    t13 += v * b5;
    t14 += v * b6;
    t15 += v * b7;
    t16 += v * b8;
    t17 += v * b9;
    t18 += v * b10;
    t19 += v * b11;
    t20 += v * b12;
    t21 += v * b13;
    t22 += v * b14;
    t23 += v * b15;
    v = a[9];
    t9 += v * b0;
    t10 += v * b1;
    t11 += v * b2;
    t12 += v * b3;
    t13 += v * b4;
    t14 += v * b5;
    t15 += v * b6;
    t16 += v * b7;
    t17 += v * b8;
    t18 += v * b9;
    t19 += v * b10;
    t20 += v * b11;
    t21 += v * b12;
    t22 += v * b13;
    t23 += v * b14;
    t24 += v * b15;
    v = a[10];
    t10 += v * b0;
    t11 += v * b1;
    t12 += v * b2;
    t13 += v * b3;
    t14 += v * b4;
    t15 += v * b5;
    t16 += v * b6;
    t17 += v * b7;
    t18 += v * b8;
    t19 += v * b9;
    t20 += v * b10;
    t21 += v * b11;
    t22 += v * b12;
    t23 += v * b13;
    t24 += v * b14;
    t25 += v * b15;
    v = a[11];
    t11 += v * b0;
    t12 += v * b1;
    t13 += v * b2;
    t14 += v * b3;
    t15 += v * b4;
    t16 += v * b5;
    t17 += v * b6;
    t18 += v * b7;
    t19 += v * b8;
    t20 += v * b9;
    t21 += v * b10;
    t22 += v * b11;
    t23 += v * b12;
    t24 += v * b13;
    t25 += v * b14;
    t26 += v * b15;
    v = a[12];
    t12 += v * b0;
    t13 += v * b1;
    t14 += v * b2;
    t15 += v * b3;
    t16 += v * b4;
    t17 += v * b5;
    t18 += v * b6;
    t19 += v * b7;
    t20 += v * b8;
    t21 += v * b9;
    t22 += v * b10;
    t23 += v * b11;
    t24 += v * b12;
    t25 += v * b13;
    t26 += v * b14;
    t27 += v * b15;
    v = a[13];
    t13 += v * b0;
    t14 += v * b1;
    t15 += v * b2;
    t16 += v * b3;
    t17 += v * b4;
    t18 += v * b5;
    t19 += v * b6;
    t20 += v * b7;
    t21 += v * b8;
    t22 += v * b9;
    t23 += v * b10;
    t24 += v * b11;
    t25 += v * b12;
    t26 += v * b13;
    t27 += v * b14;
    t28 += v * b15;
    v = a[14];
    t14 += v * b0;
    t15 += v * b1;
    t16 += v * b2;
    t17 += v * b3;
    t18 += v * b4;
    t19 += v * b5;
    t20 += v * b6;
    t21 += v * b7;
    t22 += v * b8;
    t23 += v * b9;
    t24 += v * b10;
    t25 += v * b11;
    t26 += v * b12;
    t27 += v * b13;
    t28 += v * b14;
    t29 += v * b15;
    v = a[15];
    t15 += v * b0;
    t16 += v * b1;
    t17 += v * b2;
    t18 += v * b3;
    t19 += v * b4;
    t20 += v * b5;
    t21 += v * b6;
    t22 += v * b7;
    t23 += v * b8;
    t24 += v * b9;
    t25 += v * b10;
    t26 += v * b11;
    t27 += v * b12;
    t28 += v * b13;
    t29 += v * b14;
    t30 += v * b15;

    t0 += 38 * t16;
    t1 += 38 * t17;
    t2 += 38 * t18;
    t3 += 38 * t19;
    t4 += 38 * t20;
    t5 += 38 * t21;
    t6 += 38 * t22;
    t7 += 38 * t23;
    t8 += 38 * t24;
    t9 += 38 * t25;
    t10 += 38 * t26;
    t11 += 38 * t27;
    t12 += 38 * t28;
    t13 += 38 * t29;
    t14 += 38 * t30;
    // t15 left as is

    // first car
    c = 1;
    v = t0 + c + 65535;
    c = Math.floor(v / 65536);
    t0 = v - c * 65536;
    v = t1 + c + 65535;
    c = Math.floor(v / 65536);
    t1 = v - c * 65536;
    v = t2 + c + 65535;
    c = Math.floor(v / 65536);
    t2 = v - c * 65536;
    v = t3 + c + 65535;
    c = Math.floor(v / 65536);
    t3 = v - c * 65536;
    v = t4 + c + 65535;
    c = Math.floor(v / 65536);
    t4 = v - c * 65536;
    v = t5 + c + 65535;
    c = Math.floor(v / 65536);
    t5 = v - c * 65536;
    v = t6 + c + 65535;
    c = Math.floor(v / 65536);
    t6 = v - c * 65536;
    v = t7 + c + 65535;
    c = Math.floor(v / 65536);
    t7 = v - c * 65536;
    v = t8 + c + 65535;
    c = Math.floor(v / 65536);
    t8 = v - c * 65536;
    v = t9 + c + 65535;
    c = Math.floor(v / 65536);
    t9 = v - c * 65536;
    v = t10 + c + 65535;
    c = Math.floor(v / 65536);
    t10 = v - c * 65536;
    v = t11 + c + 65535;
    c = Math.floor(v / 65536);
    t11 = v - c * 65536;
    v = t12 + c + 65535;
    c = Math.floor(v / 65536);
    t12 = v - c * 65536;
    v = t13 + c + 65535;
    c = Math.floor(v / 65536);
    t13 = v - c * 65536;
    v = t14 + c + 65535;
    c = Math.floor(v / 65536);
    t14 = v - c * 65536;
    v = t15 + c + 65535;
    c = Math.floor(v / 65536);
    t15 = v - c * 65536;
    t0 += c - 1 + 37 * (c - 1);

    // second car
    c = 1;
    v = t0 + c + 65535;
    c = Math.floor(v / 65536);
    t0 = v - c * 65536;
    v = t1 + c + 65535;
    c = Math.floor(v / 65536);
    t1 = v - c * 65536;
    v = t2 + c + 65535;
    c = Math.floor(v / 65536);
    t2 = v - c * 65536;
    v = t3 + c + 65535;
    c = Math.floor(v / 65536);
    t3 = v - c * 65536;
    v = t4 + c + 65535;
    c = Math.floor(v / 65536);
    t4 = v - c * 65536;
    v = t5 + c + 65535;
    c = Math.floor(v / 65536);
    t5 = v - c * 65536;
    v = t6 + c + 65535;
    c = Math.floor(v / 65536);
    t6 = v - c * 65536;
    v = t7 + c + 65535;
    c = Math.floor(v / 65536);
    t7 = v - c * 65536;
    v = t8 + c + 65535;
    c = Math.floor(v / 65536);
    t8 = v - c * 65536;
    v = t9 + c + 65535;
    c = Math.floor(v / 65536);
    t9 = v - c * 65536;
    v = t10 + c + 65535;
    c = Math.floor(v / 65536);
    t10 = v - c * 65536;
    v = t11 + c + 65535;
    c = Math.floor(v / 65536);
    t11 = v - c * 65536;
    v = t12 + c + 65535;
    c = Math.floor(v / 65536);
    t12 = v - c * 65536;
    v = t13 + c + 65535;
    c = Math.floor(v / 65536);
    t13 = v - c * 65536;
    v = t14 + c + 65535;
    c = Math.floor(v / 65536);
    t14 = v - c * 65536;
    v = t15 + c + 65535;
    c = Math.floor(v / 65536);
    t15 = v - c * 65536;
    t0 += c - 1 + 37 * (c - 1);

    o[0] = t0;
    o[1] = t1;
    o[2] = t2;
    o[3] = t3;
    o[4] = t4;
    o[5] = t5;
    o[6] = t6;
    o[7] = t7;
    o[8] = t8;
    o[9] = t9;
    o[10] = t10;
    o[11] = t11;
    o[12] = t12;
    o[13] = t13;
    o[14] = t14;
    o[15] = t15;
}

function S(o, a) {
    M(o, a, a);
}

function inv25519(o, i) {
    var c = gf();
    var a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        S(c, c);
        if (a !== 2 && a !== 4) M(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
}

function pow2523(o, i) {
    var c = gf();
    var a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 250; a >= 0; a--) {
        S(c, c);
        if (a !== 1) M(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
}

function crypto_scalarmult(q, n, p) {
    var z = new Uint8Array(32);
    var x = new Float64Array(80),
        r, i;
    var a = gf(),
        b = gf(),
        c = gf(),
        d = gf(),
        e = gf(),
        f = gf();
    for (i = 0; i < 31; i++) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;
    unpack25519(x, p);
    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
        r = (z[i >>> 3] >>> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, _121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    for (i = 0; i < 16; i++) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    var x32 = x.subarray(32);
    var x16 = x.subarray(16);
    inv25519(x32, x32);
    M(x16, x16, x32);
    pack25519(q, x16);
    return 0;
}

function crypto_scalarmult_base(q, n) {
    return crypto_scalarmult(q, n, _9);
}

function crypto_box_keypair(y, x) {
    randombytes(x, 32);
    return crypto_scalarmult_base(y, x);
}

function crypto_box_beforenm(k, y, x) {
    var s = new Uint8Array(32);
    crypto_scalarmult(s, x, y);
    return crypto_core_hsalsa20(k, _0, s, sigma);
}

var crypto_box_afternm = crypto_secretbox;
var crypto_box_open_afternm = crypto_secretbox_open;

function crypto_box(c, m, d, n, y, x) {
    var k = new Uint8Array(32);
    crypto_box_beforenm(k, y, x);
    return crypto_box_afternm(c, m, d, n, k);
}

function crypto_box_open(m, c, d, n, y, x) {
    var k = new Uint8Array(32);
    crypto_box_beforenm(k, y, x);
    return crypto_box_open_afternm(m, c, d, n, k);
}

var K = [
    0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
    0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
    0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
    0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
    0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
    0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
    0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
    0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
    0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
    0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
    0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
    0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
    0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
    0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
    0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
    0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
    0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
    0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
    0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
    0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
    0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
    0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
    0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
    0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
    0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
    0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
    0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
    0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
    0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
    0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
    0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
    0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
    0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
    0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
    0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
    0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
    0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
    0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
    0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
    0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
];

function crypto_hashblocks_hl(hh, hl, m, n) {
    var wh = new Int32Array(16),
        wl = new Int32Array(16),
        bh0, bh1, bh2, bh3, bh4, bh5, bh6, bh7,
        bl0, bl1, bl2, bl3, bl4, bl5, bl6, bl7,
        th, tl, i, j, h, l, a, b, c, d;

    var ah0 = hh[0],
        ah1 = hh[1],
        ah2 = hh[2],
        ah3 = hh[3],
        ah4 = hh[4],
        ah5 = hh[5],
        ah6 = hh[6],
        ah7 = hh[7],

        al0 = hl[0],
        al1 = hl[1],
        al2 = hl[2],
        al3 = hl[3],
        al4 = hl[4],
        al5 = hl[5],
        al6 = hl[6],
        al7 = hl[7];

    var pos = 0;
    while (n >= 128) {
        for (i = 0; i < 16; i++) {
            j = 8 * i + pos;
            wh[i] = (m[j + 0] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3];
            wl[i] = (m[j + 4] << 24) | (m[j + 5] << 16) | (m[j + 6] << 8) | m[j + 7];
        }
        for (i = 0; i < 80; i++) {
            bh0 = ah0;
            bh1 = ah1;
            bh2 = ah2;
            bh3 = ah3;
            bh4 = ah4;
            bh5 = ah5;
            bh6 = ah6;
            bh7 = ah7;

            bl0 = al0;
            bl1 = al1;
            bl2 = al2;
            bl3 = al3;
            bl4 = al4;
            bl5 = al5;
            bl6 = al6;
            bl7 = al7;

            // add
            h = ah7;
            l = al7;

            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;

            // Sigma1
            h = ((ah4 >>> 14) | (al4 << (32 - 14))) ^ ((ah4 >>> 18) | (al4 << (32 - 18))) ^ ((al4 >>> (41 - 32)) | (ah4 << (32 - (41 - 32))));
            l = ((al4 >>> 14) | (ah4 << (32 - 14))) ^ ((al4 >>> 18) | (ah4 << (32 - 18))) ^ ((ah4 >>> (41 - 32)) | (al4 << (32 - (41 - 32))));

            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;

            // Ch
            h = (ah4 & ah5) ^ (~ah4 & ah6);
            l = (al4 & al5) ^ (~al4 & al6);

            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;

            // K
            h = K[i * 2];
            l = K[i * 2 + 1];

            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;

            // w
            h = wh[i % 16];
            l = wl[i % 16];

            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            th = c & 0xffff | d << 16;
            tl = a & 0xffff | b << 16;

            // add
            h = th;
            l = tl;

            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;

            // Sigma0
            h = ((ah0 >>> 28) | (al0 << (32 - 28))) ^ ((al0 >>> (34 - 32)) | (ah0 << (32 - (34 - 32)))) ^ ((al0 >>> (39 - 32)) | (ah0 << (32 - (39 - 32))));
            l = ((al0 >>> 28) | (ah0 << (32 - 28))) ^ ((ah0 >>> (34 - 32)) | (al0 << (32 - (34 - 32)))) ^ ((ah0 >>> (39 - 32)) | (al0 << (32 - (39 - 32))));

            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;

            // Maj
            h = (ah0 & ah1) ^ (ah0 & ah2) ^ (ah1 & ah2);
            l = (al0 & al1) ^ (al0 & al2) ^ (al1 & al2);

            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            bh7 = (c & 0xffff) | (d << 16);
            bl7 = (a & 0xffff) | (b << 16);

            // add
            h = bh3;
            l = bl3;

            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;

            h = th;
            l = tl;

            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            bh3 = (c & 0xffff) | (d << 16);
            bl3 = (a & 0xffff) | (b << 16);

            ah1 = bh0;
            ah2 = bh1;
            ah3 = bh2;
            ah4 = bh3;
            ah5 = bh4;
            ah6 = bh5;
            ah7 = bh6;
            ah0 = bh7;

            al1 = bl0;
            al2 = bl1;
            al3 = bl2;
            al4 = bl3;
            al5 = bl4;
            al6 = bl5;
            al7 = bl6;
            al0 = bl7;

            if (i % 16 === 15) {
                for (j = 0; j < 16; j++) {
                    // add
                    h = wh[j];
                    l = wl[j];

                    a = l & 0xffff;
                    b = l >>> 16;
                    c = h & 0xffff;
                    d = h >>> 16;

                    h = wh[(j + 9) % 16];
                    l = wl[(j + 9) % 16];

                    a += l & 0xffff;
                    b += l >>> 16;
                    c += h & 0xffff;
                    d += h >>> 16;

                    // sigma0
                    th = wh[(j + 1) % 16];
                    tl = wl[(j + 1) % 16];
                    h = ((th >>> 1) | (tl << (32 - 1))) ^ ((th >>> 8) | (tl << (32 - 8))) ^ (th >>> 7);
                    l = ((tl >>> 1) | (th << (32 - 1))) ^ ((tl >>> 8) | (th << (32 - 8))) ^ ((tl >>> 7) | (th << (32 - 7)));

                    a += l & 0xffff;
                    b += l >>> 16;
                    c += h & 0xffff;
                    d += h >>> 16;

                    // sigma1
                    th = wh[(j + 14) % 16];
                    tl = wl[(j + 14) % 16];
                    h = ((th >>> 19) | (tl << (32 - 19))) ^ ((tl >>> (61 - 32)) | (th << (32 - (61 - 32)))) ^ (th >>> 6);
                    l = ((tl >>> 19) | (th << (32 - 19))) ^ ((th >>> (61 - 32)) | (tl << (32 - (61 - 32)))) ^ ((tl >>> 6) | (th << (32 - 6)));

                    a += l & 0xffff;
                    b += l >>> 16;
                    c += h & 0xffff;
                    d += h >>> 16;

                    b += a >>> 16;
                    c += b >>> 16;
                    d += c >>> 16;

                    wh[j] = (c & 0xffff) | (d << 16);
                    wl[j] = (a & 0xffff) | (b << 16);
                }
            }
        }

        // add
        h = ah0;
        l = al0;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        h = hh[0];
        l = hl[0];

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        hh[0] = ah0 = (c & 0xffff) | (d << 16);
        hl[0] = al0 = (a & 0xffff) | (b << 16);

        h = ah1;
        l = al1;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        h = hh[1];
        l = hl[1];

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        hh[1] = ah1 = (c & 0xffff) | (d << 16);
        hl[1] = al1 = (a & 0xffff) | (b << 16);

        h = ah2;
        l = al2;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        h = hh[2];
        l = hl[2];

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        hh[2] = ah2 = (c & 0xffff) | (d << 16);
        hl[2] = al2 = (a & 0xffff) | (b << 16);

        h = ah3;
        l = al3;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        h = hh[3];
        l = hl[3];

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        hh[3] = ah3 = (c & 0xffff) | (d << 16);
        hl[3] = al3 = (a & 0xffff) | (b << 16);

        h = ah4;
        l = al4;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        h = hh[4];
        l = hl[4];

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        hh[4] = ah4 = (c & 0xffff) | (d << 16);
        hl[4] = al4 = (a & 0xffff) | (b << 16);

        h = ah5;
        l = al5;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        h = hh[5];
        l = hl[5];

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        hh[5] = ah5 = (c & 0xffff) | (d << 16);
        hl[5] = al5 = (a & 0xffff) | (b << 16);

        h = ah6;
        l = al6;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        h = hh[6];
        l = hl[6];

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        hh[6] = ah6 = (c & 0xffff) | (d << 16);
        hl[6] = al6 = (a & 0xffff) | (b << 16);

        h = ah7;
        l = al7;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        h = hh[7];
        l = hl[7];

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        hh[7] = ah7 = (c & 0xffff) | (d << 16);
        hl[7] = al7 = (a & 0xffff) | (b << 16);

        pos += 128;
        n -= 128;
    }

    return n;
}

function crypto_hash(out, m, n) {
    var hh = new Int32Array(8),
        hl = new Int32Array(8),
        x = new Uint8Array(256),
        i, b = n;

    hh[0] = 0x6a09e667;
    hh[1] = 0xbb67ae85;
    hh[2] = 0x3c6ef372;
    hh[3] = 0xa54ff53a;
    hh[4] = 0x510e527f;
    hh[5] = 0x9b05688c;
    hh[6] = 0x1f83d9ab;
    hh[7] = 0x5be0cd19;

    hl[0] = 0xf3bcc908;
    hl[1] = 0x84caa73b;
    hl[2] = 0xfe94f82b;
    hl[3] = 0x5f1d36f1;
    hl[4] = 0xade682d1;
    hl[5] = 0x2b3e6c1f;
    hl[6] = 0xfb41bd6b;
    hl[7] = 0x137e2179;

    crypto_hashblocks_hl(hh, hl, m, n);
    n %= 128;

    for (i = 0; i < n; i++) x[i] = m[b - n + i];
    x[n] = 128;

    n = 256 - 128 * (n < 112 ? 1 : 0);
    x[n - 9] = 0;
    ts64(x, n - 8, (b / 0x20000000) | 0, b << 3);
    crypto_hashblocks_hl(hh, hl, x, n);

    for (i = 0; i < 8; i++) ts64(out, 8 * i, hh[i], hl[i]);

    return 0;
}

function add(p, q) {
    var a = gf(),
        b = gf(),
        c = gf(),
        d = gf(),
        e = gf(),
        f = gf(),
        g = gf(),
        h = gf(),
        t = gf();

    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);

    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

function cswap(p, q, b) {
    var i;
    for (i = 0; i < 4; i++) {
        sel25519(p[i], q[i], b);
    }
}

function pack(r, p) {
    var tx = gf(),
        ty = gf(),
        zi = gf();
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
}

function scalarmult(p, q, s) {
    var b, i;
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (i = 255; i >= 0; --i) {
        b = (s[(i / 8) | 0] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

function scalarbase(p, s) {
    var q = [gf(), gf(), gf(), gf()];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

function crypto_sign_keypair(pk, sk, seeded) {
    var d = new Uint8Array(64);
    var p = [gf(), gf(), gf(), gf()];
    var i;

    if (!seeded) randombytes(sk, 32);
    crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(p, d);
    pack(pk, p);

    for (i = 0; i < 32; i++) sk[i + 32] = pk[i];
    return 0;
}

var L = new Float64Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);

function modL(r, x) {
    var carry, i, j, k;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32, k = i - 12; j < k; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; j++) x[j] -= carry * L[j];
    for (i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = x[i] & 255;
    }
}

function reduce(r) {
    var x = new Float64Array(64),
        i;
    for (i = 0; i < 64; i++) x[i] = r[i];
    for (i = 0; i < 64; i++) r[i] = 0;
    modL(r, x);
}

// Note: difference from C - smlen returned, not passed as argument.
function crypto_sign(sm, m, n, sk) {
    var d = new Uint8Array(64),
        h = new Uint8Array(64),
        r = new Uint8Array(64);
    var i, j, x = new Float64Array(64);
    var p = [gf(), gf(), gf(), gf()];

    crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    var smlen = n + 64;
    for (i = 0; i < n; i++) sm[64 + i] = m[i];
    for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i];

    crypto_hash(r, sm.subarray(32), n + 32);
    reduce(r);
    scalarbase(p, r);
    pack(sm, p);

    for (i = 32; i < 64; i++) sm[i] = sk[i];
    crypto_hash(h, sm, n + 64);
    reduce(h);

    for (i = 0; i < 64; i++) x[i] = 0;
    for (i = 0; i < 32; i++) x[i] = r[i];
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 32; j++) {
            x[i + j] += h[i] * d[j];
        }
    }

    modL(sm.subarray(32), x);
    return smlen;
}

function unpackneg(r, p) {
    var t = gf(),
        chk = gf(),
        num = gf(),
        den = gf(),
        den2 = gf(),
        den4 = gf(),
        den6 = gf();

    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) === (p[31] >> 7)) Z(r[0], gf0, r[0]);

    M(r[3], r[0], r[1]);
    return 0;
}

function crypto_sign_open(m, sm, n, pk) {
    var i, mlen;
    var t = new Uint8Array(32),
        h = new Uint8Array(64);
    var p = [gf(), gf(), gf(), gf()],
        q = [gf(), gf(), gf(), gf()];

    mlen = -1;
    if (n < 64) return -1;

    if (unpackneg(q, pk)) return -1;

    for (i = 0; i < n; i++) m[i] = sm[i];
    for (i = 0; i < 32; i++) m[i + 32] = pk[i];
    crypto_hash(h, m, n);
    reduce(h);
    scalarmult(p, q, h);

    scalarbase(q, sm.subarray(32));
    add(p, q);
    pack(t, p);

    n -= 64;
    if (crypto_verify_32(sm, 0, t, 0)) {
        for (i = 0; i < n; i++) m[i] = 0;
        return -1;
    }

    for (i = 0; i < n; i++) m[i] = sm[i + 64];
    mlen = n;
    return mlen;
}

var crypto_secretbox_KEYBYTES = 32,
    crypto_secretbox_NONCEBYTES = 24,
    crypto_secretbox_ZEROBYTES = 32,
    crypto_secretbox_BOXZEROBYTES = 16,
    crypto_scalarmult_BYTES = 32,
    crypto_scalarmult_SCALARBYTES = 32,
    crypto_box_PUBLICKEYBYTES = 32,
    crypto_box_SECRETKEYBYTES = 32,
    crypto_box_BEFORENMBYTES = 32,
    crypto_box_NONCEBYTES = crypto_secretbox_NONCEBYTES,
    crypto_box_ZEROBYTES = crypto_secretbox_ZEROBYTES,
    crypto_box_BOXZEROBYTES = crypto_secretbox_BOXZEROBYTES,
    crypto_sign_BYTES = 64,
    crypto_sign_PUBLICKEYBYTES = 32,
    crypto_sign_SECRETKEYBYTES = 64,
    crypto_sign_SEEDBYTES = 32,
    crypto_hash_BYTES = 64;

nacl.lowlevel = {
    crypto_core_hsalsa20: crypto_core_hsalsa20,
    crypto_stream_xor: crypto_stream_xor,
    crypto_stream: crypto_stream,
    crypto_stream_salsa20_xor: crypto_stream_salsa20_xor,
    crypto_stream_salsa20: crypto_stream_salsa20,
    crypto_onetimeauth: crypto_onetimeauth,
    crypto_onetimeauth_verify: crypto_onetimeauth_verify,
    crypto_verify_16: crypto_verify_16,
    crypto_verify_32: crypto_verify_32,
    crypto_secretbox: crypto_secretbox,
    crypto_secretbox_open: crypto_secretbox_open,
    crypto_scalarmult: crypto_scalarmult,
    crypto_scalarmult_base: crypto_scalarmult_base,
    crypto_box_beforenm: crypto_box_beforenm,
    crypto_box_afternm: crypto_box_afternm,
    crypto_box: crypto_box,
    crypto_box_open: crypto_box_open,
    crypto_box_keypair: crypto_box_keypair,
    crypto_hash: crypto_hash,
    crypto_sign: crypto_sign,
    crypto_sign_keypair: crypto_sign_keypair,
    crypto_sign_open: crypto_sign_open,

    crypto_secretbox_KEYBYTES: crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES: crypto_secretbox_NONCEBYTES,
    crypto_secretbox_ZEROBYTES: crypto_secretbox_ZEROBYTES,
    crypto_secretbox_BOXZEROBYTES: crypto_secretbox_BOXZEROBYTES,
    crypto_scalarmult_BYTES: crypto_scalarmult_BYTES,
    crypto_scalarmult_SCALARBYTES: crypto_scalarmult_SCALARBYTES,
    crypto_box_PUBLICKEYBYTES: crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES: crypto_box_SECRETKEYBYTES,
    crypto_box_BEFORENMBYTES: crypto_box_BEFORENMBYTES,
    crypto_box_NONCEBYTES: crypto_box_NONCEBYTES,
    crypto_box_ZEROBYTES: crypto_box_ZEROBYTES,
    crypto_box_BOXZEROBYTES: crypto_box_BOXZEROBYTES,
    crypto_sign_BYTES: crypto_sign_BYTES,
    crypto_sign_PUBLICKEYBYTES: crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES: crypto_sign_SECRETKEYBYTES,
    crypto_sign_SEEDBYTES: crypto_sign_SEEDBYTES,
    crypto_hash_BYTES: crypto_hash_BYTES
};

/* High-level API */

function checkLengths(k, n) {
    if (k.length !== crypto_secretbox_KEYBYTES) throw new Error('bad key size');
    if (n.length !== crypto_secretbox_NONCEBYTES) throw new Error('bad nonce size');
}

function checkBoxLengths(pk, sk) {
    if (pk.length !== crypto_box_PUBLICKEYBYTES) throw new Error('bad public key size');
    if (sk.length !== crypto_box_SECRETKEYBYTES) throw new Error('bad secret key size');
}

function checkArrayTypes() {
    for (var i = 0; i < arguments.length; i++) {
        if (!(arguments[i] instanceof Uint8Array))
            throw new TypeError('unexpected type, use Uint8Array');
    }
}

function cleanup(arr) {
    for (var i = 0; i < arr.length; i++) arr[i] = 0;
}

nacl.randomBytes = function(n) {
    var b = new Uint8Array(n);
    randombytes(b, n);
    return b;
};

nacl.secretbox = function(msg, nonce, key) {
    checkArrayTypes(msg, nonce, key);
    checkLengths(key, nonce);
    var m = new Uint8Array(crypto_secretbox_ZEROBYTES + msg.length);
    var c = new Uint8Array(m.length);
    for (var i = 0; i < msg.length; i++) m[i + crypto_secretbox_ZEROBYTES] = msg[i];
    crypto_secretbox(c, m, m.length, nonce, key);
    return c.subarray(crypto_secretbox_BOXZEROBYTES);
};

nacl.secretbox.open = function(box, nonce, key) {
    checkArrayTypes(box, nonce, key);
    checkLengths(key, nonce);
    var c = new Uint8Array(crypto_secretbox_BOXZEROBYTES + box.length);
    var m = new Uint8Array(c.length);
    for (var i = 0; i < box.length; i++) c[i + crypto_secretbox_BOXZEROBYTES] = box[i];
    if (c.length < 32) return null;
    if (crypto_secretbox_open(m, c, c.length, nonce, key) !== 0) return null;
    return m.subarray(crypto_secretbox_ZEROBYTES);
};

nacl.secretbox.keyLength = crypto_secretbox_KEYBYTES;
nacl.secretbox.nonceLength = crypto_secretbox_NONCEBYTES;
nacl.secretbox.overheadLength = crypto_secretbox_BOXZEROBYTES;

nacl.scalarMult = function(n, p) {
    checkArrayTypes(n, p);
    if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error('bad n size');
    if (p.length !== crypto_scalarmult_BYTES) throw new Error('bad p size');
    var q = new Uint8Array(crypto_scalarmult_BYTES);
    crypto_scalarmult(q, n, p);
    return q;
};

nacl.scalarMult.base = function(n) {
    checkArrayTypes(n);
    if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error('bad n size');
    var q = new Uint8Array(crypto_scalarmult_BYTES);
    crypto_scalarmult_base(q, n);
    return q;
};

nacl.scalarMult.scalarLength = crypto_scalarmult_SCALARBYTES;
nacl.scalarMult.groupElementLength = crypto_scalarmult_BYTES;

nacl.box = function(msg, nonce, publicKey, secretKey) {
    var k = nacl.box.before(publicKey, secretKey);
    return nacl.secretbox(msg, nonce, k);
};

nacl.box.before = function(publicKey, secretKey) {
    checkArrayTypes(publicKey, secretKey);
    checkBoxLengths(publicKey, secretKey);
    var k = new Uint8Array(crypto_box_BEFORENMBYTES);
    crypto_box_beforenm(k, publicKey, secretKey);
    return k;
};

nacl.box.after = nacl.secretbox;

nacl.box.open = function(msg, nonce, publicKey, secretKey) {
    var k = nacl.box.before(publicKey, secretKey);
    return nacl.secretbox.open(msg, nonce, k);
};

nacl.box.open.after = nacl.secretbox.open;

nacl.box.keyPair = function() {
    var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
    var sk = new Uint8Array(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(pk, sk);
    return { publicKey: pk, secretKey: sk };
};

nacl.box.keyPair.fromSecretKey = function(secretKey) {
    checkArrayTypes(secretKey);
    if (secretKey.length !== crypto_box_SECRETKEYBYTES)
        throw new Error('bad secret key size');
    var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
    crypto_scalarmult_base(pk, secretKey);
    return { publicKey: pk, secretKey: new Uint8Array(secretKey) };
};

nacl.box.publicKeyLength = crypto_box_PUBLICKEYBYTES;
nacl.box.secretKeyLength = crypto_box_SECRETKEYBYTES;
nacl.box.sharedKeyLength = crypto_box_BEFORENMBYTES;
nacl.box.nonceLength = crypto_box_NONCEBYTES;
nacl.box.overheadLength = nacl.secretbox.overheadLength;

nacl.sign = function(msg, secretKey) {
    checkArrayTypes(msg, secretKey);
    if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
        throw new Error('bad secret key size');
    var signedMsg = new Uint8Array(crypto_sign_BYTES + msg.length);
    crypto_sign(signedMsg, msg, msg.length, secretKey);
    return signedMsg;
};

nacl.sign.open = function(signedMsg, publicKey) {
    checkArrayTypes(signedMsg, publicKey);
    if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
        throw new Error('bad public key size');
    var tmp = new Uint8Array(signedMsg.length);
    var mlen = crypto_sign_open(tmp, signedMsg, signedMsg.length, publicKey);
    if (mlen < 0) return null;
    var m = new Uint8Array(mlen);
    for (var i = 0; i < m.length; i++) m[i] = tmp[i];
    return m;
};

nacl.sign.detached = function(msg, secretKey) {
    var signedMsg = nacl.sign(msg, secretKey);
    var sig = new Uint8Array(crypto_sign_BYTES);
    for (var i = 0; i < sig.length; i++) sig[i] = signedMsg[i];
    return sig;
};

nacl.sign.detached.verify = function(msg, sig, publicKey) {
    checkArrayTypes(msg, sig, publicKey);
    if (sig.length !== crypto_sign_BYTES)
        throw new Error('bad signature size');
    if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
        throw new Error('bad public key size');
    var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
    var m = new Uint8Array(crypto_sign_BYTES + msg.length);
    var i;
    for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
    for (i = 0; i < msg.length; i++) sm[i + crypto_sign_BYTES] = msg[i];
    return (crypto_sign_open(m, sm, sm.length, publicKey) >= 0);
};

nacl.sign.keyPair = function() {
    var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
    var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk, sk);
    return { publicKey: pk, secretKey: sk };
};

nacl.sign.keyPair.fromSecretKey = function(secretKey) {
    checkArrayTypes(secretKey);
    if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
        throw new Error('bad secret key size');
    var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
    for (var i = 0; i < pk.length; i++) pk[i] = secretKey[32 + i];
    return { publicKey: pk, secretKey: new Uint8Array(secretKey) };
};

nacl.sign.keyPair.fromSeed = function(seed) {
    checkArrayTypes(seed);
    if (seed.length !== crypto_sign_SEEDBYTES)
        throw new Error('bad seed size');
    var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
    var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
    for (var i = 0; i < 32; i++) sk[i] = seed[i];
    crypto_sign_keypair(pk, sk, true);
    return { publicKey: pk, secretKey: sk };
};

nacl.sign.publicKeyLength = crypto_sign_PUBLICKEYBYTES;
nacl.sign.secretKeyLength = crypto_sign_SECRETKEYBYTES;
nacl.sign.seedLength = crypto_sign_SEEDBYTES;
nacl.sign.signatureLength = crypto_sign_BYTES;

nacl.hash = function(msg) {
    checkArrayTypes(msg);
    var h = new Uint8Array(crypto_hash_BYTES);
    crypto_hash(h, msg, msg.length);
    return h;
};

nacl.hash.hashLength = crypto_hash_BYTES;

nacl.verify = function(x, y) {
    checkArrayTypes(x, y);
    // Zero length arguments are considered not equal.
    if (x.length === 0 || y.length === 0) return false;
    if (x.length !== y.length) return false;
    return (vn(x, 0, y, 0, x.length) === 0) ? true : false;
};

nacl.setPRNG = function(fn) {
    randombytes = fn;
};

(function() {
    // Initialize PRNG if environment provides CSPRNG.
    // If not, methods calling randombytes will throw.
    var crypto = typeof self !== 'undefined' ? (self.crypto || self.msCrypto) : null;
    if (crypto && crypto.getRandomValues) {
        // Browsers.
        var QUOTA = 65536;
        nacl.setPRNG(function(x, n) {
            var i, v = new Uint8Array(n);
            for (i = 0; i < n; i += QUOTA) {
                crypto.getRandomValues(v.subarray(i, i + Math.min(n - i, QUOTA)));
            }
            for (i = 0; i < n; i++) x[i] = v[i];
            cleanup(v);
        });
    } else if (typeof require !== 'undefined') {
        // Node.js.
        crypto = require('crypto');
        if (crypto && crypto.randomBytes) {
            nacl.setPRNG(function(x, n) {
                var i, v = crypto.randomBytes(n);
                for (i = 0; i < n; i++) x[i] = v[i];
                cleanup(v);
            });
        }
    }
})();

var Hashes;

function utf8Encode(str) {
    var x, y, output = '',
        i = -1,
        l;

    if (str && str.length) {
        l = str.length;
        while ((i += 1) < l) {
            /* Decode utf-16 surrogate pairs */
            x = str.charCodeAt(i);
            y = i + 1 < l ? str.charCodeAt(i + 1) : 0;
            if (0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF) {
                x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
                i += 1;
            }
            /* Encode output as utf-8 */
            if (x <= 0x7F) {
                output += String.fromCharCode(x);
            } else if (x <= 0x7FF) {
                output += String.fromCharCode(0xC0 | ((x >>> 6) & 0x1F),
                    0x80 | (x & 0x3F));
            } else if (x <= 0xFFFF) {
                output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                    0x80 | ((x >>> 6) & 0x3F),
                    0x80 | (x & 0x3F));
            } else if (x <= 0x1FFFFF) {
                output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                    0x80 | ((x >>> 12) & 0x3F),
                    0x80 | ((x >>> 6) & 0x3F),
                    0x80 | (x & 0x3F));
            }
        }
    }
    return output;
}

function utf8Decode(str) {
    var i, ac, c1, c2, c3, arr = [],
        l;
    i = ac = c1 = c2 = c3 = 0;

    if (str && str.length) {
        l = str.length;
        str += '';

        while (i < l) {
            c1 = str.charCodeAt(i);
            ac += 1;
            if (c1 < 128) {
                arr[ac] = String.fromCharCode(c1);
                i += 1;
            } else if (c1 > 191 && c1 < 224) {
                c2 = str.charCodeAt(i + 1);
                arr[ac] = String.fromCharCode(((c1 & 31) << 6) | (c2 & 63));
                i += 2;
            } else {
                c2 = str.charCodeAt(i + 1);
                c3 = str.charCodeAt(i + 2);
                arr[ac] = String.fromCharCode(((c1 & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                i += 3;
            }
        }
    }
    return arr.join('');
}

/**
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */

function safe_add(x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF),
        msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
}

/**
 * Bitwise rotate a 32-bit number to the left.
 */

function bit_rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
}

/**
 * Convert a raw string to a hex string
 */

function rstr2hex(input, hexcase) {
    var hex_tab = hexcase ? '0123456789ABCDEF' : '0123456789abcdef',
        output = '',
        x, i = 0,
        l = input.length;
    for (; i < l; i += 1) {
        x = input.charCodeAt(i);
        output += hex_tab.charAt((x >>> 4) & 0x0F) + hex_tab.charAt(x & 0x0F);
    }
    return output;
}

/**
 * Encode a string as utf-16
 */

function str2rstr_utf16le(input) {
    var i, l = input.length,
        output = '';
    for (i = 0; i < l; i += 1) {
        output += String.fromCharCode(input.charCodeAt(i) & 0xFF, (input.charCodeAt(i) >>> 8) & 0xFF);
    }
    return output;
}

function str2rstr_utf16be(input) {
    var i, l = input.length,
        output = '';
    for (i = 0; i < l; i += 1) {
        output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF, input.charCodeAt(i) & 0xFF);
    }
    return output;
}

/**
 * Convert an array of big-endian words to a string
 */

function binb2rstr(input) {
    var i, l = input.length * 32,
        output = '';
    for (i = 0; i < l; i += 8) {
        output += String.fromCharCode((input[i >> 5] >>> (24 - i % 32)) & 0xFF);
    }
    return output;
}

/**
 * Convert an array of little-endian words to a string
 */

function binl2rstr(input) {
    var i, l = input.length * 32,
        output = '';
    for (i = 0; i < l; i += 8) {
        output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
    }
    return output;
}

/**
 * Convert a raw string to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */

function rstr2binl(input) {
    var i, l = input.length * 8,
        output = Array(input.length >> 2),
        lo = output.length;
    for (i = 0; i < lo; i += 1) {
        output[i] = 0;
    }
    for (i = 0; i < l; i += 8) {
        output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
    }
    return output;
}

/**
 * Convert a raw string to an array of big-endian words
 * Characters >255 have their high-byte silently ignored.
 */

function rstr2binb(input) {
    var i, l = input.length * 8,
        output = Array(input.length >> 2),
        lo = output.length;
    for (i = 0; i < lo; i += 1) {
        output[i] = 0;
    }
    for (i = 0; i < l; i += 8) {
        output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
    }
    return output;
}

/**
 * Convert a raw string to an arbitrary string encoding
 */

function rstr2any(input, encoding) {
    var divisor = encoding.length,
        remainders = Array(),
        i, q, x, ld, quotient, dividend, output, full_length;

    /* Convert to an array of 16-bit big-endian values, forming the dividend */
    dividend = Array(Math.ceil(input.length / 2));
    ld = dividend.length;
    for (i = 0; i < ld; i += 1) {
        dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
    }

    /**
     * Repeatedly perform a long division. The binary array forms the dividend,
     * the length of the encoding is the divisor. Once computed, the quotient
     * forms the dividend for the next step. We stop when the dividend is zerHashes.
     * All remainders are stored for later use.
     */
    while (dividend.length > 0) {
        quotient = Array();
        x = 0;
        for (i = 0; i < dividend.length; i += 1) {
            x = (x << 16) + dividend[i];
            q = Math.floor(x / divisor);
            x -= q * divisor;
            if (quotient.length > 0 || q > 0) {
                quotient[quotient.length] = q;
            }
        }
        remainders[remainders.length] = x;
        dividend = quotient;
    }

    /* Convert the remainders to the output string */
    output = '';
    for (i = remainders.length - 1; i >= 0; i--) {
        output += encoding.charAt(remainders[i]);
    }

    /* Append leading zero equivalents */
    full_length = Math.ceil(input.length * 8 / (Math.log(encoding.length) / Math.log(2)));
    for (i = output.length; i < full_length; i += 1) {
        output = encoding[0] + output;
    }
    return output;
}

/**
 * Convert a raw string to a base-64 string
 */

function rstr2b64(input, b64pad) {
    var tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
        output = '',
        len = input.length,
        i, j, triplet;
    b64pad = b64pad || '=';
    for (i = 0; i < len; i += 3) {
        triplet = (input.charCodeAt(i) << 16) | (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0) | (i + 2 < len ? input.charCodeAt(i + 2) : 0);
        for (j = 0; j < 4; j += 1) {
            if (i * 8 + j * 6 > input.length * 8) {
                output += b64pad;
            } else {
                output += tab.charAt((triplet >>> 6 * (3 - j)) & 0x3F);
            }
        }
    }
    return output;
}

Hashes = {
    /**
     * @property {String} version
     * @readonly
     */
    VERSION: '1.0.6',
    /**
     * @member Hashes
     * @class Base64
     * @constructor
     */
    Base64: function() {
        // private properties
        var tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
            pad = '=', // default pad according with the RFC standard
            url = false, // URL encoding support @todo
            utf8 = true; // by default enable UTF-8 support encoding

        // public method for encoding
        this.encode = function(input) {
            var i, j, triplet,
                output = '',
                len = input.length;

            pad = pad || '=';
            input = (utf8) ? utf8Encode(input) : input;

            for (i = 0; i < len; i += 3) {
                triplet = (input.charCodeAt(i) << 16) | (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0) | (i + 2 < len ? input.charCodeAt(i + 2) : 0);
                for (j = 0; j < 4; j += 1) {
                    if (i * 8 + j * 6 > len * 8) {
                        output += pad;
                    } else {
                        output += tab.charAt((triplet >>> 6 * (3 - j)) & 0x3F);
                    }
                }
            }
            return output;
        };

        // public method for decoding
        this.decode = function(input) {
            // var b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
            var i, o1, o2, o3, h1, h2, h3, h4, bits, ac,
                dec = '',
                arr = [];
            if (!input) {
                return input;
            }

            i = ac = 0;
            input = input.replace(new RegExp('\\' + pad, 'gi'), ''); // use '='
            //input += '';

            do { // unpack four hexets into three octets using index points in b64
                h1 = tab.indexOf(input.charAt(i += 1));
                h2 = tab.indexOf(input.charAt(i += 1));
                h3 = tab.indexOf(input.charAt(i += 1));
                h4 = tab.indexOf(input.charAt(i += 1));

                bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;

                o1 = bits >> 16 & 0xff;
                o2 = bits >> 8 & 0xff;
                o3 = bits & 0xff;
                ac += 1;

                if (h3 === 64) {
                    arr[ac] = String.fromCharCode(o1);
                } else if (h4 === 64) {
                    arr[ac] = String.fromCharCode(o1, o2);
                } else {
                    arr[ac] = String.fromCharCode(o1, o2, o3);
                }
            } while (i < input.length);

            dec = arr.join('');
            dec = (utf8) ? utf8Decode(dec) : dec;

            return dec;
        };

        // set custom pad string
        this.setPad = function(str) {
            pad = str || pad;
            return this;
        };
        // set custom tab string characters
        this.setTab = function(str) {
            tab = str || tab;
            return this;
        };
        this.setUTF8 = function(bool) {
            if (typeof bool === 'boolean') {
                utf8 = bool;
            }
            return this;
        };
    },

    /**
     * CRC-32 calculation
     * @member Hashes
     * @method CRC32
     * @static
     * @param {String} str Input String
     * @return {String}
     */
    CRC32: function(str) {
        var crc = 0,
            x = 0,
            y = 0,
            table, i, iTop;
        str = utf8Encode(str);

        table = [
            '00000000 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3 0EDB8832 ',
            '79DCB8A4 E0D5E91E 97D2D988 09B64C2B 7EB17CBD E7B82D07 90BF1D91 1DB71064 6AB020F2 F3B97148 ',
            '84BE41DE 1ADAD47D 6DDDE4EB F4D4B551 83D385C7 136C9856 646BA8C0 FD62F97A 8A65C9EC 14015C4F ',
            '63066CD9 FA0F3D63 8D080DF5 3B6E20C8 4C69105E D56041E4 A2677172 3C03E4D1 4B04D447 D20D85FD ',
            'A50AB56B 35B5A8FA 42B2986C DBBBC9D6 ACBCF940 32D86CE3 45DF5C75 DCD60DCF ABD13D59 26D930AC ',
            '51DE003A C8D75180 BFD06116 21B4F4B5 56B3C423 CFBA9599 B8BDA50F 2802B89E 5F058808 C60CD9B2 ',
            'B10BE924 2F6F7C87 58684C11 C1611DAB B6662D3D 76DC4190 01DB7106 98D220BC EFD5102A 71B18589 ',
            '06B6B51F 9FBFE4A5 E8B8D433 7807C9A2 0F00F934 9609A88E E10E9818 7F6A0DBB 086D3D2D 91646C97 ',
            'E6635C01 6B6B51F4 1C6C6162 856530D8 F262004E 6C0695ED 1B01A57B 8208F4C1 F50FC457 65B0D9C6 ',
            '12B7E950 8BBEB8EA FCB9887C 62DD1DDF 15DA2D49 8CD37CF3 FBD44C65 4DB26158 3AB551CE A3BC0074 ',
            'D4BB30E2 4ADFA541 3DD895D7 A4D1C46D D3D6F4FB 4369E96A 346ED9FC AD678846 DA60B8D0 44042D73 ',
            '33031DE5 AA0A4C5F DD0D7CC9 5005713C 270241AA BE0B1010 C90C2086 5768B525 206F85B3 B966D409 ',
            'CE61E49F 5EDEF90E 29D9C998 B0D09822 C7D7A8B4 59B33D17 2EB40D81 B7BD5C3B C0BA6CAD EDB88320 ',
            '9ABFB3B6 03B6E20C 74B1D29A EAD54739 9DD277AF 04DB2615 73DC1683 E3630B12 94643B84 0D6D6A3E ',
            '7A6A5AA8 E40ECF0B 9309FF9D 0A00AE27 7D079EB1 F00F9344 8708A3D2 1E01F268 6906C2FE F762575D ',
            '806567CB 196C3671 6E6B06E7 FED41B76 89D32BE0 10DA7A5A 67DD4ACC F9B9DF6F 8EBEEFF9 17B7BE43 ',
            '60B08ED5 D6D6A3E8 A1D1937E 38D8C2C4 4FDFF252 D1BB67F1 A6BC5767 3FB506DD 48B2364B D80D2BDA ',
            'AF0A1B4C 36034AF6 41047A60 DF60EFC3 A867DF55 316E8EEF 4669BE79 CB61B38C BC66831A 256FD2A0 ',
            '5268E236 CC0C7795 BB0B4703 220216B9 5505262F C5BA3BBE B2BD0B28 2BB45A92 5CB36A04 C2D7FFA7 ',
            'B5D0CF31 2CD99E8B 5BDEAE1D 9B64C2B0 EC63F226 756AA39C 026D930A 9C0906A9 EB0E363F 72076785 ',
            '05005713 95BF4A82 E2B87A14 7BB12BAE 0CB61B38 92D28E9B E5D5BE0D 7CDCEFB7 0BDBDF21 86D3D2D4 ',
            'F1D4E242 68DDB3F8 1FDA836E 81BE16CD F6B9265B 6FB077E1 18B74777 88085AE6 FF0F6A70 66063BCA ',
            '11010B5C 8F659EFF F862AE69 616BFFD3 166CCF45 A00AE278 D70DD2EE 4E048354 3903B3C2 A7672661 ',
            'D06016F7 4969474D 3E6E77DB AED16A4A D9D65ADC 40DF0B66 37D83BF0 A9BCAE53 DEBB9EC5 47B2CF7F ',
            '30B5FFE9 BDBDF21C CABAC28A 53B39330 24B4A3A6 BAD03605 CDD70693 54DE5729 23D967BF B3667A2E ',
            'C4614AB8 5D681B02 2A6F2B94 B40BBE37 C30C8EA1 5A05DF1B 2D02EF8D'
        ].join('');

        crc = crc ^ (-1);
        for (i = 0, iTop = str.length; i < iTop; i += 1) {
            y = (crc ^ str.charCodeAt(i)) & 0xFF;
            x = '0x' + table.substr(y * 9, 8);
            crc = (crc >>> 8) ^ x;
        }
        // always return a positive number (that's what >>> 0 does)
        return (crc ^ (-1)) >>> 0;
    },
    /**
     * @member Hashes
     * @class MD5
     * @constructor
     * @param {Object} [config]
     *
     * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
     * Digest Algorithm, as defined in RFC 1321.
     * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
     * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
     * See <http://pajhome.org.uk/crypt/md5> for more infHashes.
     */
    MD5: function(options) {
        /**
         * Private config properties. You may need to tweak these to be compatible with
         * the server-side, but the defaults work in most cases.
         * See {@link Hashes.MD5#method-setUpperCase} and {@link Hashes.SHA1#method-setUpperCase}
         */
        var hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false, // hexadecimal output case format. false - lowercase; true - uppercase
            b64pad = (options && typeof options.pad === 'string') ? options.pad : '=', // base-64 pad character. Defaults to '=' for strict RFC compliance
            utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true; // enable/disable utf8 encoding

        // privileged (public) methods
        this.hex = function(s) {
            return rstr2hex(rstr(s, utf8), hexcase);
        };
        this.b64 = function(s) {
            return rstr2b64(rstr(s), b64pad);
        };
        this.any = function(s, e) {
            return rstr2any(rstr(s, utf8), e);
        };
        this.raw = function(s) {
            return rstr(s, utf8);
        };
        this.hex_hmac = function(k, d) {
            return rstr2hex(rstr_hmac(k, d), hexcase);
        };
        this.b64_hmac = function(k, d) {
            return rstr2b64(rstr_hmac(k, d), b64pad);
        };
        this.any_hmac = function(k, d, e) {
            return rstr2any(rstr_hmac(k, d), e);
        };
        /**
         * Perform a simple self-test to see if the VM is working
         * @return {String} Hexadecimal hash sample
         */
        this.vm_test = function() {
            return hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
        };
        /**
         * Enable/disable uppercase hexadecimal returned string
         * @param {Boolean}
         * @return {Object} this
         */
        this.setUpperCase = function(a) {
            if (typeof a === 'boolean') {
                hexcase = a;
            }
            return this;
        };
        /**
         * Defines a base64 pad string
         * @param {String} Pad
         * @return {Object} this
         */
        this.setPad = function(a) {
            b64pad = a || b64pad;
            return this;
        };
        /**
         * Defines a base64 pad string
         * @param {Boolean}
         * @return {Object} [this]
         */
        this.setUTF8 = function(a) {
            if (typeof a === 'boolean') {
                utf8 = a;
            }
            return this;
        };

        // private methods

        /**
         * Calculate the MD5 of a raw string
         */

        function rstr(s) {
            s = (utf8) ? utf8Encode(s) : s;
            return binl2rstr(binl(rstr2binl(s), s.length * 8));
        }

        /**
         * Calculate the HMAC-MD5, of a key and some data (raw strings)
         */

        function rstr_hmac(key, data) {
            var bkey, ipad, opad, hash, i;

            key = (utf8) ? utf8Encode(key) : key;
            data = (utf8) ? utf8Encode(data) : data;
            bkey = rstr2binl(key);
            if (bkey.length > 16) {
                bkey = binl(bkey, key.length * 8);
            }

            ipad = Array(16), opad = Array(16);
            for (i = 0; i < 16; i += 1) {
                ipad[i] = bkey[i] ^ 0x36363636;
                opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }
            hash = binl(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
            return binl2rstr(binl(opad.concat(hash), 512 + 128));
        }

        /**
         * Calculate the MD5 of an array of little-endian words, and a bit length.
         */

        function binl(x, len) {
            var i, olda, oldb, oldc, oldd,
                a = 1732584193,
                b = -271733879,
                c = -1732584194,
                d = 271733878;

            /* append padding */
            x[len >> 5] |= 0x80 << ((len) % 32);
            x[(((len + 64) >>> 9) << 4) + 14] = len;

            for (i = 0; i < x.length; i += 16) {
                olda = a;
                oldb = b;
                oldc = c;
                oldd = d;

                a = md5_ff(a, b, c, d, x[i + 0], 7, -680876936);
                d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
                c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
                b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
                a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
                d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
                c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
                b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
                a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
                d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
                c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
                b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
                a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
                d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
                c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
                b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);

                a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
                d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
                c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
                b = md5_gg(b, c, d, a, x[i + 0], 20, -373897302);
                a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
                d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
                c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
                b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
                a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
                d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
                c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
                b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
                a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
                d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
                c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
                b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

                a = md5_hh(a, b, c, d, x[i + 5], 4, -378558);
                d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
                c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
                b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
                a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
                d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
                c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
                b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
                a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
                d = md5_hh(d, a, b, c, x[i + 0], 11, -358537222);
                c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
                b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
                a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
                d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
                c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
                b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);

                a = md5_ii(a, b, c, d, x[i + 0], 6, -198630844);
                d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
                c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
                b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
                a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
                d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
                c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
                b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
                a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
                d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
                c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
                b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
                a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
                d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
                c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
                b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);

                a = safe_add(a, olda);
                b = safe_add(b, oldb);
                c = safe_add(c, oldc);
                d = safe_add(d, oldd);
            }
            return Array(a, b, c, d);
        }

        /**
         * These functions implement the four basic operations the algorithm uses.
         */

        function md5_cmn(q, a, b, x, s, t) {
            return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
        }

        function md5_ff(a, b, c, d, x, s, t) {
            return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
        }

        function md5_gg(a, b, c, d, x, s, t) {
            return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
        }

        function md5_hh(a, b, c, d, x, s, t) {
            return md5_cmn(b ^ c ^ d, a, b, x, s, t);
        }

        function md5_ii(a, b, c, d, x, s, t) {
            return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
        }
    },
    /**
     * @member Hashes
     * @class Hashes.SHA1
     * @param {Object} [config]
     * @constructor
     *
     * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined in FIPS 180-1
     * Version 2.2 Copyright Paul Johnston 2000 - 2009.
     * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
     * See http://pajhome.org.uk/crypt/md5 for details.
     */
    SHA1: function(options) {
        /**
         * Private config properties. You may need to tweak these to be compatible with
         * the server-side, but the defaults work in most cases.
         * See {@link Hashes.MD5#method-setUpperCase} and {@link Hashes.SHA1#method-setUpperCase}
         */
        var hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false, // hexadecimal output case format. false - lowercase; true - uppercase
            b64pad = (options && typeof options.pad === 'string') ? options.pad : '=', // base-64 pad character. Defaults to '=' for strict RFC compliance
            utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true; // enable/disable utf8 encoding

        // public methods
        this.hex = function(s) {
            return rstr2hex(rstr(s, utf8), hexcase);
        };
        this.b64 = function(s) {
            return rstr2b64(rstr(s, utf8), b64pad);
        };
        this.any = function(s, e) {
            return rstr2any(rstr(s, utf8), e);
        };
        this.raw = function(s) {
            return rstr(s, utf8);
        };
        this.hex_hmac = function(k, d) {
            return rstr2hex(rstr_hmac(k, d));
        };
        this.b64_hmac = function(k, d) {
            return rstr2b64(rstr_hmac(k, d), b64pad);
        };
        this.any_hmac = function(k, d, e) {
            return rstr2any(rstr_hmac(k, d), e);
        };
        /**
         * Perform a simple self-test to see if the VM is working
         * @return {String} Hexadecimal hash sample
         * @public
         */
        this.vm_test = function() {
            return hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
        };
        /**
         * @description Enable/disable uppercase hexadecimal returned string
         * @param {boolean}
         * @return {Object} this
         * @public
         */
        this.setUpperCase = function(a) {
            if (typeof a === 'boolean') {
                hexcase = a;
            }
            return this;
        };
        /**
         * @description Defines a base64 pad string
         * @param {string} Pad
         * @return {Object} this
         * @public
         */
        this.setPad = function(a) {
            b64pad = a || b64pad;
            return this;
        };
        /**
         * @description Defines a base64 pad string
         * @param {boolean}
         * @return {Object} this
         * @public
         */
        this.setUTF8 = function(a) {
            if (typeof a === 'boolean') {
                utf8 = a;
            }
            return this;
        };

        // private methods

        /**
         * Calculate the SHA-512 of a raw string
         */

        function rstr(s) {
            s = (utf8) ? utf8Encode(s) : s;
            return binb2rstr(binb(rstr2binb(s), s.length * 8));
        }

        /**
         * Calculate the HMAC-SHA1 of a key and some data (raw strings)
         */

        function rstr_hmac(key, data) {
            var bkey, ipad, opad, i, hash;
            key = (utf8) ? utf8Encode(key) : key;
            data = (utf8) ? utf8Encode(data) : data;
            bkey = rstr2binb(key);

            if (bkey.length > 16) {
                bkey = binb(bkey, key.length * 8);
            }
            ipad = Array(16), opad = Array(16);
            for (i = 0; i < 16; i += 1) {
                ipad[i] = bkey[i] ^ 0x36363636;
                opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }
            hash = binb(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
            return binb2rstr(binb(opad.concat(hash), 512 + 160));
        }

        /**
         * Calculate the SHA-1 of an array of big-endian words, and a bit length
         */

        function binb(x, len) {
            var i, j, t, olda, oldb, oldc, oldd, olde,
                w = Array(80),
                a = 1732584193,
                b = -271733879,
                c = -1732584194,
                d = 271733878,
                e = -1009589776;

            /* append padding */
            x[len >> 5] |= 0x80 << (24 - len % 32);
            x[((len + 64 >> 9) << 4) + 15] = len;

            for (i = 0; i < x.length; i += 16) {
                olda = a;
                oldb = b;
                oldc = c;
                oldd = d;
                olde = e;

                for (j = 0; j < 80; j += 1) {
                    if (j < 16) {
                        w[j] = x[i + j];
                    } else {
                        w[j] = bit_rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                    }
                    t = safe_add(safe_add(bit_rol(a, 5), sha1_ft(j, b, c, d)),
                        safe_add(safe_add(e, w[j]), sha1_kt(j)));
                    e = d;
                    d = c;
                    c = bit_rol(b, 30);
                    b = a;
                    a = t;
                }

                a = safe_add(a, olda);
                b = safe_add(b, oldb);
                c = safe_add(c, oldc);
                d = safe_add(d, oldd);
                e = safe_add(e, olde);
            }
            return Array(a, b, c, d, e);
        }

        /**
         * Perform the appropriate triplet combination function for the current
         * iteration
         */

        function sha1_ft(t, b, c, d) {
            if (t < 20) {
                return (b & c) | ((~b) & d);
            }
            if (t < 40) {
                return b ^ c ^ d;
            }
            if (t < 60) {
                return (b & c) | (b & d) | (c & d);
            }
            return b ^ c ^ d;
        }

        /**
         * Determine the appropriate additive constant for the current iteration
         */

        function sha1_kt(t) {
            return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 :
                (t < 60) ? -1894007588 : -899497514;
        }
    },
    /**
     * @class Hashes.SHA256
     * @param {config}
     *
     * A JavaScript implementation of the Secure Hash Algorithm, SHA-256, as defined in FIPS 180-2
     * Version 2.2 Copyright Angel Marin, Paul Johnston 2000 - 2009.
     * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
     * See http://pajhome.org.uk/crypt/md5 for details.
     * Also http://anmar.eu.org/projects/jssha2/
     */
    SHA256: function(options) {
        /**
         * Private properties configuration variables. You may need to tweak these to be compatible with
         * the server-side, but the defaults work in most cases.
         * @see this.setUpperCase() method
         * @see this.setPad() method
         */
        var hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false, // hexadecimal output case format. false - lowercase; true - uppercase  */
            b64pad = (options && typeof options.pad === 'string') ? options.pad : '=',
            /* base-64 pad character. Default '=' for strict RFC compliance   */
            utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true,
            /* enable/disable utf8 encoding */
            sha256_K;

        /* privileged (public) methods */
        this.hex = function(s) {
            return rstr2hex(rstr(s, utf8));
        };
        this.b64 = function(s) {
            return rstr2b64(rstr(s, utf8), b64pad);
        };
        this.any = function(s, e) {
            return rstr2any(rstr(s, utf8), e);
        };
        this.raw = function(s) {
            return rstr(s, utf8);
        };
        this.hex_hmac = function(k, d) {
            return rstr2hex(rstr_hmac(k, d));
        };
        this.b64_hmac = function(k, d) {
            return rstr2b64(rstr_hmac(k, d), b64pad);
        };
        this.any_hmac = function(k, d, e) {
            return rstr2any(rstr_hmac(k, d), e);
        };
        /**
         * Perform a simple self-test to see if the VM is working
         * @return {String} Hexadecimal hash sample
         * @public
         */
        this.vm_test = function() {
            return hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
        };
        /**
         * Enable/disable uppercase hexadecimal returned string
         * @param {boolean}
         * @return {Object} this
         * @public
         */
        this.setUpperCase = function(a) {
            if (typeof a === 'boolean') {
                hexcase = a;
            }
            return this;
        };
        /**
         * @description Defines a base64 pad string
         * @param {string} Pad
         * @return {Object} this
         * @public
         */
        this.setPad = function(a) {
            b64pad = a || b64pad;
            return this;
        };
        /**
         * Defines a base64 pad string
         * @param {boolean}
         * @return {Object} this
         * @public
         */
        this.setUTF8 = function(a) {
            if (typeof a === 'boolean') {
                utf8 = a;
            }
            return this;
        };

        // private methods

        /**
         * Calculate the SHA-512 of a raw string
         */

        function rstr(s, utf8) {
            s = (utf8) ? utf8Encode(s) : s;
            return binb2rstr(binb(rstr2binb(s), s.length * 8));
        }

        /**
         * Calculate the HMAC-sha256 of a key and some data (raw strings)
         */

        function rstr_hmac(key, data) {
            key = (utf8) ? utf8Encode(key) : key;
            data = (utf8) ? utf8Encode(data) : data;
            var hash, i = 0,
                bkey = rstr2binb(key),
                ipad = Array(16),
                opad = Array(16);

            if (bkey.length > 16) {
                bkey = binb(bkey, key.length * 8);
            }

            for (; i < 16; i += 1) {
                ipad[i] = bkey[i] ^ 0x36363636;
                opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }

            hash = binb(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
            return binb2rstr(binb(opad.concat(hash), 512 + 256));
        }

        /*
         * Main sha256 function, with its support functions
         */

        function sha256_S(X, n) {
            return (X >>> n) | (X << (32 - n));
        }

        function sha256_R(X, n) {
            return (X >>> n);
        }

        function sha256_Ch(x, y, z) {
            return ((x & y) ^ ((~x) & z));
        }

        function sha256_Maj(x, y, z) {
            return ((x & y) ^ (x & z) ^ (y & z));
        }

        function sha256_Sigma0256(x) {
            return (sha256_S(x, 2) ^ sha256_S(x, 13) ^ sha256_S(x, 22));
        }

        function sha256_Sigma1256(x) {
            return (sha256_S(x, 6) ^ sha256_S(x, 11) ^ sha256_S(x, 25));
        }

        function sha256_Gamma0256(x) {
            return (sha256_S(x, 7) ^ sha256_S(x, 18) ^ sha256_R(x, 3));
        }

        function sha256_Gamma1256(x) {
            return (sha256_S(x, 17) ^ sha256_S(x, 19) ^ sha256_R(x, 10));
        }

        function sha256_Sigma0512(x) {
            return (sha256_S(x, 28) ^ sha256_S(x, 34) ^ sha256_S(x, 39));
        }

        function sha256_Sigma1512(x) {
            return (sha256_S(x, 14) ^ sha256_S(x, 18) ^ sha256_S(x, 41));
        }

        function sha256_Gamma0512(x) {
            return (sha256_S(x, 1) ^ sha256_S(x, 8) ^ sha256_R(x, 7));
        }

        function sha256_Gamma1512(x) {
            return (sha256_S(x, 19) ^ sha256_S(x, 61) ^ sha256_R(x, 6));
        }

        sha256_K = [
            1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993, -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987,
            1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522,
            264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585,
            113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
            1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885, -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344,
            430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
            1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872, -1866530822, -1538233109, -1090935817, -965641998
        ];

        function binb(m, l) {
            var HASH = [1779033703, -1150833019, 1013904242, -1521486534,
                1359893119, -1694144372, 528734635, 1541459225
            ];
            var W = new Array(64);
            var a, b, c, d, e, f, g, h;
            var i, j, T1, T2;

            /* append padding */
            m[l >> 5] |= 0x80 << (24 - l % 32);
            m[((l + 64 >> 9) << 4) + 15] = l;

            for (i = 0; i < m.length; i += 16) {
                a = HASH[0];
                b = HASH[1];
                c = HASH[2];
                d = HASH[3];
                e = HASH[4];
                f = HASH[5];
                g = HASH[6];
                h = HASH[7];

                for (j = 0; j < 64; j += 1) {
                    if (j < 16) {
                        W[j] = m[j + i];
                    } else {
                        W[j] = safe_add(safe_add(safe_add(sha256_Gamma1256(W[j - 2]), W[j - 7]),
                            sha256_Gamma0256(W[j - 15])), W[j - 16]);
                    }

                    T1 = safe_add(safe_add(safe_add(safe_add(h, sha256_Sigma1256(e)), sha256_Ch(e, f, g)),
                        sha256_K[j]), W[j]);
                    T2 = safe_add(sha256_Sigma0256(a), sha256_Maj(a, b, c));
                    h = g;
                    g = f;
                    f = e;
                    e = safe_add(d, T1);
                    d = c;
                    c = b;
                    b = a;
                    a = safe_add(T1, T2);
                }

                HASH[0] = safe_add(a, HASH[0]);
                HASH[1] = safe_add(b, HASH[1]);
                HASH[2] = safe_add(c, HASH[2]);
                HASH[3] = safe_add(d, HASH[3]);
                HASH[4] = safe_add(e, HASH[4]);
                HASH[5] = safe_add(f, HASH[5]);
                HASH[6] = safe_add(g, HASH[6]);
                HASH[7] = safe_add(h, HASH[7]);
            }
            return HASH;
        }

    },

    /**
     * @class Hashes.SHA512
     * @param {config}
     *
     * A JavaScript implementation of the Secure Hash Algorithm, SHA-512, as defined in FIPS 180-2
     * Version 2.2 Copyright Anonymous Contributor, Paul Johnston 2000 - 2009.
     * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
     * See http://pajhome.org.uk/crypt/md5 for details.
     */
    SHA512: function(options) {
        /**
         * Private properties configuration variables. You may need to tweak these to be compatible with
         * the server-side, but the defaults work in most cases.
         * @see this.setUpperCase() method
         * @see this.setPad() method
         */
        var hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false,
            /* hexadecimal output case format. false - lowercase; true - uppercase  */
            b64pad = (options && typeof options.pad === 'string') ? options.pad : '=',
            /* base-64 pad character. Default '=' for strict RFC compliance   */
            utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true,
            /* enable/disable utf8 encoding */
            sha512_k;

        /* privileged (public) methods */
        this.hex = function(s) {
            return rstr2hex(rstr(s));
        };
        this.b64 = function(s) {
            return rstr2b64(rstr(s), b64pad);
        };
        this.any = function(s, e) {
            return rstr2any(rstr(s), e);
        };
        this.raw = function(s) {
            return rstr(s, utf8);
        };
        this.hex_hmac = function(k, d) {
            return rstr2hex(rstr_hmac(k, d));
        };
        this.b64_hmac = function(k, d) {
            return rstr2b64(rstr_hmac(k, d), b64pad);
        };
        this.any_hmac = function(k, d, e) {
            return rstr2any(rstr_hmac(k, d), e);
        };
        /**
         * Perform a simple self-test to see if the VM is working
         * @return {String} Hexadecimal hash sample
         * @public
         */
        this.vm_test = function() {
            return hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
        };
        /**
         * @description Enable/disable uppercase hexadecimal returned string
         * @param {boolean}
         * @return {Object} this
         * @public
         */
        this.setUpperCase = function(a) {
            if (typeof a === 'boolean') {
                hexcase = a;
            }
            return this;
        };
        /**
         * @description Defines a base64 pad string
         * @param {string} Pad
         * @return {Object} this
         * @public
         */
        this.setPad = function(a) {
            b64pad = a || b64pad;
            return this;
        };
        /**
         * @description Defines a base64 pad string
         * @param {boolean}
         * @return {Object} this
         * @public
         */
        this.setUTF8 = function(a) {
            if (typeof a === 'boolean') {
                utf8 = a;
            }
            return this;
        };

        /* private methods */

        /**
         * Calculate the SHA-512 of a raw string
         */

        function rstr(s) {
            s = (utf8) ? utf8Encode(s) : s;
            return binb2rstr(binb(rstr2binb(s), s.length * 8));
        }
        /*
         * Calculate the HMAC-SHA-512 of a key and some data (raw strings)
         */

        function rstr_hmac(key, data) {
            key = (utf8) ? utf8Encode(key) : key;
            data = (utf8) ? utf8Encode(data) : data;

            var hash, i = 0,
                bkey = rstr2binb(key),
                ipad = Array(32),
                opad = Array(32);

            if (bkey.length > 32) {
                bkey = binb(bkey, key.length * 8);
            }

            for (; i < 32; i += 1) {
                ipad[i] = bkey[i] ^ 0x36363636;
                opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }

            hash = binb(ipad.concat(rstr2binb(data)), 1024 + data.length * 8);
            return binb2rstr(binb(opad.concat(hash), 1024 + 512));
        }

        /**
         * Calculate the SHA-512 of an array of big-endian dwords, and a bit length
         */

        function binb(x, len) {
            var j, i, l,
                W = new Array(80),
                hash = new Array(16),
                //Initial hash values
                H = [
                    new int64(0x6a09e667, -205731576),
                    new int64(-1150833019, -2067093701),
                    new int64(0x3c6ef372, -23791573),
                    new int64(-1521486534, 0x5f1d36f1),
                    new int64(0x510e527f, -1377402159),
                    new int64(-1694144372, 0x2b3e6c1f),
                    new int64(0x1f83d9ab, -79577749),
                    new int64(0x5be0cd19, 0x137e2179)
                ],
                T1 = new int64(0, 0),
                T2 = new int64(0, 0),
                a = new int64(0, 0),
                b = new int64(0, 0),
                c = new int64(0, 0),
                d = new int64(0, 0),
                e = new int64(0, 0),
                f = new int64(0, 0),
                g = new int64(0, 0),
                h = new int64(0, 0),
                //Temporary variables not specified by the document
                s0 = new int64(0, 0),
                s1 = new int64(0, 0),
                Ch = new int64(0, 0),
                Maj = new int64(0, 0),
                r1 = new int64(0, 0),
                r2 = new int64(0, 0),
                r3 = new int64(0, 0);

            if (sha512_k === undefined) {
                //SHA512 constants
                sha512_k = [
                    new int64(0x428a2f98, -685199838), new int64(0x71374491, 0x23ef65cd),
                    new int64(-1245643825, -330482897), new int64(-373957723, -2121671748),
                    new int64(0x3956c25b, -213338824), new int64(0x59f111f1, -1241133031),
                    new int64(-1841331548, -1357295717), new int64(-1424204075, -630357736),
                    new int64(-670586216, -1560083902), new int64(0x12835b01, 0x45706fbe),
                    new int64(0x243185be, 0x4ee4b28c), new int64(0x550c7dc3, -704662302),
                    new int64(0x72be5d74, -226784913), new int64(-2132889090, 0x3b1696b1),
                    new int64(-1680079193, 0x25c71235), new int64(-1046744716, -815192428),
                    new int64(-459576895, -1628353838), new int64(-272742522, 0x384f25e3),
                    new int64(0xfc19dc6, -1953704523), new int64(0x240ca1cc, 0x77ac9c65),
                    new int64(0x2de92c6f, 0x592b0275), new int64(0x4a7484aa, 0x6ea6e483),
                    new int64(0x5cb0a9dc, -1119749164), new int64(0x76f988da, -2096016459),
                    new int64(-1740746414, -295247957), new int64(-1473132947, 0x2db43210),
                    new int64(-1341970488, -1728372417), new int64(-1084653625, -1091629340),
                    new int64(-958395405, 0x3da88fc2), new int64(-710438585, -1828018395),
                    new int64(0x6ca6351, -536640913), new int64(0x14292967, 0xa0e6e70),
                    new int64(0x27b70a85, 0x46d22ffc), new int64(0x2e1b2138, 0x5c26c926),
                    new int64(0x4d2c6dfc, 0x5ac42aed), new int64(0x53380d13, -1651133473),
                    new int64(0x650a7354, -1951439906), new int64(0x766a0abb, 0x3c77b2a8),
                    new int64(-2117940946, 0x47edaee6), new int64(-1838011259, 0x1482353b),
                    new int64(-1564481375, 0x4cf10364), new int64(-1474664885, -1136513023),
                    new int64(-1035236496, -789014639), new int64(-949202525, 0x654be30),
                    new int64(-778901479, -688958952), new int64(-694614492, 0x5565a910),
                    new int64(-200395387, 0x5771202a), new int64(0x106aa070, 0x32bbd1b8),
                    new int64(0x19a4c116, -1194143544), new int64(0x1e376c08, 0x5141ab53),
                    new int64(0x2748774c, -544281703), new int64(0x34b0bcb5, -509917016),
                    new int64(0x391c0cb3, -976659869), new int64(0x4ed8aa4a, -482243893),
                    new int64(0x5b9cca4f, 0x7763e373), new int64(0x682e6ff3, -692930397),
                    new int64(0x748f82ee, 0x5defb2fc), new int64(0x78a5636f, 0x43172f60),
                    new int64(-2067236844, -1578062990), new int64(-1933114872, 0x1a6439ec),
                    new int64(-1866530822, 0x23631e28), new int64(-1538233109, -561857047),
                    new int64(-1090935817, -1295615723), new int64(-965641998, -479046869),
                    new int64(-903397682, -366583396), new int64(-779700025, 0x21c0c207),
                    new int64(-354779690, -840897762), new int64(-176337025, -294727304),
                    new int64(0x6f067aa, 0x72176fba), new int64(0xa637dc5, -1563912026),
                    new int64(0x113f9804, -1090974290), new int64(0x1b710b35, 0x131c471b),
                    new int64(0x28db77f5, 0x23047d84), new int64(0x32caab7b, 0x40c72493),
                    new int64(0x3c9ebe0a, 0x15c9bebc), new int64(0x431d67c4, -1676669620),
                    new int64(0x4cc5d4be, -885112138), new int64(0x597f299c, -60457430),
                    new int64(0x5fcb6fab, 0x3ad6faec), new int64(0x6c44198c, 0x4a475817)
                ];
            }

            for (i = 0; i < 80; i += 1) {
                W[i] = new int64(0, 0);
            }

            // append padding to the source string. The format is described in the FIPS.
            x[len >> 5] |= 0x80 << (24 - (len & 0x1f));
            x[((len + 128 >> 10) << 5) + 31] = len;
            l = x.length;
            for (i = 0; i < l; i += 32) { //32 dwords is the block size
                int64copy(a, H[0]);
                int64copy(b, H[1]);
                int64copy(c, H[2]);
                int64copy(d, H[3]);
                int64copy(e, H[4]);
                int64copy(f, H[5]);
                int64copy(g, H[6]);
                int64copy(h, H[7]);

                for (j = 0; j < 16; j += 1) {
                    W[j].h = x[i + 2 * j];
                    W[j].l = x[i + 2 * j + 1];
                }

                for (j = 16; j < 80; j += 1) {
                    //sigma1
                    int64rrot(r1, W[j - 2], 19);
                    int64revrrot(r2, W[j - 2], 29);
                    int64shr(r3, W[j - 2], 6);
                    s1.l = r1.l ^ r2.l ^ r3.l;
                    s1.h = r1.h ^ r2.h ^ r3.h;
                    //sigma0
                    int64rrot(r1, W[j - 15], 1);
                    int64rrot(r2, W[j - 15], 8);
                    int64shr(r3, W[j - 15], 7);
                    s0.l = r1.l ^ r2.l ^ r3.l;
                    s0.h = r1.h ^ r2.h ^ r3.h;

                    int64add4(W[j], s1, W[j - 7], s0, W[j - 16]);
                }

                for (j = 0; j < 80; j += 1) {
                    //Ch
                    Ch.l = (e.l & f.l) ^ (~e.l & g.l);
                    Ch.h = (e.h & f.h) ^ (~e.h & g.h);

                    //Sigma1
                    int64rrot(r1, e, 14);
                    int64rrot(r2, e, 18);
                    int64revrrot(r3, e, 9);
                    s1.l = r1.l ^ r2.l ^ r3.l;
                    s1.h = r1.h ^ r2.h ^ r3.h;

                    //Sigma0
                    int64rrot(r1, a, 28);
                    int64revrrot(r2, a, 2);
                    int64revrrot(r3, a, 7);
                    s0.l = r1.l ^ r2.l ^ r3.l;
                    s0.h = r1.h ^ r2.h ^ r3.h;

                    //Maj
                    Maj.l = (a.l & b.l) ^ (a.l & c.l) ^ (b.l & c.l);
                    Maj.h = (a.h & b.h) ^ (a.h & c.h) ^ (b.h & c.h);

                    int64add5(T1, h, s1, Ch, sha512_k[j], W[j]);
                    int64add(T2, s0, Maj);

                    int64copy(h, g);
                    int64copy(g, f);
                    int64copy(f, e);
                    int64add(e, d, T1);
                    int64copy(d, c);
                    int64copy(c, b);
                    int64copy(b, a);
                    int64add(a, T1, T2);
                }
                int64add(H[0], H[0], a);
                int64add(H[1], H[1], b);
                int64add(H[2], H[2], c);
                int64add(H[3], H[3], d);
                int64add(H[4], H[4], e);
                int64add(H[5], H[5], f);
                int64add(H[6], H[6], g);
                int64add(H[7], H[7], h);
            }

            //represent the hash as an array of 32-bit dwords
            for (i = 0; i < 8; i += 1) {
                hash[2 * i] = H[i].h;
                hash[2 * i + 1] = H[i].l;
            }
            return hash;
        }

        //A constructor for 64-bit numbers

        function int64(h, l) {
            this.h = h;
            this.l = l;
            //this.toString = int64toString;
        }

        //Copies src into dst, assuming both are 64-bit numbers

        function int64copy(dst, src) {
            dst.h = src.h;
            dst.l = src.l;
        }

        //Right-rotates a 64-bit number by shift
        //Won't handle cases of shift>=32
        //The function revrrot() is for that

        function int64rrot(dst, x, shift) {
            dst.l = (x.l >>> shift) | (x.h << (32 - shift));
            dst.h = (x.h >>> shift) | (x.l << (32 - shift));
        }

        //Reverses the dwords of the source and then rotates right by shift.
        //This is equivalent to rotation by 32+shift

        function int64revrrot(dst, x, shift) {
            dst.l = (x.h >>> shift) | (x.l << (32 - shift));
            dst.h = (x.l >>> shift) | (x.h << (32 - shift));
        }

        //Bitwise-shifts right a 64-bit number by shift
        //Won't handle shift>=32, but it's never needed in SHA512

        function int64shr(dst, x, shift) {
            dst.l = (x.l >>> shift) | (x.h << (32 - shift));
            dst.h = (x.h >>> shift);
        }

        //Adds two 64-bit numbers
        //Like the original implementation, does not rely on 32-bit operations

        function int64add(dst, x, y) {
            var w0 = (x.l & 0xffff) + (y.l & 0xffff);
            var w1 = (x.l >>> 16) + (y.l >>> 16) + (w0 >>> 16);
            var w2 = (x.h & 0xffff) + (y.h & 0xffff) + (w1 >>> 16);
            var w3 = (x.h >>> 16) + (y.h >>> 16) + (w2 >>> 16);
            dst.l = (w0 & 0xffff) | (w1 << 16);
            dst.h = (w2 & 0xffff) | (w3 << 16);
        }

        //Same, except with 4 addends. Works faster than adding them one by one.

        function int64add4(dst, a, b, c, d) {
            var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff);
            var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (w0 >>> 16);
            var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (w1 >>> 16);
            var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (w2 >>> 16);
            dst.l = (w0 & 0xffff) | (w1 << 16);
            dst.h = (w2 & 0xffff) | (w3 << 16);
        }

        //Same, except with 5 addends

        function int64add5(dst, a, b, c, d, e) {
            var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff) + (e.l & 0xffff),
                w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (w0 >>> 16),
                w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (e.h & 0xffff) + (w1 >>> 16),
                w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (w2 >>> 16);
            dst.l = (w0 & 0xffff) | (w1 << 16);
            dst.h = (w2 & 0xffff) | (w3 << 16);
        }
    },
    /**
     * @class Hashes.RMD160
     * @constructor
     * @param {Object} [config]
     *
     * A JavaScript implementation of the RIPEMD-160 Algorithm
     * Version 2.2 Copyright Jeremy Lin, Paul Johnston 2000 - 2009.
     * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
     * See http://pajhome.org.uk/crypt/md5 for details.
     * Also http://www.ocf.berkeley.edu/~jjlin/jsotp/
     */
    RMD160: function(options) {
        /**
         * Private properties configuration variables. You may need to tweak these to be compatible with
         * the server-side, but the defaults work in most cases.
         * @see this.setUpperCase() method
         * @see this.setPad() method
         */
        var hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false,
            /* hexadecimal output case format. false - lowercase; true - uppercase  */
            b64pad = (options && typeof options.pad === 'string') ? options.pa : '=',
            /* base-64 pad character. Default '=' for strict RFC compliance   */
            utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true,
            /* enable/disable utf8 encoding */
            rmd160_r1 = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
                3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
                1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
                4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
            ],
            rmd160_r2 = [
                5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
                6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
                15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
                8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
                12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
            ],
            rmd160_s1 = [
                11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
                7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
                11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
                11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
                9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
            ],
            rmd160_s2 = [
                8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
                9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
                9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
                15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
                8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
            ];

        /* privileged (public) methods */
        this.hex = function(s) {
            return rstr2hex(rstr(s, utf8));
        };
        this.b64 = function(s) {
            return rstr2b64(rstr(s, utf8), b64pad);
        };
        this.any = function(s, e) {
            return rstr2any(rstr(s, utf8), e);
        };
        this.raw = function(s) {
            return rstr(s, utf8);
        };
        this.hex_hmac = function(k, d) {
            return rstr2hex(rstr_hmac(k, d));
        };
        this.b64_hmac = function(k, d) {
            return rstr2b64(rstr_hmac(k, d), b64pad);
        };
        this.any_hmac = function(k, d, e) {
            return rstr2any(rstr_hmac(k, d), e);
        };
        /**
         * Perform a simple self-test to see if the VM is working
         * @return {String} Hexadecimal hash sample
         * @public
         */
        this.vm_test = function() {
            return hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
        };
        /**
         * @description Enable/disable uppercase hexadecimal returned string
         * @param {boolean}
         * @return {Object} this
         * @public
         */
        this.setUpperCase = function(a) {
            if (typeof a === 'boolean') {
                hexcase = a;
            }
            return this;
        };
        /**
         * @description Defines a base64 pad string
         * @param {string} Pad
         * @return {Object} this
         * @public
         */
        this.setPad = function(a) {
            if (typeof a !== 'undefined') {
                b64pad = a;
            }
            return this;
        };
        /**
         * @description Defines a base64 pad string
         * @param {boolean}
         * @return {Object} this
         * @public
         */
        this.setUTF8 = function(a) {
            if (typeof a === 'boolean') {
                utf8 = a;
            }
            return this;
        };

        /* private methods */

        /**
         * Calculate the rmd160 of a raw string
         */

        function rstr(s) {
            s = (utf8) ? utf8Encode(s) : s;
            return binl2rstr(binl(rstr2binl(s), s.length * 8));
        }

        /**
         * Calculate the HMAC-rmd160 of a key and some data (raw strings)
         */

        function rstr_hmac(key, data) {
            key = (utf8) ? utf8Encode(key) : key;
            data = (utf8) ? utf8Encode(data) : data;
            var i, hash,
                bkey = rstr2binl(key),
                ipad = Array(16),
                opad = Array(16);

            if (bkey.length > 16) {
                bkey = binl(bkey, key.length * 8);
            }

            for (i = 0; i < 16; i += 1) {
                ipad[i] = bkey[i] ^ 0x36363636;
                opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }
            hash = binl(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
            return binl2rstr(binl(opad.concat(hash), 512 + 160));
        }

        /**
         * Convert an array of little-endian words to a string
         */

        function binl2rstr(input) {
            var i, output = '',
                l = input.length * 32;
            for (i = 0; i < l; i += 8) {
                output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
            }
            return output;
        }

        /**
         * Calculate the RIPE-MD160 of an array of little-endian words, and a bit length.
         */

        function binl(x, len) {
            var T, j, i, l,
                h0 = 0x67452301,
                h1 = 0xefcdab89,
                h2 = 0x98badcfe,
                h3 = 0x10325476,
                h4 = 0xc3d2e1f0,
                A1, B1, C1, D1, E1,
                A2, B2, C2, D2, E2;

            /* append padding */
            x[len >> 5] |= 0x80 << (len % 32);
            x[(((len + 64) >>> 9) << 4) + 14] = len;
            l = x.length;

            for (i = 0; i < l; i += 16) {
                A1 = A2 = h0;
                B1 = B2 = h1;
                C1 = C2 = h2;
                D1 = D2 = h3;
                E1 = E2 = h4;
                for (j = 0; j <= 79; j += 1) {
                    T = safe_add(A1, rmd160_f(j, B1, C1, D1));
                    T = safe_add(T, x[i + rmd160_r1[j]]);
                    T = safe_add(T, rmd160_K1(j));
                    T = safe_add(bit_rol(T, rmd160_s1[j]), E1);
                    A1 = E1;
                    E1 = D1;
                    D1 = bit_rol(C1, 10);
                    C1 = B1;
                    B1 = T;
                    T = safe_add(A2, rmd160_f(79 - j, B2, C2, D2));
                    T = safe_add(T, x[i + rmd160_r2[j]]);
                    T = safe_add(T, rmd160_K2(j));
                    T = safe_add(bit_rol(T, rmd160_s2[j]), E2);
                    A2 = E2;
                    E2 = D2;
                    D2 = bit_rol(C2, 10);
                    C2 = B2;
                    B2 = T;
                }

                T = safe_add(h1, safe_add(C1, D2));
                h1 = safe_add(h2, safe_add(D1, E2));
                h2 = safe_add(h3, safe_add(E1, A2));
                h3 = safe_add(h4, safe_add(A1, B2));
                h4 = safe_add(h0, safe_add(B1, C2));
                h0 = T;
            }
            return [h0, h1, h2, h3, h4];
        }

        // specific algorithm methods

        function rmd160_f(j, x, y, z) {
            return (0 <= j && j <= 15) ? (x ^ y ^ z) :
                (16 <= j && j <= 31) ? (x & y) | (~x & z) :
                (32 <= j && j <= 47) ? (x | ~y) ^ z :
                (48 <= j && j <= 63) ? (x & z) | (y & ~z) :
                (64 <= j && j <= 79) ? x ^ (y | ~z) :
                'rmd160_f: j out of range';
        }

        function rmd160_K1(j) {
            return (0 <= j && j <= 15) ? 0x00000000 :
                (16 <= j && j <= 31) ? 0x5a827999 :
                (32 <= j && j <= 47) ? 0x6ed9eba1 :
                (48 <= j && j <= 63) ? 0x8f1bbcdc :
                (64 <= j && j <= 79) ? 0xa953fd4e :
                'rmd160_K1: j out of range';
        }

        function rmd160_K2(j) {
            return (0 <= j && j <= 15) ? 0x50a28be6 :
                (16 <= j && j <= 31) ? 0x5c4dd124 :
                (32 <= j && j <= 47) ? 0x6d703ef3 :
                (48 <= j && j <= 63) ? 0x7a6d76e9 :
                (64 <= j && j <= 79) ? 0x00000000 :
                'rmd160_K2: j out of range';
        }
    }
};

// exposes Hashes
(function(window, undefined) {
    var freeExports = false;
    if (typeof exports === 'object') {
        freeExports = exports;
        if (exports && typeof global === 'object' && global && global === global.global) {
            window = global;
        }
    }

    if (typeof define === 'function' && typeof define.amd === 'object' && define.amd) {
        // define as an anonymous module, so, through path mapping, it can be aliased
        define(function() {
            return Hashes;
        });
    } else if (freeExports) {
        // in Node.js or RingoJS v0.8.0+
        if (typeof module === 'object' && module && module.exports === freeExports) {
            module.exports = Hashes;
        }
        // in Narwhal or RingoJS v0.7.0-
        else {
            freeExports.Hashes = Hashes;
        }
    } else {
        // in a browser or Rhino
        window.Hashes = Hashes;
    }
}(this));

function sendData(ruler, prekey, amount, addressCur, addressOut, data, depend, nonce, remarks) {
    type = 'transfer'
    addressKeyPair = Wallet.ImportKeyPair(prekey);
    timestamp = new Date().getTime();
    hashdata = type + "#" + nonce + "#" + addressCur + "#" + addressOut + "#" + amount + "#" + data + "#" + depend + "#" + timestamp + "#" + remarks;
    hash = new Hashes.SHA256().hex(hashdata);
    sign = Wallet.sign(hash, addressKeyPair);
    signHex = Wallet.Bytes2Hex(sign);
    transferdata = { type: type, hash: hash, nonce: nonce, addressIn: addressCur, addressOut: addressOut, amount: amount, data: data, depend: depend, timestamp: timestamp, sign: signHex, remarks: remarks }
    $.ajax({
        url: `${ruler}/satrpc/?v1.0.0&cmd=Transfer&type=${type}&hash=${hash}&nonce=${nonce}&addressIn=${addressCur}&addressOut=${addressOut}&amount=${amount}&data=${data}&depend=${depend}&timestamp=${timestamp}&sign=${signHex}&remarks=${remarks}`,
        dataType: "text",
        type: "get",
        success: function(data) {
            var jsonObj = JSON.parse(data);
            var res = jsonObj["success"];
            console.log(jsonObj)
        },
        error: function(err) {

        }
    });

    return hash;
};
