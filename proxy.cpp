#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Bcrypt.lib")

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <memory>
#include <algorithm>
#include <iomanip>

static std::string CFG_HOST      = "";
static int         CFG_SRV_PORT  = 25565;
static int         CFG_BIND_PORT = 25565;
static std::string AUTH_TOKEN, AUTH_UUID, AUTH_USERNAME;

static std::string jsonStr(const std::string& js, const std::string& key) {
    auto pos = js.find("\"" + key + "\"");
    if (pos == std::string::npos) return {};
    pos = js.find(':', pos); if (pos == std::string::npos) return {};
    pos = js.find_first_not_of(" \t\r\n", pos + 1);
    if (pos == std::string::npos) return {};
    if (js[pos] == '"') { auto e = js.find('"', pos+1); return js.substr(pos+1, e-pos-1); }
    auto e = js.find_first_of(",}\r\n", pos);
    auto s = js.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
    while (!s.empty() && (s.back()==' '||s.back()=='\t')) s.pop_back();
    return s;
}

static void loadFiles() {
    auto readFile = [](const char* p) {
        std::ifstream f(p); std::ostringstream ss; ss << f.rdbuf(); return ss.str();
    };

    auto cfg = readFile("config.json");
    auto parseBlock = [&](const std::string& name, auto cb) {
        auto si = cfg.find("\"" + name + "\""); if (si == std::string::npos) return;
        auto b = cfg.find('{', si), e = cfg.find('}', b);
        if (b != std::string::npos) cb(cfg.substr(b, e-b+1));
    };
    parseBlock("server", [](const std::string& blk){
        auto h = jsonStr(blk,"host"); if (!h.empty()) CFG_HOST = h;
        auto p = jsonStr(blk,"port"); if (!p.empty()) CFG_SRV_PORT = std::stoi(p);
    });
    parseBlock("proxy", [](const std::string& blk){
        auto p = jsonStr(blk,"port"); if (!p.empty()) CFG_BIND_PORT = std::stoi(p);
    });

    auto auth = readFile("auth.json");
    if (auth.empty()) { std::cerr << "[!] auth.json not found - run auth.bat first\n"; exit(1); }
    AUTH_TOKEN    = jsonStr(auth, "accessToken");
    AUTH_UUID     = jsonStr(auth, "uuid");
    AUTH_USERNAME = jsonStr(auth, "username");
    if (AUTH_TOKEN.empty()) { std::cerr << "[!] auth.json invalid - re-run auth.bat\n"; exit(1); }
}

static int readVI(const uint8_t* buf, int avail, int32_t* out) {
    *out = 0;
    for (int i = 0; i < 5 && i < avail; i++) {
        *out |= (buf[i] & 0x7F) << (7*i);
        if (!(buf[i] & 0x80)) return i+1;
    }
    return -1;
}
static std::vector<uint8_t> writeVI(int32_t v) {
    std::vector<uint8_t> r; uint32_t u = v;
    do { uint8_t b = u & 0x7F; u >>= 7; if (u) b |= 0x80; r.push_back(b); } while (u);
    return r;
}

static BCRYPT_ALG_HANDLE g_aesAlg = nullptr;

static void initAes() {
    BCryptOpenAlgorithmProvider(&g_aesAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(g_aesAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
}

struct AesCfb8 {
    BCRYPT_KEY_HANDLE key = nullptr;
    std::vector<uint8_t> keyObj;
    uint8_t sr[16] = {};

    void init(const uint8_t* keyBytes, const uint8_t* iv) {
        ULONG objSize = 0, dummy = 0;
        BCryptGetProperty(g_aesAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objSize, sizeof(objSize), &dummy, 0);
        keyObj.resize(objSize);
        BCryptGenerateSymmetricKey(g_aesAlg, &key, keyObj.data(), objSize, (PUCHAR)keyBytes, 16, 0);
        memcpy(sr, iv, 16);
    }

    void process(const uint8_t* in, uint8_t* out, int n, bool encrypt) {
        for (int i = 0; i < n; i++) {
            uint8_t block[16], result[16]; memcpy(block, sr, 16);
            ULONG res = 0;
            BCryptEncrypt(key, block, 16, nullptr, nullptr, 0, result, 16, &res, 0);
            uint8_t inByte = in[i];
            out[i] = inByte ^ result[0];
            memmove(sr, sr+1, 15);
            sr[15] = encrypt ? out[i] : inByte;
        }
    }

    void encrypt(const uint8_t* in, uint8_t* out, int n) { process(in, out, n, true);  }
    void decrypt(const uint8_t* in, uint8_t* out, int n) { process(in, out, n, false); }
};

static bool recvN(SOCKET s, uint8_t* buf, int n) {
    for (int d=0; d<n;) { int r=recv(s,(char*)buf+d,n-d,0); if(r<=0) return false; d+=r; }
    return true;
}
static bool sendN(SOCKET s, const uint8_t* buf, int n) {
    for (int d=0; d<n;) { int r=send(s,(const char*)buf+d,n-d,0); if(r<=0) return false; d+=r; }
    return true;
}

static bool crecvN(SOCKET s, uint8_t* buf, int n, AesCfb8* c) {
    if (!recvN(s, buf, n)) return false;
    if (c) c->decrypt(buf, buf, n);
    return true;
}

static bool readPkt(SOCKET s, std::vector<uint8_t>& pkt, AesCfb8* c = nullptr) {
    uint8_t hdr[5]; int hLen=0; int32_t length=0; int shift=0;
    for (int i=0; i<5; i++) {
        if (!crecvN(s, &hdr[i], 1, c)) return false; hLen++;
        length |= (hdr[i] & 0x7F) << shift; shift += 7;
        if (!(hdr[i] & 0x80)) break;
    }
    pkt.resize(hLen + length);
    memcpy(pkt.data(), hdr, hLen);
    return length==0 || crecvN(s, pkt.data()+hLen, length, c);
}

static bool sendPkt(SOCKET s, const std::vector<uint8_t>& pkt, AesCfb8* c = nullptr) {
    if (!c) return sendN(s, pkt.data(), (int)pkt.size());
    std::vector<uint8_t> enc(pkt.size());
    c->encrypt(pkt.data(), enc.data(), (int)pkt.size());
    return sendN(s, enc.data(), (int)enc.size());
}

static void appendStr(std::vector<uint8_t>& buf, const std::string& s) {
    auto v = writeVI((int)s.size());
    buf.insert(buf.end(), v.begin(), v.end());
    buf.insert(buf.end(), s.begin(), s.end());
}
static std::vector<uint8_t> buildPkt(int id, const std::vector<uint8_t>& payload) {
    auto ib = writeVI(id); auto lb = writeVI((int)(ib.size()+payload.size()));
    std::vector<uint8_t> o;
    o.insert(o.end(),lb.begin(),lb.end()); o.insert(o.end(),ib.begin(),ib.end());
    o.insert(o.end(),payload.begin(),payload.end()); return o;
}
static std::vector<uint8_t> buildPktComp(int id, const std::vector<uint8_t>& payload) {
    auto ib = writeVI(id); auto dl = writeVI(0);
    std::vector<uint8_t> body;
    body.insert(body.end(),dl.begin(),dl.end()); body.insert(body.end(),ib.begin(),ib.end());
    body.insert(body.end(),payload.begin(),payload.end());
    auto lb = writeVI((int)body.size());
    std::vector<uint8_t> o;
    o.insert(o.end(),lb.begin(),lb.end()); o.insert(o.end(),body.begin(),body.end()); return o;
}

static std::string minecraftHash(const std::string& serverID,
                                  const uint8_t* sharedSecret, int ssLen,
                                  const uint8_t* serverKey, int skLen) {
    BCRYPT_ALG_HANDLE hAlg; BCRYPT_HASH_HANDLE hHash;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0);
    ULONG hashObjSize = 0, dummy = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjSize, sizeof(hashObjSize), &dummy, 0);
    std::vector<uint8_t> obj(hashObjSize), digest(20);
    BCryptCreateHash(hAlg, &hHash, obj.data(), hashObjSize, nullptr, 0, 0);
    BCryptHashData(hHash, (PUCHAR)serverID.data(), (ULONG)serverID.size(), 0);
    BCryptHashData(hHash, (PUCHAR)sharedSecret, ssLen, 0);
    BCryptHashData(hHash, (PUCHAR)serverKey, skLen, 0);
    BCryptFinishHash(hHash, digest.data(), 20, 0);
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0);

    bool negative = (digest[0] & 0x80) != 0;
    if (negative) {
        bool carry = true;
        for (int i = 19; i >= 0; i--) {
            int v = ~digest[i] + (carry ? 1 : 0);
            digest[i] = v & 0xFF; carry = (v > 0xFF);
        }
    }
    std::ostringstream ss;
    if (negative) ss << '-';
    bool leading = true;
    for (int i = 0; i < 20; i++) {
        if (leading && digest[i] == 0) continue;
        leading = false;
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)digest[i];
    }
    if (leading) return "0";
    return ss.str();
}

static std::vector<uint8_t> randomBytes(int n) {
    std::vector<uint8_t> buf(n);
    BCryptGenRandom(nullptr, buf.data(), n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return buf;
}

static bool parseDerPublicKey(const uint8_t* der, int derLen,
                               std::vector<uint8_t>& modulus,
                               std::vector<uint8_t>& exponent) {
    auto readLen = [](const uint8_t* p, int& consumed) -> int {
        consumed = 1;
        if (!(*p & 0x80)) return *p;
        int n = *p & 0x7F; consumed = 1 + n;
        int len = 0; for (int i = 0; i < n; i++) len = (len << 8) | p[1+i];
        return len;
    };
    int c;
    if (der[0] != 0x30) return false;
    int outerLen = readLen(der+1, c); const uint8_t* p = der+1+c;
    (void)outerLen;
    if (p[0] != 0x30) return false;
    int algLen = readLen(p+1, c); p += 1+c+algLen;
    if (p[0] != 0x03) return false;
    readLen(p+1, c); p += 1+c;
    p++;
    if (p[0] != 0x30) return false;
    readLen(p+1, c); p += 1+c;
    if (p[0] != 0x02) return false; int modLen = readLen(p+1, c); p += 1+c;
    modulus.assign(p, p+modLen); p += modLen;
    if (p[0] != 0x02) return false; int expLen = readLen(p+1, c); p += 1+c;
    exponent.assign(p, p+expLen);
    return true;
}

static std::vector<uint8_t> rsaEncryptPkcs1(const uint8_t* der, int derLen,
                                              const uint8_t* data, int dataLen) {
    std::vector<uint8_t> modulus, exponent;
    if (!parseDerPublicKey(der, derLen, modulus, exponent)) return {};

    size_t modStart = 0;
    while (modStart < modulus.size()-1 && modulus[modStart] == 0) modStart++;
    const uint8_t* mod = modulus.data() + modStart;
    int modLen = (int)(modulus.size() - modStart);

    ULONG blobSize = sizeof(BCRYPT_RSAKEY_BLOB) + (ULONG)exponent.size() + modLen;
    std::vector<uint8_t> blob(blobSize);
    auto* hdr = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob.data());
    hdr->Magic       = BCRYPT_RSAPUBLIC_MAGIC;
    hdr->BitLength   = modLen * 8;
    hdr->cbPublicExp = (ULONG)exponent.size();
    hdr->cbModulus   = modLen;
    hdr->cbPrime1 = hdr->cbPrime2 = 0;
    uint8_t* dst = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
    memcpy(dst, exponent.data(), exponent.size()); dst += exponent.size();
    memcpy(dst, mod, modLen);

    BCRYPT_ALG_HANDLE hAlg; BCRYPT_KEY_HANDLE hKey;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    BCryptImportKeyPair(hAlg, nullptr, BCRYPT_RSAPUBLIC_BLOB, &hKey, blob.data(), blobSize, 0);

    ULONG outLen = 0;
    BCRYPT_PKCS1_PADDING_INFO pad{};
    BCryptEncrypt(hKey, (PUCHAR)data, dataLen, &pad, nullptr, 0, nullptr, 0, &outLen, BCRYPT_PAD_PKCS1);
    std::vector<uint8_t> out(outLen);
    BCryptEncrypt(hKey, (PUCHAR)data, dataLen, &pad, nullptr, 0, out.data(), outLen, &outLen, BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

static std::vector<uint8_t> rsaDecryptPkcs1(BCRYPT_KEY_HANDLE key,
                                              const uint8_t* data, int dataLen) {
    ULONG outLen = 0;
    BCRYPT_PKCS1_PADDING_INFO pad{};
    BCryptDecrypt(key, (PUCHAR)data, dataLen, &pad, nullptr, 0, nullptr, 0, &outLen, BCRYPT_PAD_PKCS1);
    std::vector<uint8_t> out(outLen);
    BCryptDecrypt(key, (PUCHAR)data, dataLen, &pad, nullptr, 0, out.data(), outLen, &outLen, BCRYPT_PAD_PKCS1);
    out.resize(outLen);
    return out;
}

struct RsaKeyPair {
    BCRYPT_KEY_HANDLE key = nullptr;
    std::vector<uint8_t> derPub;
};

static void derLen(std::vector<uint8_t>& out, int len) {
    if (len < 128) { out.push_back((uint8_t)len); return; }
    if (len < 256) { out.push_back(0x81); out.push_back((uint8_t)len); return; }
    out.push_back(0x82); out.push_back((len>>8)&0xFF); out.push_back(len&0xFF);
}
static void derSeq(std::vector<uint8_t>& out, const std::vector<uint8_t>& inner) {
    out.push_back(0x30); derLen(out, (int)inner.size());
    out.insert(out.end(), inner.begin(), inner.end());
}
static void derInt(std::vector<uint8_t>& out, const uint8_t* data, int len) {
    out.push_back(0x02);
    bool needZero = len > 0 && (data[0] & 0x80);
    derLen(out, len + (needZero ? 1 : 0));
    if (needZero) out.push_back(0x00);
    out.insert(out.end(), data, data+len);
}

static RsaKeyPair generateRsa1024() {
    RsaKeyPair kp;
    BCRYPT_ALG_HANDLE hAlg;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    BCryptGenerateKeyPair(hAlg, &kp.key, 1024, 0);
    BCryptFinalizeKeyPair(kp.key, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    ULONG blobSize = 0, dummy = 0;
    BCryptExportKey(kp.key, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &blobSize, 0);
    std::vector<uint8_t> blob(blobSize);
    BCryptExportKey(kp.key, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), blobSize, &blobSize, 0);
    auto* hdr = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob.data());
    const uint8_t* expBytes = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
    const uint8_t* modBytes = expBytes + hdr->cbPublicExp;

    std::vector<uint8_t> rsaPub;
    derInt(rsaPub, modBytes, hdr->cbModulus);
    derInt(rsaPub, expBytes, hdr->cbPublicExp);
    std::vector<uint8_t> rsaPubSeq; derSeq(rsaPubSeq, rsaPub);

    std::vector<uint8_t> bitStr; bitStr.push_back(0x03);
    derLen(bitStr, (int)rsaPubSeq.size()+1); bitStr.push_back(0x00);
    bitStr.insert(bitStr.end(), rsaPubSeq.begin(), rsaPubSeq.end());

    static const uint8_t algId[] = {
        0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00
    };
    std::vector<uint8_t> inner(algId, algId+sizeof(algId));
    inner.insert(inner.end(), bitStr.begin(), bitStr.end());
    derSeq(kp.derPub, inner);
    return kp;
}

static std::string winhttp(const std::wstring& host, const std::wstring& path,
                            bool isPost, const std::string& body,
                            const std::wstring& extraHeaders = L"") {
    HINTERNET hSess = WinHttpOpen(L"proxy/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET hConn = WinHttpConnect(hSess, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hReq  = WinHttpOpenRequest(hConn, isPost ? L"POST" : L"GET", path.c_str(),
                                          nullptr, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    std::wstring hdrs = L"Content-Type: application/json\r\n";
    if (!extraHeaders.empty()) hdrs += extraHeaders + L"\r\n";
    WinHttpSendRequest(hReq, hdrs.c_str(), (DWORD)-1,
                       (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
    WinHttpReceiveResponse(hReq, nullptr);
    std::string result;
    DWORD avail = 0, read = 0;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        std::vector<char> buf(avail);
        WinHttpReadData(hReq, buf.data(), avail, &read);
        result.append(buf.data(), read);
    }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
    return result;
}

static void sessionJoin(const std::string& serverId,
                         const uint8_t* sharedSecret, int ssLen,
                         const uint8_t* serverPubKey, int spkLen) {
    std::string hash = minecraftHash(serverId, sharedSecret, ssLen, serverPubKey, spkLen);
    std::string body = "{\"accessToken\":\"" + AUTH_TOKEN + "\","
                       "\"selectedProfile\":\"" + AUTH_UUID + "\","
                       "\"serverId\":\"" + hash + "\"}";
    winhttp(L"sessionserver.mojang.com", L"/session/minecraft/join", true, body);
}

static std::string sessionHasJoined(const std::string& username, const std::string& serverHash) {
    std::wstring path = L"/session/minecraft/hasJoined?username=" +
                        std::wstring(username.begin(), username.end()) +
                        L"&serverId=" + std::wstring(serverHash.begin(), serverHash.end());
    return winhttp(L"sessionserver.mojang.com", path, false, "");
}

static std::string clientRecvLoginStart(SOCKET cs) {
    std::vector<uint8_t> pkt;
    if (!readPkt(cs, pkt)) return {};
    int32_t len; int hl = readVI(pkt.data(),(int)pkt.size(),&len);
    const uint8_t* p = pkt.data()+hl; int rem = len;
    int32_t id; int il = readVI(p,rem,&id); p+=il; rem-=il;
    if (id != 0x00) return {};
    int32_t pv; int pvl=readVI(p,rem,&pv); p+=pvl; rem-=pvl;
    int32_t sl; int sll=readVI(p,rem,&sl); p+=sll+sl; rem-=sll+sl;
    p+=2; rem-=2;
    int32_t ns; readVI(p,rem,&ns);
    if (ns == 1) {
        readPkt(cs, pkt);
        std::string json=R"({"version":{"name":"1.8.9","protocol":47},"players":{"max":1,"online":0},"description":{"text":"Proxy"}})";
        std::vector<uint8_t> rp; appendStr(rp, json);
        auto full = buildPkt(0x00, rp); sendN(cs, full.data(), (int)full.size());
        readPkt(cs, pkt); sendN(cs, pkt.data(), (int)pkt.size());
        return {};
    }
    if (ns != 2) return {};
    if (!readPkt(cs, pkt)) return {};
    hl = readVI(pkt.data(),(int)pkt.size(),&len);
    p = pkt.data()+hl; rem = len;
    il = readVI(p,rem,&id); p+=il; rem-=il;
    if (id != 0x00) return {};
    int32_t uLen; int ul=readVI(p,rem,&uLen); p+=ul;
    return std::string((char*)p, uLen);
}

static bool clientDoLogin(SOCKET cs, const std::string& username,
                           RsaKeyPair& rsa, int comprThresh,
                           AesCfb8& sendCipher, AesCfb8& recvCipher) {
    auto verifyToken = randomBytes(4);
    {
        std::vector<uint8_t> payload;
        appendStr(payload, "");
        auto vi = writeVI((int)rsa.derPub.size());
        payload.insert(payload.end(), vi.begin(), vi.end());
        payload.insert(payload.end(), rsa.derPub.begin(), rsa.derPub.end());
        auto vt = writeVI(4);
        payload.insert(payload.end(), vt.begin(), vt.end());
        payload.insert(payload.end(), verifyToken.begin(), verifyToken.end());
        auto pkt = buildPkt(0x01, payload);
        if (!sendN(cs, pkt.data(), (int)pkt.size())) return false;
    }

    std::vector<uint8_t> pkt;
    if (!readPkt(cs, pkt)) return false;
    {
        int32_t len; int hl=readVI(pkt.data(),(int)pkt.size(),&len);
        const uint8_t* p=pkt.data()+hl; int rem=len;
        int32_t id; int il=readVI(p,rem,&id); p+=il; rem-=il;
        if (id != 0x01) return false;

        int32_t ssEncLen; int sslL=readVI(p,rem,&ssEncLen); p+=sslL; rem-=sslL;
        auto sharedSecret = rsaDecryptPkcs1(rsa.key, p, ssEncLen); p+=ssEncLen; rem-=ssEncLen;
        if (sharedSecret.size() != 16) return false;

        int32_t vtEncLen; int vtlL=readVI(p,rem,&vtEncLen); p+=vtlL;
        auto vtDec = rsaDecryptPkcs1(rsa.key, p, vtEncLen);
        if (vtDec.size() != 4 || memcmp(vtDec.data(), verifyToken.data(), 4) != 0) return false;

        std::string hash = minecraftHash("", sharedSecret.data(), 16,
                                          rsa.derPub.data(), (int)rsa.derPub.size());
        auto resp = sessionHasJoined(username, hash);
        if (resp.find("\"id\"") == std::string::npos) {
            std::cerr << "[!] " << username << " failed Mojang auth\n";
            return false;
        }

        sendCipher.init(sharedSecret.data(), sharedSecret.data());
        recvCipher.init(sharedSecret.data(), sharedSecret.data());
    }

    if (comprThresh >= 0) {
        auto v = writeVI(comprThresh);
        auto pkt2 = buildPkt(0x03, v);
        if (!sendPkt(cs, pkt2, &sendCipher)) return false;
    }
    {
        std::vector<uint8_t> payload;
        appendStr(payload, "00000000-0000-0000-0000-000000000000");
        appendStr(payload, username);
        auto pkt2 = comprThresh >= 0 ? buildPktComp(0x02, payload) : buildPkt(0x02, payload);
        if (!sendPkt(cs, pkt2, &sendCipher)) return false;
    }
    return true;
}

static bool serverDoLogin(SOCKET ss, const std::string& username, int& comprThresh,
                           AesCfb8& sendCipher, AesCfb8& recvCipher) {
    comprThresh = -1;
    {
        std::vector<uint8_t> payload;
        auto pv = writeVI(47); payload.insert(payload.end(),pv.begin(),pv.end());
        appendStr(payload, CFG_HOST);
        payload.push_back((CFG_SRV_PORT>>8)&0xFF); payload.push_back(CFG_SRV_PORT&0xFF);
        auto ns = writeVI(2); payload.insert(payload.end(),ns.begin(),ns.end());
        auto hsPkt = buildPkt(0x00, payload);
        if (!sendN(ss, hsPkt.data(), (int)hsPkt.size())) return false;
    }
    {
        std::vector<uint8_t> payload; appendStr(payload, username);
        auto pkt = buildPkt(0x00, payload);
        if (!sendN(ss, pkt.data(), (int)pkt.size())) return false;
    }

    std::vector<uint8_t> pkt;
    while (true) {
        AesCfb8* rc = recvCipher.key ? &recvCipher : nullptr;
        if (!readPkt(ss, pkt, rc)) return false;
        int32_t len; int hl=readVI(pkt.data(),(int)pkt.size(),&len);
        const uint8_t* p=pkt.data()+hl; int rem=len;
        int32_t id; int il=readVI(p,rem,&id); p+=il; rem-=il;
        if (comprThresh >= 0) {
            int32_t realId; int ril=readVI(p,rem,&realId); p+=ril; rem-=ril;
            id = realId;
        }

        if (id == 0x02) return true;

        if (id == 0x03) {
            int32_t thresh; readVI(p, rem, &thresh); comprThresh = thresh;
            continue;
        }

        if (id == 0x01) {
            int32_t sLen; int slL=readVI(p,rem,&sLen); p+=slL;
            std::string serverID((char*)p, sLen); p+=sLen; rem-=slL+sLen;

            int32_t pkLen; int pkl=readVI(p,rem,&pkLen); p+=pkl;
            std::vector<uint8_t> serverPubKey(p, p+pkLen); p+=pkLen; rem-=pkl+pkLen;

            int32_t vtLen; int vtl=readVI(p,rem,&vtLen); p+=vtl;
            std::vector<uint8_t> verifyToken(p, p+vtLen);

            auto sharedSecret = randomBytes(16);
            sessionJoin(serverID, sharedSecret.data(), 16,
                        serverPubKey.data(), (int)serverPubKey.size());

            auto encSS = rsaEncryptPkcs1(serverPubKey.data(), (int)serverPubKey.size(),
                                          sharedSecret.data(), 16);
            auto encVT = rsaEncryptPkcs1(serverPubKey.data(), (int)serverPubKey.size(),
                                          verifyToken.data(), (int)verifyToken.size());
            if (encSS.empty() || encVT.empty()) return false;

            {
                std::vector<uint8_t> payload;
                auto vi1 = writeVI((int)encSS.size());
                payload.insert(payload.end(),vi1.begin(),vi1.end());
                payload.insert(payload.end(),encSS.begin(),encSS.end());
                auto vi2 = writeVI((int)encVT.size());
                payload.insert(payload.end(),vi2.begin(),vi2.end());
                payload.insert(payload.end(),encVT.begin(),encVT.end());
                auto pkt2 = buildPkt(0x01, payload);
                if (!sendN(ss, pkt2.data(), (int)pkt2.size())) return false;
            }

            sendCipher.init(sharedSecret.data(), sharedSecret.data());
            recvCipher.init(sharedSecret.data(), sharedSecret.data());
            continue;
        }

        if (id == 0x00) return false;
    }
}

struct Conn { SOCKET cs, ss; std::atomic<bool> alive{true}; AesCfb8 cRecv, cSend, sRecv, sSend; };

static void relay(SOCKET from, SOCKET to, AesCfb8* dec, AesCfb8* enc, Conn* c) {
    std::vector<uint8_t> buf(65536), out(65536);
    while (c->alive) {
        int n = recv(from, (char*)buf.data(), (int)buf.size(), 0);
        if (n <= 0) { c->alive = false; return; }
        if (dec) dec->decrypt(buf.data(), buf.data(), n);
        const uint8_t* src = buf.data();
        if (enc) { enc->encrypt(buf.data(), out.data(), n); src = out.data(); }
        if (!sendN(to, src, n)) { c->alive = false; return; }
    }
}

static RsaKeyPair g_rsa;

static void handleClient(SOCKET clientSock) {
    std::string username = clientRecvLoginStart(clientSock);
    if (username.empty()) { closesocket(clientSock); return; }
    std::cout << "[+] " << username << "\n";

    SOCKET serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(CFG_HOST.c_str(), std::to_string(CFG_SRV_PORT).c_str(), &hints, &res) || !res ||
        connect(serverSock, res->ai_addr, (int)res->ai_addrlen)) {
        std::cerr << "[!] Cannot reach " << CFG_HOST << "\n";
        freeaddrinfo(res); closesocket(clientSock); closesocket(serverSock); return;
    }
    freeaddrinfo(res);

    auto c = std::make_shared<Conn>();
    c->cs = clientSock; c->ss = serverSock;

    int comprThresh = -1;
    if (!serverDoLogin(serverSock, username, comprThresh, c->sSend, c->sRecv)) {
        std::cerr << "[!] Server login failed for " << username << "\n";
        closesocket(clientSock); closesocket(serverSock); return;
    }
    if (!clientDoLogin(clientSock, username, g_rsa, comprThresh, c->cSend, c->cRecv)) {
        std::cerr << "[!] Client auth failed for " << username << "\n";
        closesocket(clientSock); closesocket(serverSock); return;
    }

    std::cout << "[+] " << username << " in game\n";

    std::atomic<bool> closed{false};
    auto cleanup = [&]() {
        if (!closed.exchange(true)) { c->alive = false; closesocket(clientSock); closesocket(serverSock); }
    };

    std::thread t1([&]{ relay(serverSock, clientSock, &c->sRecv, &c->cSend, c.get()); cleanup(); });
    std::thread t2([&]{ relay(clientSock, serverSock, &c->cRecv, &c->sSend, c.get()); cleanup(); });
    t1.join(); t2.join();
    std::cout << "[-] " << username << "\n";
}

int main() {
    loadFiles();
    initAes();
    g_rsa = generateRsa1024();

    std::cout << "Logged in as : " << AUTH_USERNAME << "\n";
    std::cout << "Target       : " << CFG_HOST << ":" << CFG_SRV_PORT << "\n";

    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int opt = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_port = htons(CFG_BIND_PORT); addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(ls,(sockaddr*)&addr,sizeof(addr)) || listen(ls,5)) {
        std::cerr << "[!] Cannot bind :" << CFG_BIND_PORT << "\n"; return 1;
    }
    std::cout << "Listening on  :" << CFG_BIND_PORT << "\n";

    while (true) {
        SOCKET cs = accept(ls, nullptr, nullptr);
        if (cs != INVALID_SOCKET) std::thread(handleClient, cs).detach();
    }
    WSACleanup();
}
