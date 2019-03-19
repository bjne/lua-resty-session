local _M = { __VERSION = 0.1 }

local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string

--local json_decode = require "cjson.safe".decode
local json_encode = require "cjson.safe".encode
local b64u_decode = require "ngx.base64".decode_base64url
local b64u_encode = require "ngx.base64".encode_base64url

local sub = string.sub
local match = string.match
local concat = table.concat

--[[
    openssl 1.1.0g
    Intel(R) Core(TM) i7-6500U CPU @ 2.50GHz (2cores 4threads)

    # openssl speed -mb -multi +4 ecdsap256 rsa1024
                      sign    verify    sign/s verify/s
    rsa 1024 bits 0.000057s 0.000004s  17680.8 276190.5
                                  sign    verify    sign/s verify/s
     256 bit ecdsa (nistp256)   0.0000s   0.0000s  23088.9  20486.9
--]]

ffi.cdef[[
typedef struct bio_method_st BIO_METHOD;
BIO_METHOD *BIO_s_mem(void);

typedef struct bio_st BIO;
BIO *BIO_new(BIO_METHOD *type);
int BIO_puts(BIO *bp, const char *buf);
void BIO_vfree(BIO *a);

typedef struct evp_pkey_st EVP_PKEY;
EVP_PKEY *EVP_PKEY_new(void);
int EVP_PKEY_size(EVP_PKEY *pkey);
void EVP_PKEY_free(EVP_PKEY *key);

typedef struct engine_st ENGINE;
typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const unsigned char *in, int inl);
int EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *sig,unsigned int *s,
        EVP_PKEY *pkey);


int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
        unsigned int siglen, EVP_PKEY *pkey);

typedef int pem_password_cb(char *buf, int size, int rwflag, void *u);

const EVP_MD *EVP_sha256(void);

/* RSA */
typedef struct rsa_st RSA;
RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u);
RSA *PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **x, pem_password_cb *cb, void *u);
int EVP_PKEY_set1_RSA(EVP_PKEY *e, RSA *r);
void RSA_free(RSA *rsa);
]]

local jwt = {}
local jwt_mt = { __index = jwt }

local unsigned_char_t = ffi.typeof('unsigned char[?]')
local unsigned_int_t = ffi.typeof('unsigned int[?]')

local rsa_pkey = function(pem, password, private)
    local read = C['PEM_read_bio_RSA' .. (private and 'PrivateKey' or '_PUBKEY')]

    local bio_method = C.BIO_s_mem()
    local bio = ffi.gc(C.BIO_new(bio_method), C.BIO_vfree)

    if C.BIO_puts(bio, pem) <= 0 then
        return nil, "BIO_puts"
    end

    -- password?

    local key = ffi.gc(read(bio, nil, nil, nil), C.RSA_free)
    if key == nil then
        return nil, "PEM_read_" .. (private and 'private_key' or 'public_key')
    end

    local pkey = ffi.gc(C.EVP_PKEY_new(), C.EVP_PKEY_free)
    if pkey == nil then
        return nil, "EVP_PKEY_new: no memory"
    end

    if C.EVP_PKEY_set1_RSA(pkey, key) ~= 1 then
        return nil, "EVP_PKEY_set1_RSA"
    end

    -- todo: collect some garbage?

    return pkey
end

_M.new = function(private_key, password)
    local pkey, err = rsa_pkey(private_key, password, true)
    if not pkey then
        return nil, err
    end

    local md_ctx = ffi.gc(C.EVP_MD_CTX_new(), C.EVP_MD_CTX_free)
    if md_ctx == nil then
        return nil, "EVP_MD_CTX_new: no memory"
    end

    if C.EVP_DigestInit_ex(md_ctx, C.EVP_sha256(), nil) ~= 1 then
        return nil, "EVP_DigestInit_ex"
    end

    local _jwt = {b64u_encode('{"alg":"RS256"}')}

    local self = {
        _jwt = _jwt,
        _pkey = pkey,
        _hdr = _jwt[1] .. '.',
        _hdr_len = #_jwt[1],
        _md_ctx = md_ctx,
        _md_buf = unsigned_char_t(C.EVP_PKEY_size(pkey)),
        _md_len = unsigned_int_t(1)
    }

    return setmetatable(self, jwt_mt)
end

local sign_or_verify = function(self, sig)
    local md_ctx, md_buf, md_len = self._md_ctx, self._md_buf, self._md_len

    local data = concat(self._jwt, '.', 1, 2)

    if C.EVP_DigestInit_ex(md_ctx, nil, nil) ~= 1 then
        return nil, "EVP_DigestInit_ex"
    end

    if C.EVP_DigestUpdate(md_ctx, data, #data) <= 0 then
        return nil, "EVP_DigestUpdate"
    end

    if sig ~= nil then
        return C.EVP_VerifyFinal(md_ctx, sig, #sig, self._pkey) == 1
    end

    if C.EVP_SignFinal(md_ctx, md_buf, md_len, self._pkey) <= 0 then
        return nil, "EVP_SignFinal"
    end

    self._jwt[3] = b64u_encode(ffi_str(md_buf, md_len[0]))

    return concat(self._jwt, '.', 1, 3)
end

function jwt:create(data)
    data = type(data) == 'table' and json_encode(data) or tostring(data)
    self._jwt[2] = b64u_encode(data)

    return sign_or_verify(self)
end

function jwt:verify(data)
    if sub(data, 1, self._hdr_len + 1) ~= self._hdr then
        return false
    end

    local sig
    self._jwt[2], sig = match(sub(data, self._hdr_len + 2), '^([^.]+)%.([^.]+)$')
    if not sig then
        return false
    end

    sig = b64u_decode(sig)
    if sig == nil then
        return false
    end

    if sign_or_verify(self, sig) then
        return b64u_decode(self._jwt[2])
    end

    return false
end

-- openssl genrsa 2048|tee rsa_key.pem|openssl rsa -pubout -out rsa_pub.pem

return _M
