local _M = { _VERSION = 0.1 }
local jwt = require "resty.session.jwt"

local new_tab = require "table.new"
local clone_tab = require "table.clone"

local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string

local b64u_decode = require "ngx.base64".decode_base64url
local b64u_encode = require "ngx.base64".encode_base64url

local sub = string.sub
local concat = table.concat
local format = string.format
local http_time = ngx.http_time

ffi.cdef[[
typedef struct evp_cipher_st EVP_CIPHER;
const EVP_CIPHER *EVP_aes_256_gcm(void);

typedef struct evp_enc_ctx_st EVP_CIPHER_CTX;
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new();
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, const void *ptr);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);

int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
        const unsigned char *salt, const unsigned char *data,
        int datal, int count, unsigned char *key, unsigned char *iv);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
        const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
        int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
]]

local EVP_CTRL_AEAD_GET_TAG = 0x10
local EVP_CTRL_AEAD_SET_TAG = 0x11

local session = {}
local session_mt = { __index = session }

local EVP_aes_256_gcm = C.EVP_aes_256_gcm()
local out_len, tmp_len = ffi.new("int[1]"), ffi.new("int[1]")
local str_buf_size, string_buffer_t, str_buf = 4096, ffi.typeof('char[?]')

local function string_buffer(size, must_alloc)
    if size > str_buf_size or must_alloc then
        return string_buffer_t(size)
    end

    if not str_buf then
        str_buf = string_buffer_t(str_buf_size)
    end

    return str_buf
end


_M.new = function(config)
    local cek, private_key = config.encryption_key, config.signing_key
    if not cek or #cek ~= 32 then
        return nil, "secret must be defined and have length == 32"
    end

    if not private_key then
        return nil, "ec_key must be defined"
    end

    local enc_ctx = ffi.gc(C.EVP_CIPHER_CTX_new(), C.EVP_CIPHER_CTX_free)
    if not enc_ctx then
        return nil, "EVP_CIPHER_CTX_new(): no memory"
    end

    local dec_ctx = ffi.gc(C.EVP_CIPHER_CTX_new(), C.EVP_CIPHER_CTX_free)
    if not dec_ctx then
        return nil, "EVP_CIPHER_CTX_new(): no memory"
    end

    if C.EVP_EncryptInit_ex(enc_ctx, EVP_aes_256_gcm, nil, nil, nil) ~= 1 then
        return nil, "EVP_EncryptInit_ex"
    end

    if C.EVP_DecryptInit_ex(dec_ctx, EVP_aes_256_gcm, nil, nil, nil) ~= 1 then
        return nil, "EVP_DecryptInit_ex"
    end

    local _jwt, err = jwt.new(private_key)
    if not _jwt then
        return nil, err
    end

    local cookie_name = config.cookie_name or 'me'
    local params = { ';path=' .. (config.cookie_path or '/') }
    params[#params + 1] = config.cookie_domain
    params[#params + 1] = not config.cookie_httponly and nil or 'HttpOnly'
    params[#params + 1] = config.cookie_secure and 'Secure'
    params = concat(params, ';')

    local chunk_size = (config.chunk_size or 4000)
    	- #('Set-Cookie: ') - #cookie_name
	- #(';expires=' .. http_time(0)) - #params

    if chunk_size < 200 then
        return nil, "too small chunk_size"
    end

    local self = {
        _ttl = config.ttl or 86400,
        _iv = sub(ngx.md5_bin(cek), -12),
        _cek = cek,
        _jwt = _jwt,
        _enc_ctx = enc_ctx,
        _dec_ctx = dec_ctx,
        _params = params,
        _delete = format('null; path=%s; expires=%s', params[1], http_time(0)),
        _chunk_size = chunk_size,
        _cookie = {
            'cookie_',
	    cookie_name,
            '(chunk#)',                        -- 3
            '=',
            '(cookie_value)',                  -- 5
            ';expires=',
            '(Thu, 01 Jan 1970 00:00:00 GMT)', -- 7
            params
        }
    }

    return setmetatable(self, session_mt)
end

function session:decrypt(data)
    data = b64u_decode(data)
    if not data then
        return nil, "invalid base64url data"
    end

    local ctx, data_len = self._dec_ctx, #data - 16

    if data_len < 1 then -- todo: min block size?
        return nil, "invalid data"
    end

    if C.EVP_DecryptInit_ex(ctx, nil, nil, self._cek, self._iv) ~= 1 then
        return nil, "EVP_DecryptInit_ex"
    end

    ---- set the GCM mode authentication tag
    if C.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, sub(data, -16)) ~= 1 then
        return nil, "EVP_CIPHER_CTX_ctrl"
    end

    local buf = string_buffer(data_len) -- todo: can this be calculated?
    if C.EVP_DecryptUpdate(ctx, buf, out_len, sub(data, 1, -17), data_len) ~= 1 or
        C.EVP_DecryptFinal_ex(ctx, buf + out_len[0], tmp_len) ~= 1 then
         return nil, "EVP_DecryptUpdate|EVP_DecryptFinal_ex"
    end

    return ffi_str(buf, out_len[0] + tmp_len[0])
end

function session:encrypt(data)
    local ctx, data_len = self._enc_ctx, #(data or '')

    if C.EVP_EncryptInit_ex(ctx, nil, nil, self._cek, self._iv) ~= 1 then
        return nil, "EVP_EncryptInit_ex"
    end

    local buf = string_buffer(data_len + 16)
    if C.EVP_EncryptUpdate(ctx, buf, out_len, data, data_len) ~= 1 or
        C.EVP_EncryptFinal_ex(ctx, buf + out_len[0], tmp_len) ~= 1 then
        return nil, "EVP_EncryptUpdate|EVP_EncryptFinal_ex"
    end

    ---- get the GCM mode authentication tag
    if C.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, buf + out_len[0] + tmp_len[0]) ~= 1 then
        return nil, "EVP_CIPHER_CTX_ctrl"
    end

    return b64u_encode(ffi_str(buf, out_len[0] + tmp_len[0] + 16))
end

local cookie_jar = new_tab(20,0)
function session:set_chunked_cookie(data, err)
    if not data then
        return nil, err
    end

    local cookie, chunk_size = self._cookie, self._chunk_size


    cookie[7] = http_time(ngx.time() + self._ttl)

    local remaining, sent, chunks, send_len = #data, 0
    for chunk=0,19 do
        cookie[3] = chunk == 0 and '' or tostring(chunk)
        send_len = chunk_size - #cookie[3] - 1
        cookie[5] = sub(data, sent + 1, sent + send_len)
        remaining, sent = remaining - send_len, sent + send_len
        cookie_jar[chunk + 1], chunks = concat(cookie, '', 2, 8), chunk + 1

        if remaining <= 0 then
            break
        end
    end

    if remaining > 0 then
        return nil, "out of space"
    end

    cookie[5] = nil
    for chunk=20,chunks+1,-1 do
        cookie[3] = chunk - 1

        if not cookie[5] and ngx.var[concat(cookie, '', 1, 3)] ~= nil then
            cookie[5] = self._delete
        end

        cookie_jar[chunk] = cookie[5] and concat(cookie, '', 2, 5)
    end

    ngx.header.Set_Cookie = clone_tab(cookie_jar) -- todo: clone needed?

    return true
end

function session:get_chunked_cookie()
    local cookie = self._cookie
    for chunk=0,19 do
        cookie[3] = chunk == 0 and '' or chunk
        cookie_jar[chunk + 1] = ngx.var[concat(cookie, '', 1, 3)]

        if cookie_jar[chunk + 1] == nil then
            return chunk > 0 and concat(cookie_jar, '', 1, chunk)
        end
    end

    return false
end

function session:save(data)
    if ngx.headers_sent then
        ngx.log(ngx.ERR, "session.save: headers_sent")
        return nil, "headers_sent"
    end

    local signed, err = self._jwt:create(data)
    if not signed then
        return nil, err
    end

    return self:set_chunked_cookie(self:encrypt(signed))
end

function session:load()
    local cookie_data, err = self:get_chunked_cookie()
    if not cookie_data then
        return nil, err
    end

    local signed, err = self:decrypt(cookie_data)
    if not signed then
        return nil, err
    end

    local data, err = self._jwt:verify(signed)
    if not data then
        return nil, err
    end

    return data
end

return _M
