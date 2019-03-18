Name
====

lua-resty-session - `aes256gcm(jwt(RS256, session_data))`

Status
======

This is work in progress

Usage
=====

```lua
local session = require "resty.session".new{
	chunk_size = 2000,
	signing_key = [[-----BEGIN RSA PRIVATE KEY-----]]
	encryption_key = '12345678901234567890123456789012',
}	

local ok, err = session:save{ foo = "bar" }
local session_data, err = session:load()
```
