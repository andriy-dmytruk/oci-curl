require("oci_curl_common")

function parse_arguments(args)
    local request = {method = "GET", url = nil, body = nil, headers = {}}
    local session
    local debug = false

    local i = 1
    while i <= #args do
        local key, value
        if (string.sub(args[i], 1, 1) == '-') then
            if #args[i] == 2 and args[i] ~= '-v' then
                key, value = args[i]:sub(2, 2), args[i + 1]
                i = i + 1
            else
                key, value = args[i]:sub(2, 2), string.sub(args[i], 3)
            end
        else
            value = args[i]
        end

        if key == "H" then
            local index = value:find(": ")
            if index then
                request.headers[value:sub(1, index - 1)] = value:sub(index + 2):lower()
            else
                request.headers[value] = true
            end
        elseif key == 'X' then
            request.method = value
        elseif key == 'd' then
            request.body = value
        elseif key == 's' then
            session = value
        elseif key == 'v' then
            debug = true
        else
            request.url = value
        end
        i = i + 1
    end

    return request, session, debug
end

function parse_session(session_string)
    local token = session_string:match('"token"%s*:%s*"(%S+)"')
    local private_key_string = session_string:match('"private_key"%s*:%s*"([^"]+)"')

    local openssl_pkey = require "openssl.pkey"
    local key = openssl_pkey.new()
    key:setPrivateKey(private_key_string)
    return { token = token, private_key = key }
end

function main(args)
    if #args == 0 then
        print("oci_curl_sign_session.lua")
        print("Usage:")
        print("    lua oci_curl_sign_session.lua [url] [optional arguments]")
        print("Arguments:")
        print("       url             The request URL")
        print("    -H header: value   A header")
        print("    -X method          The HTTP method")
        print("    -d body            The body data")
        print"     -s session         The session in same format as returned from oci_curl_init_session.lua"
        print("    -v                 Run in verbose mode")
        return
    end

    local request, session_string, debug = parse_arguments(args)
    if debug then
        print_debug("Starting in debug mode")
    end
    if not session_string then
        error("Argument -s session is required")
    end
    local session = parse_session(session_string)

    local key_id = string.format("ST$%s", session.token)
    sign_request_with_key_id(request, key_id, session.private_key, debug)

    local result = '{'
    for k,v in pairs(request.headers) do
        if k == "Authorization" or k == "x-content-sha256"
                or k == "content-length" or k == "content-type" or k == "date" then
            if #result > 1 then
                result = result .. ','
            end
            result = result .. '"' .. k:gsub('"', '\\"') .. '":"' .. v:gsub('"', '\\"') .. '"'
        end
    end
    result = result .. '}'
    print(result)
end

main({...})
