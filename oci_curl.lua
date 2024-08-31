-- To run you need lua and http
-- On MacOS:
-- brew install lua luarocks
-- luarocks install http base64
-- -- I also got this error for some reason: Failed to locate 'm4'
-- -- Solved it with: sudo ln -s /Library/Developer/CommandLineTools/usr/bin/gm4 /Library/Developer/CommandLineTools/usr/bin/m4
-- Implementation based on: https://www.ateam-oracle.com/post/oracle-cloud-infrastructure-oci-rest-call-walkthrough-with-curl

function parse_arguments(args)
    local request = {method = "GET", url = nil, body = nil, headers = {}}
    local oci = { profile = "DEFAULT", config_file = "~/.oci/config" }
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
        elseif key == 'p' then
            oci.profile = value
        elseif key == 'c' then
            oci.config_file = value
        elseif key == 'v' then
            debug = true
        else
            request.url = value
        end
        i = i + 1
    end

    return request, oci, debug
end

-- Read OCI config file
function get_oci_profile(config_file, profile)
    local file = io.open(config_file:gsub("~", os.getenv( "HOME" )), "r")
    local current_profile = nil
    local profile_config = {}

    for line in file:lines() do
        if string.sub(line, 1, 1) == '[' and string.sub(line, #line, #line) == ']' then
            current_profile = line:sub(2, #line - 1)
        elseif profile == current_profile then
            local index = line:find("=")
            if index then
                local key = line:sub(1, index - 1):gsub("%s", "")
                local value = line:sub(index + 1):gsub("%s", "")
                profile_config[key] = value
            end
        end
    end
    file:close()

    return profile_config
end

function print_debug(...)
    local param={...}
    for i=1,#param do
        param[i] = param[i]:gsub("\n", "\nDEBUG:  ")
    end
    print("DEBUG:", table.unpack(param))
end

function create_signature(to_sign, private_key_path)
    local file = io.open(private_key_path, "rb")
    local key_string = file:read("*all")
    file:close()

    local openssl_pkey = require "openssl.pkey"
    local openssl_digest = require "openssl.digest"
    local base64 = require "base64"

    local key = openssl_pkey:new("")
    key:setPrivateKey(key_string)
    local data = openssl_digest.new("sha256")
    data:update(to_sign)
    return base64.encode(key:sign(data))
end

function create_sha(to_hash)
    local openssl_digest = require "openssl.digest"
    local base64 = require "base64"

    return base64.encode(openssl_digest.new("sha256"):final(to_hash))
end

function sign_request(request, oci, debug)
    if not oci.profile_config or not oci.profile_config.user then
        error("Only API Key based authentication is supported")
    end

    local key_id = string.format("%s/%s/%s", oci.profile_config.tenancy,
            oci.profile_config.user, oci.profile_config.fingerprint)
    sign_request_with_key_id(request, key_id, oci.profile_config.key_file, debug)
end

function sign_request_with_key_id(request, key_id, key_file, debug)
    -- See https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm

    local date = os.date("!%a, %d %h %Y %H:%M:%S GMT")
    request.headers["date"] = date

    -- path includes query parameters
    local host, path = request.url:match("https://([^/]+)(/.+)")
    local request_target = string.format("%s %s", request.method:lower(), path)

    local required_headers = "(request-target) date host"
    local to_sign = string.format("(request-target): %s\ndate: %s\nhost: %s", request_target, date, host)
    if request.method == "PUT" or request.method == "POST" then
        required_headers = required_headers .. " x-content-sha256 content-type content-length"
        local content_sha = create_sha(request.body)
        request.headers["x-content-sha256"] = content_sha
        to_sign = to_sign .. string.format(
                "\nx-content-sha256: %s\ncontent-type: %s\ncontent-length: %s",
                content_sha, request.headers["content-type"], request.headers["content-length"]
        )
    end

    if debug then
        print_debug("Required headers for signing:", required_headers)
        print_debug("Signing the following string:", to_sign)
    end
    local signature = create_signature(to_sign, key_file)
    local header_value = string.format(
            'Signature version="1",keyId="%s",algorithm="rsa-sha256",headers="%s",signature="%s"',
            key_id, required_headers, signature
    )
    request.headers["Authorization"] = header_value
end

function send_request(request_data, debug)
    local http_request = require "http.request"
    local http_headers = require "http.headers"

    if debug then
        print_debug("Request: ")
        print_debug("=========")
        print_debug(string.format("%s %s", request_data.method, request_data.url))
        for k,v in pairs(request_data.headers) do
            print_debug(string.format("%s: %s", k, v))
        end
        if (request_data.body) then
            print_debug(request_data.body)
        end
        print_debug("=========")
    end

    local headers = http_headers.new()
    headers:append(":method", request_data.method)
    local request = http_request.new_from_uri(request_data.url, headers)
    for k, v in pairs(request_data.headers) do
        request.headers:append(k, v)
    end
    if request_data.body then
        request:set_body(request_data.body)
    end

    local headers, stream = assert(request:go())
    local status = headers:get(":status")
    local body = stream:get_body_as_string()

    if debug then
        print_debug("Response: ")
        print_debug("=========")
        print_debug(status)
        for k, v in pairs(headers) do
            if k ~= ":status" then
                print_debug(string.format("%s: %s", k, v))
            end
        end
        if (body) then
            print_debug(body)
        end
        print_debug("=========")
    end

    if status:sub(1, 1) ~= "2" then
        print("ERROR:  Non-2xx response status code:", status)
    end
    return body
end

function main(args)
    if #args == 0 then
        print("oci_curl.lua")
        print("Usage:")
        print("    lua oci_curl.lua [url] [optional arguments]")
        print("Arguments:")
        print("       url             The request URL")
        print("    -H header: value   A header")
        print("    -X method          The HTTP method")
        print("    -d body            The body data")
        print("    -c OCI config      The path to OCI config")
        print("    -p OCI profile     The OCI profile to use")
        print("    -v                 Run in verbose mode")
        print("Examples:")
        print("    lua oci_curl.lua https://objectstorage.us-phoenix-1.oraclecloud.com/n/")
        print("    lua oci_curl.lua -X POST https://logging.us-phoenix-1.oci.oraclecloud.com/20200531/logGroups/" ..
                " -d '{\"compartmentId\":\"<id>\",\"displayName\":\"test-log-group\"}'")
        print("    lua oci_curl.lua -X DELETE 'https://logging.us-phoenix-1.oci.oraclecloud.com/20200531/logGroups/<id>' -v")
        print("    lua oci_curl.lua 'https://logging.us-phoenix-1.oci.oraclecloud.com/20200531/logGroups?compartmentId=<id>&displayName=test-log-group'")
        return
    end

    local request, oci, debug = parse_arguments(args)
    if oci.config_file and oci.profile then
        oci.profile_config = get_oci_profile(oci.config_file, oci.profile)
    end

    if request.body then
        if not request.headers["content-length"] then
            request.headers["content-length"] = #request.body
        end
        if not request.headers["content-type"] then
            request.headers["content-type"] = "application/json"
        end
    end

    sign_request(request, oci, debug)
    local response_body = send_request(request, debug)
    print(response_body)
end

main({...})
