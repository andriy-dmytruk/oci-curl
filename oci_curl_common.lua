-- Implementation based on: https://www.ateam-oracle.com/post/oracle-cloud-infrastructure-oci-rest-call-walkthrough-with-curl

-- Read OCI config file
function get_oci_profile(config_file, profile)
    local file = io.open(config_file:gsub("~", os.getenv( "HOME" )), "r")
    if not file then
        error("Could not find OCI config file at " .. config_file)
    end
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

    if not profile_config.fingerprint then
        error("Parsing of profile " .. profile .. " from OCI config file " .. config_file .. " failed")
    end

    return profile_config
end

function print_debug(...)
    local param={...}
    for i=1,#param do
        param[i] = param[i]:gsub("\n", "\nDEBUG:  ")
    end
    print("DEBUG:", table.unpack(param))
end

function read_key_from_file(private_key_path)
    local file = assert(io.open(private_key_path, "rb"))
    local key_string = file:read("*all")
    file:close()

    local openssl_pkey = require "openssl.pkey"
    local key = openssl_pkey.new()
    key:setPrivateKey(key_string)
    return key
end

function create_signature(to_sign, private_key)
    local openssl_digest = require "openssl.digest"
    local base64 = require "base64"

    local data = openssl_digest.new("sha256")
    data:update(to_sign)
    return base64.encode(private_key:sign(data))
end

function create_sha(to_hash)
    local openssl_digest = require "openssl.digest"
    local base64 = require "base64"

    return base64.encode(openssl_digest.new("sha256"):final(to_hash))
end

function calculate_certificate_fingerprint(cert)
    -- Calculate the sha
    local fgpt = cert:digest("sha1"):upper()
    -- Add the ":"
    for i = 1, #fgpt / 2 - 1 do
        fgpt = fgpt:sub(1, i * 3 - 1) .. ":" .. fgpt:sub(i * 3)
    end
    return fgpt
end

function create_instance_principal_session(debug)
    -- curl https://auth.us-phoenix-1.oraclecloud.com/
    local region = get_instance_principal_region(debug)
    if debug then
        print_debug("Using region:", region)
    end

    local openssl_pkey = require("openssl.pkey")
    local openssl_x509 = require("openssl.x509")

    -- key.pem, intermediate.pem, cert.pem
    local cert_string = send_instance_principal_metadata_request("/identity/cert.pem", {}, debug)
    local cert = openssl_x509.new(cert_string)
    local tenant_id
    for i, values in pairs(cert:getSubject():all()) do
        for k, v in pairs(values) do
            if v:match("opc%-tenant:(.+)") then
                tenant_id = v:match("opc%-tenant:(.+)")
            end
        end
    end
    if not tenant_id then
        error("Could not extract tenant id from certificate")
    end
    -- openssl x509 -in %s -noout -text
    if debug then
        print_debug("Got tenant id from certificate: '" .. tenant_id .. "'")
    end

    local fingerprint = calculate_certificate_fingerprint(cert)
    -- openssl x509 -in cert.pem -noout -fingerprint -sha1"
    if debug then
        print_debug("Created certificate fingerprint: '" .. fingerprint .. "'")
    end
    local cert_string_short = cert_string:gsub("%-%-%-%-%-[%a ]+%-%-%-%-%-", ""):gsub("\n", "")

    local intermediate_string = send_instance_principal_metadata_request("/identity/intermediate.pem", {}, debug)
    local intermediate_string_short = intermediate_string:gsub("%-%-%-%-%-[%a ]+%-%-%-%-%-", ""):gsub("\n", "")

    -- signer: https://github.com/oracle/oci-python-sdk/blob/dbee482abc73e76c65b1ba482b94e62b749d0df0/src/oci/auth/federation_client.py#L212
    local key_id = string.format("%s/fed-x509/%s", tenant_id, fingerprint)
    local federation_endpoint = string.format("https://auth.%s.oraclecloud.com/v1/x509", region)
    if debug then
        print_debug("Using key id: '" .. key_id .. "' and endpoint '" .. federation_endpoint .. "'")
    end

    local key_string = send_instance_principal_metadata_request("/identity/key.pem", {}, debug)
    local key = openssl_pkey.new()
    key:setPrivateKey(key_string)

    local session_key = openssl_pkey.new({ type = "RSA", bits = 2048 })
    local public_key_string = session_key:toPEM("public")
    if debug then
        print_debug("Created session key with public key: ", public_key_string)
    end
    public_key_string = public_key_string:gsub("%-%-%-%-%-[%a ]+%-%-%-%-%-", ""):gsub("\n", "")

    -- request: https://github.com/oracle/oci-python-sdk/blob/dbee482abc73e76c65b1ba482b94e62b749d0df0/src/oci/auth/federation_client.py#L153
    local request = {
        url = federation_endpoint,
        method = "POST",
        body = string.format(
                '{"certificate":"%s","publicKey":"%s","intermediateCertificates":["%s"]}',
                cert_string_short, public_key_string, intermediate_string_short
        )
    }
    sign_request_with_key_id(request, key_id, key, debug, true)
    local response = send_request(request, debug)
    if debug then
        print_debug("Got session response: '" .. response .. "'")
    end

    -- Parse the response
    local token = response:match('"token"%s*:%s*"(%S+)"')
    if not token then
        error("Got invalid session authorization response. Could not retrieve token")
    end
    if debug then
        print_debug("Retrieved token: '" .. token .. "'")
    end

    return {
        token = token,
        private_key = session_key
    }
end

function get_instance_principal_region(debug)
    -- TODO support different realms. The realm is based on retrieved region
    -- curl http://169.254.169.254/opc/v2/instance/region -H'Authorization: Bearer Oracle' -H'Accept: text/plain'
    local region_code = send_instance_principal_metadata_request("/instance/region", {}, debug)
    local REGIONS_SHORT_NAMES = require('regions')
    local region = REGIONS_SHORT_NAMES[region_code]
    if not region then
        error("Could not find a region for code ".. region_code)
    end
    return region
end

function send_instance_principal_metadata_request(path, headers, debug)
    -- TODO support /v1 URL. Need to check if either is available and send request there
    local metadata_url = "http://169.254.169.254/opc/v2" .. path
    local request = require("http.request").new_from_uri(metadata_url)
    request.headers:append("Authorization", "Bearer Oracle")
    request.headers:append("Accept", "text/plain")
    if headers then
        for k, v in pairs(headers) do
            request.headers:append(k, v)
        end
    end

    if debug then
        print_debug("Sending request to '" .. metadata_url .. "'")
    end

    local headers, stream = assert(request:go())
    local status, body = headers:get(":status"), stream:get_body_as_string()
    if debug then
        print_debug("Got response status: '" .. status .. "'")
        print_debug("Got response body: '" .. body .. "'")
    end
    if status ~= "200" then
        error("Could not get " .. path .. " from metadata endpoint")
    end
    return body
end

function sign_request(request, oci, debug)
    if oci.auth_mode == 'api_key' then
        local profile_config = get_oci_profile(oci.config_file, oci.profile)
        local key_id = string.format("%s/%s/%s", profile_config.tenancy,
                profile_config.user, profile_config.fingerprint)
        local private_key = read_key_from_file(profile_config.key_file)
        sign_request_with_key_id(request, key_id, private_key, debug)
    elseif oci.auth_mode == "instance_principal" then
        local session = create_instance_principal_session(debug)
        -- https://github.com/oracle/oci-python-sdk/blob/master/src/oci/auth/signers/security_token_signer.py#L12
        local key_id = string.format("ST$%s", session.token)
        sign_request_with_key_id(request, key_id, session.private_key, debug)
    else
        error("Only api_key and instance_principal auth modes are supported")
    end
end

function sign_request_with_key_id(request, key_id, private_key, debug, exclude_host)
    -- See https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm
    if not request.headers then
        request.headers = {}
    end
    if request.body then
        if not request.headers["content-length"] then
            request.headers["content-length"] = #request.body
        end
        if not request.headers["content-type"] then
            request.headers["content-type"] = "application/json"
        end
    end

    local date = os.date("!%a, %d %h %Y %H:%M:%S GMT")
    request.headers["date"] = date

    -- path includes query parameters
    local host, path = request.url:match("https://([^/]+)(/.+)")
    local request_target = string.format("%s %s", request.method:lower(), path)

    local required_headers = "(request-target) date"
    local to_sign = string.format("(request-target): %s\ndate: %s", request_target, date)
    if not exclude_host then
        required_headers = required_headers .. " host"
        to_sign = to_sign .. string.format("\nhost: %s", host)
    end
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
    local signature = create_signature(to_sign, private_key)
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
        local curl_request = "curl -X" .. request_data.method
        for k,v in pairs(request_data.headers) do
            curl_request = curl_request .. string.format(" -H'%s: %s'", k, v)
        end
        if (request_data.body) then
            curl_request = curl_request .. " -d'" .. request_data.body .. "'"
        end
        curl_request = curl_request .. " " .. request_data.url
        print(curl_request)
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
