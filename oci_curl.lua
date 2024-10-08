require("oci_curl_common")

function parse_arguments(args)
    local request = {method = "GET", url = nil, body = nil, headers = {}}
    local oci = { profile = "DEFAULT", config_file = "~/.oci/config", auth_mode = "api_key" }
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
        elseif key == 'a' then
            if value ~= "api_key" and value ~= "instance_principal" then
                error("-a flag must be one of api_key and instance_principal")
            end
            oci.auth_mode = value
        elseif key == 'v' then
            debug = true
        else
            request.url = value
        end
        i = i + 1
    end

    return request, oci, debug
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
    if debug then
        print_debug("Starting in debug mode")
    end

    -- TODO support changing region based on the one configured by auth
    sign_request(request, oci, debug)
    local response_body = send_request(request, debug)
    print(response_body)
end

main({...})
