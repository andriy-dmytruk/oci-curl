require("oci_curl_common")

function main(args)
    if #args == 1 and arg[1] == "-h" then
        print("oci_curl_init_session.lua")
        print("Usage:")
        print("    lua oci_curl_init_session.lua [optional arguments]")
        print("Arguments:")
        print("    -v                 Run in verbose mode")
        return
    end

    local debug = false
    if arg[1] == "-v" then
        debug = true
    end
    local session = create_instance_principal_session(debug)
    print(string.format('{"token":"%s","private_key":"%s"}',
            session.token, session.private_key:toPEM("private")))
end

main({ ... })