local args = { ... }
local COMPARTMENT_ID = args[1]
extra_params = table.concat({ table.unpack(args, 2) }, " ")

function execute_command(cmd, verify, getter)
    cmd = cmd .. " " .. extra_params
    local pipe = io.popen(cmd, 'r')
    local output = pipe:read('*a')
    if output:sub(#output, #output) == '\n' then
        output = output:sub(1, #output - 1)
    end
    pipe:close()

    print("Executed command '" .. cmd .. "'.")
    print("Got output: '" .. output .. "'.")
    if not verify(output) then
        error("Command failed")
    end
    if getter then
        return getter(output)
    end
end

execute_command(
        "lua oci_curl.lua https://objectstorage.us-phoenix-1.oraclecloud.com/n/",
        function(v) return v == '"oraclelabs"' end
)

execute_command(
        'lua oci_curl.lua -X POST https://logging.us-phoenix-1.oci.oraclecloud.com/20200531/logGroups/ -d \'{"compartmentId":"'
                .. COMPARTMENT_ID .. '","displayName":"test-log-group"}\' -H \'Accept: application/json\'',
        function(v) return v == '{}' end
)

local group_id = execute_command(
        'lua oci_curl.lua \'https://logging.us-phoenix-1.oci.oraclecloud.com/20200531/logGroups?compartmentId='
                .. COMPARTMENT_ID .. '&displayName=test-log-group\'',
        function(v) return v:find('[{"id":"ocid1', 1, true) end,
        function(v) return v:match("ocid1.loggroup[^\"]+") end
)

execute_command(
        'lua oci_curl.lua -X DELETE "https://logging.us-phoenix-1.oci.oraclecloud.com/20200531/logGroups/' .. group_id .. '"',
        function(v) return v == '{}' end
)

print("All tests succeeded!")

