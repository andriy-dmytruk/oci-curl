# OCI curl

A simple lua script that allows sending curl-like requests to OCI. Currently only API key authentication is supported.

### Usage

```shell
lua oci_curl.lua [url] [optional arguments]
```

| Argument           | Explanation | Default |
|--------------------| --- | -- |
| `[url]`            | The request URL | |
| `-H '[header]: [value]'` | A request header | |
| `-X [method]` | The request method | `GET` |
| `-d [body]` | The request body | |
| `-c [config path]` | The OCI config path | `~/.oci/config` |
| `-p [profile]` | The OCI profile name | `DEFAULT` |
| `-v` | Run in verbose mode | Not set |

### Examples

* List namespace
  ```shell
  lua oci_curl.lua https://objectstorage.us-phoenix-1.oraclecloud.com/n/
  ```
* Create log group
  ```shell
  lua oci_curl.lua -X POST https://logging.us-phoenix-1.oci.oraclecloud.com/20200531/logGroups/ -d '{"compartmentId":"<id>","displayName":"test-log-group"}' -H 'Accept: application/json'
  ```
* List log groups
  ```shell
  lua oci_curl.lua 'https://logging.us-phoenix-1.oci.oraclecloud.com/20200531/logGroups?compartmentId=<id>&displayName=test-log-group'
  ```
* Delete log group verbosely
  ```shell
  lua oci_curl.lua -X DELETE 'https://logging.us-phoenix-1.oci.oraclecloud.com/20200531/logGroups/<id>' -v
  ```
