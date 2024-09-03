# OCI curl

A simple lua script that allows sending curl-like requests to OCI. Currently only API key and instance principal authentication is supported.

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
| `-a [auth_mode]` | Authentication mode. One of `api_key` and `instance_principal` | `api_key` |
| `-v` | Run in verbose mode | Not set |

### Examples

* List namespace
  ```shell
  lua oci_curl.lua https://objectstorage.us-phoenix-1.oraclecloud.com/n/
  ```
* List namespace with instance principal
  ```shell
  lua oci_curl.lua https://objectstorage.us-phoenix-1.oraclecloud.com/n/ -a instance_principal
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

### Installation

You need to install Lua and http to run the script.

#### On MacOS

```shell
brew install lua luarocks
luarocks install http
luarocks install base64
```

I also got this error for some reason: 
```shell
Failed to locate 'm4'
```
Solved it with: 
```
sudo ln -s /Library/Developer/CommandLineTools/usr/bin/gm4 /Library/Developer/CommandLineTools/usr/bin/m4
```

#### On Oracle Linux 8

Install Lua and luarocks:
```shell
sudo dnf install readline-devel

wget http://www.lua.org/ftp/lua-5.3.5.tar.gz
tar -zxf lua-5.3.5.tar.gz
cd lua-5.3.5
make linux
sudo make install
cd ..

wget https://luarocks.org/releases/luarocks-3.11.1.tar.gz
tar zxpf luarocks-3.11.1.tar.gz
cd luarocks-3.11.1
./configure && make && sudo make install
```

Install a newer version of OpenSSL (if needed).
```shell
sudo dnf install perl-IPC-Cmd perl-Pod-Html
wget https://github.com/openssl/openssl/releases/download/openssl-3.3.1/openssl-3.3.1.tar.gz
tar xzf openssl-3.3.1.tar.gz
cd openssl-3.3.1/
sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
sudo make
sudo make install
sudo ldconfig /usr/local/ssl/lib64/
/usr/local/ssl/bin/openssl version -a
```

Install the dependencies, linking them with the newer OpenSSL version:
```shell
sudo /usr/local/bin/luarocks install luaossl CFLAGS="-O2 -fPIC -DHAVE_EVP_KDF_CTX=1" CRYPTO_INCDIR=/usr/local/ssl/include OPENSSL_INCDIR=/usr/local/ssl/include CRYPTO_DIR=/usr/local/ssl/ OPENSSL_DIR=/usr/local/ssl/ 
sudo /usr/local/bin/luarocks inastall cqueues CFLAGS="-O2 -fPIC -DHAVE_EVP_KDF_CTX=1" CRYPTO_INCDIR=/usr/local/ssl/include OPENSSL_INCDIR=/usr/local/ssl/include CRYPTO_DIR=/usr/local/ssl/ OPENSSL_DIR=/usr/local/ssl/ 
sudo /usr/local/bin/luarocks install http 
sudo /usr/local/bin/luarocks install base64
```

Update the certificates used by OpenSSL:
```shell
sudo ln -s /etc/pki/tls/cert.pem /usr/local/ssl/cert.pem
```

### Test

On local machine run:
```shell
lua test.lua <compartment-id>
```

On an OCI instance
* Create a policy to allow the instance to create logging groups:
  ```shell
  allow any-user to manage log-groups in compartment id <compartment-id> where ALL { request.principal.type='instance', request.principal.compartment.id='<compartment-id>' }
  ```
* Run:
  ```shell
  lua test.lua <compartment-id> -a instance_principal
  ```