The files in this directory are examples that can be used
to implement system info gathering on `linux`.
The harness can use the data to provide atomic test variable argument values for:

- **ipaddr**  (e.g. `10.0.0.21`)
- **ipaddr6**  (e.g. `fe80::2705:2628:3cd2:1124`)
- **subnet**   (e.g. `10.0.0`  for T1018#7)
- **gateway**  (e.g. `10.0.0.1`)
- **hostname**

## Usage in criteria
The following is an example where, using the wrong subnet or unreachable address can really slow down the test, and not provide the netflow necessary.
```csv
T1018,linux,7,Remote System Discovery - sweep
ARG,start_host,1
ARG,stop_host,3
ARG,subnet,$subnet
_E_,Process,cmdline~=ping -c 1
```

## Notes

### Default interface
Based on number of packets
```sh
cat /proc/net/dev | grep ':' | grep -v '^[ \t]*lo:' | sed 's/[ \t]0[ \t].*//g' | sed 's/\(^.*\): \(.*\)/\2 \1/g' | sort -n -r | head -1 | sed 's/.*[ \t]//'
```
