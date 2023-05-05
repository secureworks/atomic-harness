# Atomic Harness

- NOTE: this is for linux and macos only at the moment.

## Overview

The automation of atomic test validation requires the following components.  You can run [scripts/fetch_deps.sh](./scripts/fetch_deps.sh) to make the local clones.
 - Harness : this repo
 - Tests : [atomics](https://github.com/redcanaryco/atomic-red-team)
 - Criteria : [atomic-validation-criteria](https://github.com/secureworks/atomic-validation-criteria)
 - Runner : [goartrun](https://github.com/secureworks/goartrun)
 - Telemetry Tool : [example](https://github.com/secureworks/telemetry-tool-example)

We specify a set of tests to run (by technique IDs, test-indices or test names, or tactics), then the harness will find the matching validation criteria (if present) for each technique.  For each test (e.g. `T1027.001#1`) the harness will launch the runner and wait some seconds to give the agent time to send telemetry.  The harness will then use the telemetry tool to find events for the runner shell process, all the events for the duration of the test, and look for events that match the validation criteria in the data.  For each test, there will be the following files:
 - telemetry json
 - validation summary with matching events, time window, etc.
 - runner summary with stderr, stdout of commands and exit codes

## Setup and Build

```sh
# clone other repos and build goartrun
./scripts/fetch_deps.sh
make
```

## Run one or more specific tests

```sh
$ sudo ./atomic-harness --serverscsv ./doc/example_servers_config.csv T1562.004#7 T1562.004#9 T1562.004#10

```

## Run All Linux Technique Tests

The linux_techniques.csv was generated from https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v12.1/enterprise-attack/enterprise-attack.json .
In this example, I have a config file containing ip-addresses and ports of a couple of ssh and rsync test servers.
Note, there are plenty of atomic tests missing, so you will see those get skipped.  
Specifying a `--username` will run non-elevated-privilege tests as that user.
```sh
$ sudo ./atomic-harness --serverscsv ./doc/example_servers_config.csv --runlist ./data/linux_techniques.csv --username bob
```

## Re-Run All Failing Tests From Previous
If you specify `--retryfailed <path to results dir>`, the harness will re-run all tests that were not `Validated` or `Skipped`.
```sh
sudo ./atomic-harness --telemetryclear --serverscsv ./doc/example_servers_config.csv --username bob --retryfailed ./testruns/harness-results-456317467
```

## Results Summary

After the tests are finished and the telemetry fetched, the harness will exit after dumping a summary like the following.
The fifth column contains a summary of the expected event types, and the ones that are missing are wrapped in angle brackets like `<F>`.
```
Done. Output in ./testruns/harness-results-2773792211
-T1564.001  1 Done Validated    PFF        "Create a hidden file in a hidden directory"
-    T1571  2 Done Validated    PN         "Testing usage of uncommonly used port"
-T1574.006  1 Done Validated    PF         "Shared Library Injection via /etc/ld.so.preload"
-T1003.007  3 Done Skipped                 "Capture Passwords with MimiPenguin"
-T1552.004  5 Done NoTelemetry  <P><f><F>  "Copy the users GnuPG directory with rsync"
-T1548.001  5 Done Partial      PF<F>      "Make and modify capabilities of a binary"
-T1562.003  1 Done Partial      <P>P       "Disable history collection"
-T1562.006  1 Done Partial      PPP<F><F><F> "Auditing Configuration Changes on Linux Host"
```

## Results Summary Event Types

- `A` : Auth Event
- `C` : Correlation (e.g. processes piped together)
- `f` : File Read Event
- `F` : FileMod Event
- `M` : Module Load/Unload
- `N` : Netflow
- `P` : Process Event
- `S` : NetSniff Event
- `T` : PTrace Event
- `V` : Volume Activity Event
- `W` : Detection / Warning (e.g. process using high cpu)

## Results Directory

Inside the `harness-results-xx` directory, you will see subdirectory for each test for each technique, as well as `status.txt` and `status.json` files.

For successful test runs, the subdirectories will contain something like
```sh
-rw-r--r--   1 develop develop     96 Jan  5 12:35 match_string.txt
-rw-r--r--   1 develop develop   2026 Jan  5 12:35 runner-stdout.txt
-rw-r--r--   1 develop develop    465 Jan  5 12:35 runspec.json
-rw-r--r--   1 develop develop   1898 Jan  5 12:35 run_summary.json
-rw-r--r--   1 root    root        12 Jan  5 12:42 status.txt
-rw-r--r--   1 root    root      5492 Jan  5 12:42 telemetry_tool_output.txt
-rw-r--r--   1 root    root    145817 Jan  5 12:42 telemetry.json
-rw-r--r--   1 root    root       655 Jan  5 12:42 validate_spec.json
-rw-r--r--   1 root    root      4384 Jan  5 12:42 validate_summary.json
```

## Troubleshooting a partial or missing telemetry test
I will usually start with the `validate_summary.json` file.  I will the file in my editor (Sublime), which allows me to select nodes in the JSON to collapse.  I will collapse the matches for all tests to find the expected events that are missing. (TODO: automate this and provide another file).  Then I will look in the `telemetry.json` which contains all events in the timeframe, to see if the event was present, but the matching didn't find it.


