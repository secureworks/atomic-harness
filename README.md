# Atomic Harness

- **Good News**: The harness and runner now supports Windows and MacOS in addition to Linux!
- **However**... to make good use of this tool, we need good criteria defined for Windows and MacOS atomic tests.  Help out here: [atomic-validation-criteria](https://github.com/secureworks/atomic-validation-criteria)

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

## Telemetry and Matching

Since every endpoint has it's own telemetry format and schema, you need to provide a telemetry tool to fetch telemetry and convert to the simple schema used by the atomic-harness.  See the `telemetry-tool-example` to see how it is done for local osquery json results.  The harness now takes care of identifying the telemetry for each individual test and validating it against the criteria.

- atomic-harness --runlist list_of_20_techniques.csv
- harness runs `goartrun` for each atomic test found for specified techniques
- harness calls `telemtool --fetch --resultsDir /tmp/somedir --ts tstart,tend`
- harness looks in resultsDir/simple_telemetry.json provided by telemetry tool and finds events for each test, evaluates matching criteria

## Setup and Build

```sh
# clone other repos and build goartrun
./scripts/fetch_deps.sh
make
```

## Run one or more specific tests
You can specify by TestNum (1-based) or Using the first part of the TestGuid
```sh
$ sudo ./bin/atomic-harness T1562.004#7 T1562.004#9 T1562.004#b2563a4e

```

## Search for Atomics
The `atrutil` tool can help search tests
```
$ ./bin/atrutil --findtests cron
T1053.003 1 435057fb-74b1-410e-9403-d81baf194f75 Cron - Replace crontab with referenced file
T1053.003 2 b7d42afa-9086-4c8a-b7b0-8ea3faa6ebb0 Cron - Add script to all cron subfolders
T1053.003 3 2d943c18-e74a-44bf-936f-25ade6cccab4 Cron - Add script to /var/spool/cron/crontabs/ folder
T1036.003 2 a315bfff-7a98-403b-b442-2ea1b255e556 Masquerading as Linux crond process.
Found 4 in 257 tests for platform linux

$ ./bin/atrutil --findtests T1053
T1053.002 2 7266d898-ac82-4ec0-97c7-436075d0d08e At - Schedule a job
T1053.003 1 435057fb-74b1-410e-9403-d81baf194f75 Cron - Replace crontab with referenced file
T1053.003 2 b7d42afa-9086-4c8a-b7b0-8ea3faa6ebb0 Cron - Add script to all cron subfolders
T1053.003 3 2d943c18-e74a-44bf-936f-25ade6cccab4 Cron - Add script to /var/spool/cron/crontabs/ folder
T1053.006 1 f4983098-bb13-44fb-9b2c-46149961807b Create Systemd Service and Timer
T1053.006 2 3de33f5b-62e5-4e63-a2a0-6fd8808c80ec Create a user level transient systemd service and timer
T1053.006 3 d3eda496-1fc0-49e9-aff5-3bec5da9fa22 Create a system level transient systemd service and timer
```

## Run All Linux Technique Tests

The linux_techniques.csv was generated from https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v12.1/enterprise-attack/enterprise-attack.json .
In this example, I have a config file containing ip-addresses and ports of a couple of ssh and rsync test servers.
Note, there are plenty of atomic tests missing, so you will see those get skipped.  
Specifying a `--username` will run non-elevated-privilege tests as that user.
```sh
$ sudo ./bin/atomic-harness --serverscsv ./doc/example_servers_config.csv --runlist ./data/linux_techniques.csv --username bob
```

## Re-Run All Failing Tests From Previous
If you specify `--retryfailed <path to results dir>`, the harness will re-run all tests that were not `Validated` or `Skipped`.
```sh
sudo ./bin/atomic-harness --telemetryclear --serverscsv ./doc/example_servers_config.csv --username bob --retryfailed ./testruns/harness-results-456317467
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

Inside the `harness-results-xx` directory, you will see subdirectory for each test for each technique, as well as `status.txt` and `status.json` files.  Additionally, there will be `telemetry.json` and `simple_telemetry.json` files containing the raw telemetry and simplified telemetry provided by the telemetry tool.

For successful test runs, the Txxx subdirectories will contain something like
```sh
-rw-r--r--   1 develop develop     96 Jan  5 12:35 match_string.txt
-rw-r--r--   1 root    root       655 Jan  5 12:42 matches.json
-rw-r--r--   1 develop develop   2026 Jan  5 12:35 runner-stdout.txt
-rw-r--r--   1 develop develop    465 Jan  5 12:35 runspec.json
-rw-r--r--   1 develop develop   1898 Jan  5 12:35 run_summary.json
-rw-r--r--   1 root    root        12 Jan  5 12:42 status.txt
-rw-r--r--   1 root    root      5492 Jan  5 12:42 telemetry_tool_output.txt
-rw-r--r--   1 root    root      4384 Jan  5 12:42 validate_summary.json
```

## Troubleshooting a partial or missing telemetry test
I will usually start with the `validate_summary.json` file.  I will view the file in my editor (Sublime), which allows me to select nodes in the JSON to collapse.  Collapsing the matches for all tests to find the expected events that are missing. (TODO: automate this and provide another file).  Then I will look in the `telemetry.json` which contains all events in the timeframe, to see if the event was present, but the matching didn't find it.


