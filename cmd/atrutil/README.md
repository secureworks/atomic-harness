## ATR util

`atrutil` is intended to be a swiss-army knife command-line utility to search or manipulate Atomic Red Team files, Criteria files, etc.


## Search

The `--findtests` will do a case-insensitive "contains" search for each Atomic Red Team `TestNum` and `TestName` in the `Index-CSV` file for the current platform.

```
$ ./bin/atrutil --findtests shadow
T1003.008 1 3723ab77-c546-403c-8fb4-bb577033b235 Access /etc/shadow (Local)
T1003.008 3 df1a55ae-019d-4120-bc35-94f4bc5c4b0a Access /etc/{shadow,passwd} with a standard bin that's not cat
T1003.008 4 f5aa6543-6cb2-4fae-b9c2-b96e14721713 Access /etc/{shadow,passwd} with shell builtins
Found 3 in 322 tests for platform linux
```

## Patch criteria GUIDs

Originally, the criteria files only had TestNumber and TestName for each test.  However, since the ATR repo is allowing tests to be added anywhere in the YAML files, we need to use GUIDs instead.  The criteria files have already been patched, so we shouldn't need this functionality, but I left the code in case it is useful for another utility method.

```
./bin/atrutil --patch_criteria_refs
```