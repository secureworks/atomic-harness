# goartrun

## Goals

This is now exclusively for use by the atomic-harness.  However, it is still possible to use run this directly to debug the `prereq,checkreq,test,cleanup` stages of an atomic red team test directly.

## Beginnings

This began as a hard fork of MIT-licensed https://github.com/activeshadow/go-atomicredteam .
My goals are automation and security.  I stripped away all non essential packages and non-github imports like `"actshad.dev/go-atomicredteam"`

## Initial Run Design
The goal is to make this runner pull config from input file or stdin JSON rather than commandline arguments.
```sh
bin/goart --atomicsdir $HOME/atomic-red-team/atomics \
          --tempdir /tmp/goart-xyz333 \
          -t T1571 -i 1 \          # Invoke-Atomic uses 1-based, this uses 0-based indexes
          domain=172.20.10.15      # test arguments
```
