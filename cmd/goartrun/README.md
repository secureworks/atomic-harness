# goartrun

## Summary

This is a script runner exclusively used by the atomic-harness.

- Dropping of Elevated Privileges - While harness should be run as root, tests can be run as regular users.
- Handles the platform specific script types (sh,bash,powershell,cmd)
- Timeout - will kill a script command if taking too long

## Input Schema

[runspec.go](../../pkg/types/runspec.go) contains the definitions for the input config object `RunSpec` .  The harness will provide the `RunSpec` in JSON format `--config` argument as a path or `-` for stdin.

```go
type RunSpec struct {
    ID              string          // e.g. T1059.002 #7 67e5d354
    Label           string          // e.g. AppleScript NSAppleScript execution

    TempDir    string
    ResultsDir string
    Username   string               // if not root, value of SUDO_USER

    EnvOverrides map[string]string
    Script       *AtomicExecutor    // test script

    DependencyExecutorName string   // e.g. sh, bash, powershell, cmd
    Dependencies []Dependency       // optional dependency checks

    Stage   string
    Timeout int64
}
```

## Output Results Schema

```go
type ScriptResults struct {
        Spec RunSpec

        Status      int
        IsCleanedUp bool
        StartTime   int64
        EndTime     int64
}
```