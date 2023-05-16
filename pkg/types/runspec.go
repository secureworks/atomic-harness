package types

// RunSpec - schema for goartrun job
type RunSpec struct {
   Technique  string
   TestName   string
   TestIndex  int

   AtomicsDir string
   TempDir    string
   ResultsDir string
   Username   string

   Inputs     map[string]string
   //Envs       []string

   Stage      string
}


type TestState int

const (
    StatePending TestState = iota
    StateCriteriaLoaded
    StateRunnerLaunched
    StateRunnerFinished
    StateWaitForTelemetry
    StateDone
    StateSkip
)

type TestStatus int

const (
    StatusUnknown TestStatus = iota
    StatusMiscError             // 1
    StatusAtomicNotFound        // 2
    StatusCriteriaNotFound      // 3
    StatusSkipped               // 4
    StatusInvalidArguments      // 5
    StatusRunnerFailure         // 6
    StatusPreReqFail            // 7
    StatusTestFail              // 8
    StatusTestSuccess           // 9
    StatusTelemetryToolFailure  // 10
    StatusValidateFail          // 11
    StatusValidatePartial       // 12
    StatusValidateSuccess       // 13
    StatusDelegateValidation    // 14
)

// keeping these names at 4-character for status text align
func (s TestState) String() string {
    strings := [...]string{"Pend", "Load", "Rung", "Exit","WaiT","Done","Skip"}

    if s < StatePending || s > StateDone {
        return "Unkn"
    }
    return strings[s]
}

// keeping these at a max of 11-chars
func (s TestStatus) String() string {
    strings := [...]string{"Unknown", "MiscError", "NoAtomic","NoCriteria",
    "Skipped","InvalidArgs","RunnerFail","PreReqFail",
	"TestFail","TestRan","ToolFail","NoTelemetry","Partial","Validated", "Ready2Eval"}

    if s < StatusUnknown || s > StatusDelegateValidation {
        return "Unknown"
    }

    return strings[s]
}

// TestSpec - schema summarizing atomic-validation-criteria for test(s)
// for example, it could be all tests for "T1027"
type TestSpec struct {
    Technique        string
    TestIndex        string  // optional?
    TestName         string  // optional?

    Criteria         []*AtomicTestCriteria
}

type TestProgress struct {
    Technique        string
    TestIndex        string  // optional?
    TestName         string  // optional?

    State      TestState
    ExitCode   int
    Status     TestStatus
}