package types

/**
 * Structs defining the simplified event schema that allows
 * atomic-harness to handle matching.
 * TODO: import from atomic-harness repo
 */

type SimpleSchemaChar string

const (
	SimpleSchemaUnknown     SimpleSchemaChar = "?"
	SimpleSchemaProcess     SimpleSchemaChar = "P"
	SimpleSchemaFilemod     SimpleSchemaChar = "F"
	SimpleSchemaFileRead    SimpleSchemaChar = "f"
	SimpleSchemaNetflow     SimpleSchemaChar = "N"
	SimpleSchemaCorrelation SimpleSchemaChar = "C" // process piped, parent/child
	SimpleSchemaVolume      SimpleSchemaChar = "V" // mount, unmount, remount
	SimpleSchemaAuth        SimpleSchemaChar = "A"
	SimpleSchemaModule      SimpleSchemaChar = "M"
	SimpleSchemaNetsniff    SimpleSchemaChar = "S"
	SimpleSchemaPTrace      SimpleSchemaChar = "T"
	SimpleSchemaDetection   SimpleSchemaChar = "W"
)

type SimpleProcessFields struct {
	Cmdline    string `json:"cmdline"` // required
	Pid        int64  `json:"pid"`     // required
	ParentPid  int64  `json:"parent_pid"`
	ExePath    string `json:"exe_path,omitempty"`
	Env        string `json:"env,omitempty"`
	IsElevated bool   `json:"is_elevated,omitempty"`

	UniquePid       string `json:"unique_pid",omitempty`
	ParentUniquePid string `json:"parent_unique_pid,omitempty"`
	ChainId         string `json:"chainid,omitempty"` // processes piped together have same chainid
}

type SimpleProcessExitFields struct {
	ExitCode int32 `json:"exit_code"`
	Pid      int64 `json:"pid"` // required
}

type SimpleFileAction string

const (
	SimpleFileActionUnknown   SimpleFileAction = "?"
	SimpleFileActionOpenRead  SimpleFileAction = "OPEN_READ"  // OPEN readonly or READ/ACCESS
	SimpleFileActionOpenWrite SimpleFileAction = "OPEN_WRITE" // OPEN to modify or WRITE/UPDATE
	SimpleFileActionChmod     SimpleFileAction = "CHMOD"
	SimpleFileActionChown     SimpleFileAction = "CHOWN"
	SimpleFileActionDelete    SimpleFileAction = "DELETE"
	SimpleFileActionTruncate  SimpleFileAction = "TRUNC"
	SimpleFileActionCreate    SimpleFileAction = "CREATE"
	SimpleFileActionRename    SimpleFileAction = "RENAME"
	SimpleFileActionChattr    SimpleFileAction = "CHATTR"
)

type SimpleFileFields struct {
	Action     SimpleFileAction `json:"action"` // required
	ExitCode   int32            `json:"exit_code"`
	TargetPath string           `json:"target_path"`          // required
	DestPath   string           `json:"dest_path,omitempty"`  // if present, for rename/mv
	PermFlags  string           `json:"perm_flags,omitempty"` // after call

	Pid       int64  `json:"pid,omitempty"`
	UniquePid string `json:"unique_pid,omitempty"`
	ExePath   string `json:"exe_path,omitempty"`
}

type SimpleNetflowFields struct {
	FlowStr    string `json:"flow_str,omitempty"` // proto:ip:port->ip:port
	FlowStrDns string `json:"flow_dns,omitempty"` // proto:ip:port->host:port
	Flags      string `json:"flags,omitempty"`    // "SE" - IsStart, IsEnd

	Pid       int64  `json:"pid,omitempty"`
	UniquePid string `json:"unique_pid,omitempty"`
	ExePath   string `json:"exe_path,omitempty"`
}

type SimpleEvent struct {
	EventType       SimpleSchemaChar `json:"evt_type"`
	Timestamp       int64            `json:"ts,omitempty"`
	TimeStr         string           `json:"ts_str,omitempty"` // only need ts or ts_str
	MitreTechniques []string         `json:"mitre_techniques,omitempty"`

	ProcessFields     *SimpleProcessFields     `json:"evt_process,omitempty"`
	ProcessExitFields *SimpleProcessExitFields `json:"evt_exit,omitempty"`
	FileFields        *SimpleFileFields        `json:"evt_file,omitempty"`
	NetflowFields     *SimpleNetflowFields     `json:"evt_netflow,omitempty"`
}
