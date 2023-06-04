package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripComment(t *testing.T) {
	s1 := "sudo rm #{journal_folder}/* #physically deletes the journal files, and not just their content"
	cmd, comment := stripCommandComment(s1, "bash")
	assert.Equal(t, "sudo rm #{journal_folder}/* ", cmd)
	assert.Equal(t, "physically deletes the journal files, and not just their content", comment)

	s2 := "sudo rm #{journal_folder}/*"
	cmd, comment = stripCommandComment(s2, "bash")
	assert.Equal(t, "sudo rm #{journal_folder}/*", cmd)
	assert.Equal(t, "", comment)

	s3 := "# some comment here"
	cmd, comment = stripCommandComment(s3, "sh")
	assert.Equal(t, "", cmd)
	assert.Equal(t, " some comment here", comment)
}

func TestExtractRedirects(t *testing.T) {
	s1 := "ifconfig 2>/dev/null >> #{some_target}"
	cmd, filepaths := extractFileRedirects(s1, "sh")
	assert.Equal(t, 2, len(filepaths))
	assert.Equal(t, "ifconfig ", cmd)
	assert.Equal(t, "/dev/null", filepaths[0])
	assert.Equal(t, "#{some_target}", filepaths[1])

	s2 := "ifconfig"
	cmd, filepaths = extractFileRedirects(s2, "sh")
	assert.Equal(t, "ifconfig", cmd)
	assert.Equal(t, 0, len(filepaths))

	s3 := "ifconfig > /some/file"
	cmd, filepaths = extractFileRedirects(s3, "sh")
	assert.Equal(t, "ifconfig ", cmd)
	assert.Equal(t, 1, len(filepaths))
	assert.Equal(t, "/some/file", filepaths[0])
}

func TestSplitPipedCmds(t *testing.T) {
	s1 := "/bin/ls /tmp/"
	a := SplitPipedCommands(s1, "sh")
	assert.Equal(t, 1, len(a))
	assert.Equal(t, s1, a[0])

	s2 := "ls /etc | grep pa | sort"
	a = SplitPipedCommands(s2, "sh")
	assert.Equal(t, 3, len(a))
	assert.Equal(t, "ls /etc ", a[0])
	assert.Equal(t, " grep pa ", a[1])
	assert.Equal(t, " sort", a[2])
}
