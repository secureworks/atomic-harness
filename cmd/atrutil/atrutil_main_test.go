package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripComment(t *testing.T) {
	s1 := "sudo rm #{journal_folder}/* #physically deletes the journal files, and not just their content"
	cmd,comment := stripCommandComment(s1, "bash")
	assert.Equal(t, "sudo rm #{journal_folder}/* ",cmd)
	assert.Equal(t, "physically deletes the journal files, and not just their content", comment)

	s2 := "sudo rm #{journal_folder}/*"
	cmd,comment = stripCommandComment(s2, "bash")
	assert.Equal(t, "sudo rm #{journal_folder}/*", cmd)
	assert.Equal(t, "", comment)

	s3 := "# some comment here"
	cmd,comment = stripCommandComment(s3, "sh")
	assert.Equal(t, "", cmd)
	assert.Equal(t, " some comment here", comment)
}