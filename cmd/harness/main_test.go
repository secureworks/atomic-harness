package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTelemTools(t *testing.T) {
	tools := []*TelemTool{}

	tools = PrepTelemTools("telemtool,telemtool_e2e.exe")
	assert.Equal(t, 2, len(tools))
	assert.Equal(t, "telemtool", tools[0].Name)
	assert.Equal(t, "", tools[0].Suffix)
	assert.Equal(t, "telemtool_e2e.exe", tools[1].Name)
	assert.Equal(t, "_e2e", tools[1].Suffix)
}
