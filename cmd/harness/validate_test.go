package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindGoArtStageRegex(t *testing.T) {
	a := []string{}

	cmdline1 := "sh /tmp/artwork-T1560.002_3-458617291/goart-T1560.002-test.bash"
	a = gRxGoArtStage.FindStringSubmatch(cmdline1)
	assert.Equal(t,4,len(a))

	folder := a[1]
	technique := a[2]
	stageName := a[3]

	assert.Equal(t,"artwork-T1560.002_3-458617291", folder)
	assert.Equal(t,"T1560.002", technique)
	assert.Equal(t,"test", stageName)

	cmdlineBat1 := `CMD /c C:\Users\admin\AppData\Local\Temp\artwork-T1047_1-2854796409\goart-T1047-test.bat`

	a = gRxGoArtStageWin.FindStringSubmatch(cmdlineBat1)
	assert.Equal(t,5,len(a))

	folder = a[2]
	technique = a[3]
	stageName = a[4]

	assert.Equal(t,"artwork-T1047_1-2854796409", folder)
	assert.Equal(t,"T1047", technique)
	assert.Equal(t,"test", stageName)


	cmdlinePS1 := `POWERSHELL -NoProfile C:\Users\admin\AppData\Local\Temp\artwork-T1027.002_2-3400567469\goart-T1027.002-test.ps1`

	a = gRxGoArtStageWin.FindStringSubmatch(cmdlinePS1)
	assert.Equal(t,5,len(a))

	folder = a[2]
	technique = a[3]
	stageName = a[4]

	assert.Equal(t,"artwork-T1027.002_2-3400567469", folder)
	assert.Equal(t,"T1027.002", technique)
	assert.Equal(t,"test", stageName)
}
