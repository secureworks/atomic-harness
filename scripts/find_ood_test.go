package main

/*
 * CSV data format and type definitions
 */

/* Find_OutOfDate.Go:
Creates a text file that delineates every criteria which may be out of date based on the commit times to https://github.com/redcanaryco/atomic-red-team/tree/master/atomics
and https://github.com/secureworks/atomic-validation-criteria/tree/master.

Because we cannot assume that there will be the same number of tests as new tests are added, we will need to mark
'not found' tests and either prompt the user to generate the test or do it automatically.

In addition, as an unfortunate consequence of how files are stored in the criteria repo https://github.com/secureworks/atomic-validation-criteria,
we will need to map each test to the file it originated from, since the tests are sometimes stored together (ex. windows/T1027-T1047.csv), and sometimes stored alone (Ex: macos/T1000_macos.csv)
*/

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// with the default timeout settings, this test is unable to run to completion. If you would like to test it, either change the default timeout to about 3 minutes,
// or change the git log command to be since an earlier date
func TestFindOutOfDate(t *testing.T) {
	// this can be changed to your atomics path
	atomicsPath := "../../atomic-red-team/atomics"

	assert.Equal(t, "Thu Apr 27 14:23:24 2023 +0000", FindTestCommitDates(atomicsPath)["T1204.003"])

	assert.Equal(t, "Thu Apr 27 18:09:51 2023 +0200", FindTestCommitDates(atomicsPath)["T1112"])

	assert.Equal(t, "Fri May 19 17:06:33 2023 +0000", FindTestCommitDates(atomicsPath)["T1003.001"])

	assert.Equal(t, "Thu Apr 27 18:09:51 2023 +0200", FindTestCommitDates(atomicsPath)["T1070.008"])

	//try a very old commit and see if the log goes back far enough
	assert.Equal(t, "Thu Apr 27 14:23:24 2022 +0000", FindTestCommitDates(atomicsPath)["T1547.003"])
}

func TestCompareDates(t *testing.T) {
	outofDate, _ := compareDates("Thu Apr 27 18:09:51 2023 +0200", "Fri May 19 17:06:33 2023 +0000")
	assert.Equal(t, true, outofDate)

	outofDate, _ = compareDates("Thu Apr 27 18:09:51 2023 +0200", "Thu Apr 27 14:23:24 2022 +0000")
	assert.Equal(t, false, outofDate)

	outofDate, _ = compareDates("Fri May 19 17:06:33 2023 +0000", "")
	assert.Equal(t, false, outofDate)

	outofDate, _ = compareDates("Thu Apr 27 18:09:51 2023 +0200", "")
	assert.Equal(t, false, outofDate)

	outofDate, _ = compareDates("", "")
	assert.Equal(t, false, outofDate)
}
