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

func TestCommitDate(t *testing.T) {
	// this can be changed to your criteria path
	criteriaPath := "../../atomic-validation-criteria"

	//criteria does not exist for this test
	assert.Equal(t, "", FindCriteriaCommitDates(criteriaPath)["T1204.003"])

	//make sure date is parsed correctly
	assert.Equal(t, "2023-05-21 11:44:44 -0700", FindCriteriaCommitDates(criteriaPath)["T1048.002"])

	//make sure it will fail (I hope so...)
	assert.NotEqual(t, "2023-05-21 11:44:44 -0700", FindCriteriaCommitDates(criteriaPath)["T1003.001"])

}

func TestTranslateDates(t *testing.T) {

	assert.Equal(t, "Sun May 21 11:44:44 2023 -0700", translateDate("2023-05-21 11:44:44 -0700"))

	assert.Equal(t, "Mon May 22 11:44:44 2023 -0700", translateDate("2023-05-22 11:44:44 -0700"))

	assert.Equal(t, "Tue Jun 20 01:02:44 2023 -0700", translateDate("2023-06-20 1:02:44 -0700"))
}
