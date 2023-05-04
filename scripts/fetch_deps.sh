#!/bin/bash
SCRIPTSDIR=$(readlink -f $(dirname $0))

pushd "${SCRIPTSDIR}/../.."

# tools

if [ ! -d goartrun ] ; then
	git clone git@github.com:secureworks/goartrun \
	&& cd goartrun && make ; cd ..
fi

if [ ! -d telemetry-tool-example ] ; then
	git clone git@github.com:secureworks/telemetry-tool-example.git
fi

# tests

if [ ! -d atomic-red-team ] ; then
	git clone git@github.com:redcanaryco/atomic-red-team.git
fi

# validation criteria

if [ ! -d atomic-validation-criteria ] ; then
	git clone git@github.com:secureworks/atomic-validation-criteria.git
fi

