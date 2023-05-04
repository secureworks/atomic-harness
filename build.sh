#!/bin/sh

MAKE=`which make`
if [ -z "${MAKE}" ] ; then
	go build -o atomic-harness *.go
else
	make
fi