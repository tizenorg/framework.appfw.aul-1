#!/bin/sh

AMD_DUMP=$1/amd

mkdir -p $AMD_DUMP

mv -f /var/log/amd.log $AMD_DUMP
