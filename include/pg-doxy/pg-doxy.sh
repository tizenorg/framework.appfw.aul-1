#!/bin/bash

# Create doxygen from debian package server
# By Jungbae Lee (yi_jungbae@samsung.com)

cd `dirname $0`
CWD=`pwd`

# Use doxygen 1.7.0
export PATH=/usr/local/bin:${HOME}/mytools/bin:${PATH}
export LD_LIBRARY_PATH=${HOME}/mytools/lib:${LD_LIBRARY_PATH}


### Configuration
SBOX=/scratchbox/users/$USER/home/$USER
DOXYGEN_OUTPUT_DIR=$CWD/doxygen_output
DOXYGEN=./tool/bin/doxygen
DOXY_CONF=doxygen.conf
IMAGE_DIR=../../image #need to change
#IMAGE_DIR=[fill your image path]



####doxygen configuration :: output Directory
mkdir $DOXYGEN_OUTPUT_DIR

echo "Doxygen running..."
if [ ! -e $CWD/doxygen_output ]; then
	mkdir $CWD/doxygen_output
fi
# Run doxygen
$DOXYGEN $DOXY_CONF 2>&1

#image copy
cp $CWD/$IMAGE_DIR/* $DOXYGEN_OUTPUT_DIR/html/

echo "Finished!"
exit;

