#!/bin/bash
#
# This script automatically extracts the native libs from the jnetpcap distriubtion
# and bundles them along with the "usual" content of the jnetpcap.jar in a new jar file.
# This is required for clj-net-pcaps automatic native library extraction feature.
#
# Author: Ruediger Gad <r.c.g@gmx.de>
#
# License: GNU GPLv2 or at your option later 
#
# This file comes without any warranty.
# You use it and the produced results at your own risk
# 


#
# Extract the required data (base URL and version) from the full URL.
#
if [ $# -ne 0 ]
then
  TEMPLATE_URL="$1"
else
  TEMPLATE_URL="http://slytechs.com/downloads/dist/a120913os/jnetpcap-1.4.r1390-1.win32.zip"
fi
echo "Using URL: $TEMPLATE_URL"

IFS="/"; read -a URL_ARRAY <<< "$TEMPLATE_URL"
BASE_URL="http://${URL_ARRAY[2]}/${URL_ARRAY[3]}/${URL_ARRAY[4]}/${URL_ARRAY[5]}"
TEMPLATE_FILE_NAME=${URL_ARRAY[6]}
JNETPCAP_VERSION=$(echo ${URL_ARRAY[6]} | head -c -13 | tail -c +10)
JNETPCAP_BUILD=$(echo ${URL_ARRAY[6]} | head -c -11 | tail -c +20)

#
# Prepare a temporary directory.
#
TEMP_DIR="jnetpcap_temp"
mkdir "$TEMP_DIR"
cd "$TEMP_DIR"

#
# Operating system specific strings.
#
LINUX_i386="linux.i386"
LINUX_X86_64="linux.x86_64"
WIN32="win32"
WIN64="win64"
# Temp dir
TEMP_JAR_DIR="jar_temp"

echo "Downloading jnetpcap version $JNETPCAP_VERSION-$JNETPCAP_BUILD."

#echo "Downloading Linux i386 version..."
#wget "$BASE_URL/jnetpcap-$JNETPCAP_VERSION-$JNETPCAP_BUILD.$LINUX_i386.tgz"
echo "Downloading Linux x86_64 version..."
wget "$BASE_URL/jnetpcap-$JNETPCAP_VERSION-$JNETPCAP_BUILD.$LINUX_X86_64.tgz"
echo "Downloading Windows 32-bit version..."
wget "$BASE_URL/jnetpcap-$JNETPCAP_VERSION-$JNETPCAP_BUILD.$WIN32.zip"
echo "Downloading Windows 64-bit version..."
wget "$BASE_URL/jnetpcap-$JNETPCAP_VERSION-$JNETPCAP_BUILD.$WIN64.zip"

#
# Extract files and repackage jar.
#
mkdir "$LINUX_i386"
mkdir "$LINUX_X86_64"
mkdir "$WIN32"
mkdir "$WIN64"

#tar -xzf "jnetpcap-$JNETPCAP_VERSION-$JNETPCAP_BUILD.$LINUX_i386.tgz" -C "$LINUX_i386"
tar -xzf "jnetpcap-$JNETPCAP_VERSION-$JNETPCAP_BUILD.$LINUX_X86_64.tgz" -C "$LINUX_X86_64"
unzip "jnetpcap-$JNETPCAP_VERSION-$JNETPCAP_BUILD.$WIN32.zip" -d "$WIN32"
unzip "jnetpcap-$JNETPCAP_VERSION-$JNETPCAP_BUILD.$WIN64.zip" -d "$WIN64"

mkdir "$TEMP_JAR_DIR"

unzip "$LINUX_X86_64/jnetpcap-$JNETPCAP_VERSION/jnetpcap.jar" -d "$TEMP_JAR_DIR"

mkdir -p "$TEMP_JAR_DIR/native/linux/i386"
mkdir -p "$TEMP_JAR_DIR/native/linux/amd64"
mkdir -p "$TEMP_JAR_DIR/native/windows/x86"
mkdir -p "$TEMP_JAR_DIR/native/windows/x86_64"


#cp "$LINUX_i386/jnetpcap-$JNETPCAP_VERSION/*.so" "$TEMP_JAR_DIR/native/linux/i386"
cp $LINUX_X86_64/jnetpcap-$JNETPCAP_VERSION/*.so $TEMP_JAR_DIR/native/linux/amd64
cp $WIN32/jnetpcap-$JNETPCAP_VERSION/*.dll $TEMP_JAR_DIR/native/windows/x86
cp $WIN64/jnetpcap-$JNETPCAP_VERSION/*.dll $TEMP_JAR_DIR/native/windows/x86_64

cd "$TEMP_JAR_DIR"
zip -r "../../jnetpcap-$JNETPCAP_VERSION-${JNETPCAP_BUILD}a.jar" *

cd ../..
rm -rf "$TEMP_DIR"

