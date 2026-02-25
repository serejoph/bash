#!/bin/sh
ARCHIVE_OFFSET=103

TMP_DIR=/tmp

LogEvent()
{
	echo $3
	if [ $1 = 1 ]
	then
		exit $2
	fi
}

ExtractSNX()
{
	bunzip2 -c payloadsnx.bz | (cd ${TMP_DIR}; tar xf -) > /dev/null 2>&1
	if [ ! $? -eq 0 ]
	then
		LogEvent 1 1 "failed to extract archive"
	fi
}

Cleanup()
{
	rm -f ${TMP_DIR}/SNX\ Installer
	rm -f ${TMP_DIR}/snx
	rm -f ${TMP_DIR}/snx_uninstall.sh
	exit 0
}

IsNotSupperUser()
{
	if [ `id -u` != 0 ]
	then
		return 0
	fi

	return 1
}


trap Cleanup 2
trap Cleanup 3
trap Cleanup 13
trap Cleanup 15

# do not install on RHEL and CentOS version 7.x (and below)
if [ -f "/etc/system-release" ]
then
	version=$(grep -oE '[0-9]+' /etc/system-release | head -n1)
	name=$(grep -oEi 'centos|red hat' /etc/system-release)
	if [ $? -eq 0 -a $version -le 7 ]
	then
		name=$(grep -oP '([a-zA-Z\ ]+)(?=\srelease)' /etc/system-release)
		echo "
Your version of ${name} is not supported.
This SNX build can work on ${name} release 8 and higher.
Installation aborted.
"
		read -p "Press [Enter] to exit..." dummy
		exit 1
	fi
fi

COMMAND_TO_RUN="install --owner=root --group=root --mode=755 snx /usr/bin/snx; install --owner=root --group=root --mode=755 snx_uninstall.sh /usr/bin/snx_uninstall; install --directory --owner=root --group=root --mode=u=rwx /etc/snx; install --directory --owner=root --group=root --mode=u=rwx /etc/snx/tmp"

# link the stdc++ library
STDCPLUSPLUS=`ls /usr/lib/libstdc++* | grep so | head -n 1` > /dev/null 2>&1
if [ "${STDCPLUSPLUS}" != "" ]
then
	COMMAND_TO_RUN="ln -sf ${STDCPLUSPLUS} /usr/lib/libcpc++-libc6.1-2.so.3; ${COMMAND_TO_RUN}"
fi

# Extract the SNX utility
ExtractSNX "${ARCHIVE_OFFSET}" "$0"

# Check if supper user permissions are required
if IsNotSupperUser
then
	echo "The installation script requires root permissions"
	echo "Please provide the root password"
fi

# Change directory to ${TMP_DIR}
cd ${TMP_DIR}
ln -s `which su` SNX\ Installer
PATH="${PATH}:."
SNX\ Installer -c "${COMMAND_TO_RUN}"
STATUS=$?

if [ ${STATUS} = 0 ]
then
	echo "Installation successfull"
else
	echo "Installation failed"
fi


Cleanup

exit 0
