#!/bin/sh
ARCHIVE_OFFSET=961

#-------------------------------------------------
#  Common variables
#-------------------------------------------------

FULL_PRODUCT_NAME="Check Point Mobile Access Portal Agent"
SHORT_PRODUCT_NAME="Mobile Access Portal Agent"
INSTALL_DIR=/usr/bin/cshell
INSTALL_CERT_DIR=${INSTALL_DIR}/cert
BAD_CERT_FILE=${INSTALL_CERT_DIR}/.BadCertificate

PATH_TO_JAR=${INSTALL_DIR}/CShell.jar

AUTOSTART_DIR=
USER_NAME=

CERT_DIR=/etc/ssl/certs
CERT_NAME=CShell_Certificate

LOGS_DIR=/var/log/cshell


#-------------------------------------------------
#  Common functions
#-------------------------------------------------

debugger(){
	read -p "DEBUGGER> Press [ENTER] key to continue..." key
}

show_error(){
    echo
    echo "$1. Installation aborted."
}

IsCShellStarted(){
   PID=`ps ax | grep -v grep | grep -F -i "${PATH_TO_JAR}" | awk '{print $1}'`

   if [ -z "$PID" ]
      then
          echo 0
      else
          echo 1
   fi
}

KillCShell(){
   for CShellPIDs in `ps ax | grep -v grep | grep -F -i "${PATH_TO_JAR}" | awk ' { print $1;}'`; do
       kill -15 ${CShellPIDs};
   done
}

IsFFStarted(){
   PID=`ps ax | grep -v grep | grep -i "firefox" | awk '{print $1}'`

   if [ -z "$PID" ]
      then
          echo 0
      else
          echo 1
   fi
}

IsChromeStarted(){
   PID=`ps ax | grep -v grep | grep -i "google/chrome" | awk '{print $1}'`

   if [ -z "$PID" ]
      then
          echo 0
      else
          echo 1
   fi
}

IsChromeInstalled()
{
  google-chrome --version > /dev/null 2>&1
  res=$?

  if [ ${res} = 0 ]
    then
    echo 1
  else
    echo 0
  fi
}

IsFirefoxInstalled()
{
  firefox --version > /dev/null 2>&1
  res=$?

  if [ "${res}" != "127" ]
    then
    echo 1
  else
    echo 0
  fi
}

IsNotSupperUser()
{
	if [ `id -u` != 0 ]
	then
		return 0
	fi

	return 1
}

GetUserName()
{
    user_name=`who | head -n 1 | awk '{print $1}'`
    echo ${user_name}
}

GetUserHomeDir()
{
	echo /home/serejo
	return 0
    user_name=$(GetUserName)
    echo $( getent passwd "${user_name}" | cut -d: -f6 )
}

GetFirstUserGroup()
{
    group=`groups $(GetUserName) | awk {'print $3'}`
    if [ -z "$group" ]
    then
	group="root"
    fi

    echo $group
}


GetFFProfilePaths()
{
	echo "/home/serejo/snap/firefox/common/.mozilla/firefox/mv1lx4q5.default"
	return 0
    USER_HOME=$(GetUserHomeDir)

    #regular FF
    if [ -f ${USER_HOME}/.mozilla/firefox/installs.ini ]
	then
		ff_profile_paths=""
		while IFS= read -r line; do
			match=$(echo "$line" | grep -c -o "Default")
			if [ "$match" != "0" ]
			then
				line=$( echo "$line" | sed 's/ /<+>/ g')
				line=$( echo "$line" | sed 's/Default=//')

				if [ $(echo "$line" | cut -c 1-1) = '/' ]
				then
					ff_profile_paths=$(echo "$ff_profile_paths<|>$line")
				else
					ff_profile_paths=$(echo "$ff_profile_paths<|>${USER_HOME}/.mozilla/firefox/$line")
				fi
			fi
		done < "${USER_HOME}/.mozilla/firefox/installs.ini"

		ff_profile_paths=$( echo $ff_profile_paths | sed 's/^<|>//')

		echo "${ff_profile_paths}"
		return 0
	else #FF snap for Ubunti
		if [ -f ${USER_HOME}/snap/firefox/common/.mozilla/firefox/profiles.ini ]
		then
			USER_HOME="${USER_HOME}/snap/firefox/common"
			ff_profile_paths=""
			while IFS= read -r line; do

				path_match=$( echo "$line" | grep -c -o 'Path=')
				if [ "$path_match" != "0" ]
				then
					ff_profile=$( echo $line | sed 's/^<|>//')
					ff_profile=$( echo "$ff_profile" | sed 's/Path=//')
				fi

				match=$(echo "$line" | grep -c -o "Default")
				if [ "$match" != "0" ]
				then
					ff_profile_paths=$(echo "${USER_HOME}/.mozilla/firefox/$ff_profile")
					break
				fi
			done < "${USER_HOME}/.mozilla/firefox/profiles.ini"

			echo "${ff_profile_paths}"
			return 0
		else
			return 1
		fi

    fi
}

GetFFDatabases()
{
    #define FF profile dir
    FF_PROFILE_PATH=$(GetFFProfilePaths)
	res=$?

    if [ "$res" -eq "1" ] || [ -z "$FF_PROFILE_PATH" ]
       then
       return 1
    fi

	ff_profiles=$(echo "$FF_PROFILE_PATH" | sed 's/<|>/ /' )

	ff_databases=""

	for ff_profile in $ff_profiles
	do
		ff_profile=$(echo "$ff_profile" | sed 's/<+>/ / g')

		if [ -f "${ff_profile}/cert9.db" ]
         then
			ff_databases=$(echo "$ff_databases<|>sql:${ff_profile}")
		else
			ff_databases=$(echo "$ff_databases<|>${ff_profile}")
		fi
	done

	ff_databases=$(echo "$ff_databases" | sed 's/ /<+>/ g')
	ff_databases=$(echo "$ff_databases" | sed 's/^<|>//' )

    echo "${ff_databases}"
    return 0
}

GetChromeProfilePath()
{
  chrome_profile_path="$(GetUserHomeDir)/.pki/nssdb"

  if [ ! -d "${chrome_profile_path}" ]
    then
    show_error "Cannot find Chrome profile"
    return 1
  fi

  echo "${chrome_profile_path}"
  return 0
}

DeleteCertificate()
{

	if [ "$(IsFirefoxInstalled)" = 1 ]
	then
    #define FF database
    FF_DATABASES=$(GetFFDatabases)

		if [ $? -ne 0 ]
		then
            return 1
		fi

	FF_DATABASES=$(echo "$FF_DATABASES" | sed 's/<|>/ /')

	for ff_db in $FF_DATABASES
	do
		ff_db=$(echo "$ff_db" | sed 's/<+>/ / g')

	#remove cert from Firefox
		for CSHELL_CERTS in `certutil -L -d "${ff_db}" | grep -F -i "${CERT_NAME}" | awk '{print $1}'`
        do
		    `certutil -D -n "${CERT_NAME}" -d "${ff_db}"`
        done

	    CSHELL_CERTS=`certutil -L -d "${ff_db}" | grep -F -i "${CERT_NAME}" | awk '{print $1}'`
    if [ ! -z "$CSHELL_CERTS" ]
       then
           echo "Cannot remove certificate from Firefox profile"
    fi
	done
    fi

    if [ "$(IsChromeInstalled)" = 1 ]
      then
        #define Chrome profile dir
        CHROME_PROFILE_PATH=$(GetChromeProfilePath)

        if [ -z "$CHROME_PROFILE_PATH" ]
          then
              show_error "Cannot get Chrome profile"
              return 1
        fi

        #remove cert from Chrome
        for CSHELL_CERTS in `certutil -L -d "sql:${CHROME_PROFILE_PATH}" | grep -F -i "${CERT_NAME}" | awk '{print $1}'`
        do
          `certutil -D -n "${CERT_NAME}" -d "sql:${CHROME_PROFILE_PATH}"`
        done


        CSHELL_CERTS=`certutil -L -d "sql:${CHROME_PROFILE_PATH}" | grep -F -i "${CERT_NAME}" | awk '{print $1}'`

        if [ ! -z "$CSHELL_CERTS" ]
          then
          echo "Cannot remove certificate from Chrome profile"
        fi
    fi

	rm -rf ${INSTALL_CERT_DIR}/${CERT_NAME}.*

	rm -rf /etc/ssl/certs/${CERT_NAME}.p12
}


ExtractCShell()
{
	if [ ! -d ${INSTALL_DIR}/tmp ]
	    then
	        show_error "Failed to extract archive. No tmp folder"
			return 1
	fi

    bunzip2 -c ./payloadvpn.bz | tar xf - -C ${INSTALL_DIR}/tmp > /dev/null 2>&1

	if [ $? -ne 0 ]
	then
		show_error "Failed to extract archive"
		return 1
	fi

	return 0
}

installFirefoxCerts(){
	#get list of databases
	FF_DATABASES=$(GetFFDatabases)
	FF_DATABASES=$(echo "$FF_DATABASES" | sed 's/<|>/ /')

	for ff_db in $FF_DATABASES
	do
		ff_db=$(echo "$ff_db" | sed 's/<+>/ / g')
		installFirefoxCert "$ff_db"
	done
}

installFirefoxCert(){
    # require Firefox to be closed during certificate installation
	while [  $(IsFFStarted) = 1 ]
	do
	  echo
	  echo "Firefox must be closed to proceed with ${SHORT_PRODUCT_NAME} installation."
	  read -p "Press [ENTER] key to continue..." key
	  sleep 2
	done

    FF_DATABASE="$1"


    if [ -z "$FF_DATABASE" ]
       then
            show_error "Cannot get Firefox database"
		   return 1
    fi

   #install certificate to Firefox
	`certutil -A -n "${CERT_NAME}" -t "TCPu,TCPu,TCPu" -i "${INSTALL_DIR}/cert/${CERT_NAME}.crt" -d "${FF_DATABASE}" >/dev/null 2>&1`


    STATUS=$?
    if [ ${STATUS} != 0 ]
         then
              rm -rf ${INSTALL_DIR}/cert/*
              show_error "Cannot install certificate into Firefox profile"
			  return 1
    fi

    return 0
}

installChromeCert(){
  #define Chrome profile dir
    CHROME_PROFILE_PATH=$(GetChromeProfilePath)

    if [ -z "$CHROME_PROFILE_PATH" ]
       then
            show_error "Cannot get Chrome profile path"
       return 1
    fi


    #install certificate to Chrome
    `certutil -A -n "${CERT_NAME}" -t "TCPu,TCPu,TCPu" -i "${INSTALL_DIR}/cert/${CERT_NAME}.crt" -d "sql:${CHROME_PROFILE_PATH}" >/dev/null 2>&1`

    STATUS=$?
    if [ ${STATUS} != 0 ]
         then
              rm -rf ${INSTALL_DIR}/cert/*
              show_error "Cannot install certificate into Chrome"
        return 1
    fi

    return 0
}

installCerts() {

	#TODO: Generate certs into tmp location and then install them if success


	#generate temporary password
    CShellKey=`openssl rand -base64 12`
    # export CShellKey

    if [ -f ${INSTALL_DIR}/cert/first.elg ]
       then
           rm -f ${INSTALL_DIR}/cert/first.elg
    fi
    echo $CShellKey > ${INSTALL_DIR}/cert/first.elg


    #generate intermediate certificate
    openssl genrsa -out ${INSTALL_DIR}/cert/${CERT_NAME}.key 2048 >/dev/null 2>&1

    STATUS=$?
    if [ ${STATUS} != 0 ]
       then
          show_error "Cannot generate intermediate certificate key"
		  return 1
    fi

    openssl req -x509 -sha256 -new -key ${INSTALL_DIR}/cert/${CERT_NAME}.key -days 3650 -out ${INSTALL_DIR}/cert/${CERT_NAME}.crt -subj "/C=IL/O=Check Point/OU=Mobile Access/CN=Check Point Mobile" >/dev/null 2>&1

    STATUS=$?
    if [ ${STATUS} != 0 ]
       then
          show_error "Cannot generate intermediate certificate"
		  return 1
    fi

    #generate cshell cert
    openssl genrsa -out ${INSTALL_DIR}/cert/${CERT_NAME}_cshell.key 2048 >/dev/null 2>&1
    STATUS=$?
    if [ ${STATUS} != 0 ]
       then
          show_error "Cannot generate certificate key"
		  return 1
    fi

    openssl req -new -key ${INSTALL_DIR}/cert/${CERT_NAME}_cshell.key -out ${INSTALL_DIR}/cert/${CERT_NAME}_cshell.csr  -subj "/C=IL/O=Check Point/OU=Mobile Access/CN=localhost" >/dev/null 2>&1
    STATUS=$?
    if [ ${STATUS} != 0 ]
       then
          show_error "Cannot generate certificate request"
		  return 1
    fi

    printf "authorityKeyIdentifier=keyid\nbasicConstraints=CA:FALSE\nkeyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = localhost" > ${INSTALL_DIR}/cert/${CERT_NAME}.cnf

    openssl x509 -req -sha256 -in ${INSTALL_DIR}/cert/${CERT_NAME}_cshell.csr -CA ${INSTALL_DIR}/cert/${CERT_NAME}.crt -CAkey ${INSTALL_DIR}/cert/${CERT_NAME}.key -CAcreateserial -out ${INSTALL_DIR}/cert/${CERT_NAME}_cshell.crt -days 3650 -extfile "${INSTALL_DIR}/cert/${CERT_NAME}.cnf" >/dev/null 2>&1
    STATUS=$?
    if [ ${STATUS} != 0 ]
       then
          show_error "Cannot generate certificate"
		  return 1
    fi


    #create p12
    openssl pkcs12 -export -out ${INSTALL_DIR}/cert/${CERT_NAME}.p12 -in ${INSTALL_DIR}/cert/${CERT_NAME}_cshell.crt -inkey ${INSTALL_DIR}/cert/${CERT_NAME}_cshell.key -passout pass:$CShellKey >/dev/null 2>&1
    STATUS=$?
    if [ ${STATUS} != 0 ]
       then
          show_error "Cannot generate p12"
		  return 1
    fi

    #create symlink
    if [ -f /etc/ssl/certs/${CERT_NAME}.p12 ]
       then
           rm -rf /etc/ssl/certs/${CERT_NAME}.p12
    fi

    ln -s ${INSTALL_DIR}/cert/${CERT_NAME}.p12 /etc/ssl/certs/${CERT_NAME}.p12

    if [ "$(IsFirefoxInstalled)" = 1 ]
    then
		installFirefoxCerts
    STATUS=$?
    if [ ${STATUS} != 0 ]
    	then
    		return 1
    fi
    fi

    if [ "$(IsChromeInstalled)" = 1 ]
    	then
        installChromeCert
    		STATUS=$?
    		if [ ${STATUS} != 0 ]
    			then
    				return 1
    		fi
    fi

    #remove unnecessary files
    rm -f ${INSTALL_DIR}/cert/${CERT_NAME}*.key
    rm -f ${INSTALL_DIR}/cert/${CERT_NAME}*.srl
    rm -f ${INSTALL_DIR}/cert/${CERT_NAME}*.cnf
    rm -f ${INSTALL_DIR}/cert/${CERT_NAME}_*.csr
    rm -f ${INSTALL_DIR}/cert/${CERT_NAME}_*.crt

	return 0
}

#-------------------------------------------------
#  Cleanup functions
#-------------------------------------------------


cleanupTmp() {
	rm -rf ${INSTALL_DIR}/tmp
}


cleanupInstallDir() {
	rm -rf ${INSTALL_DIR}

	#Remove  autostart file
	if [ -f "$(GetUserHomeDir)/.config/autostart/cshell.desktop" ]
	then
		rm -f "$(GetUserHomeDir)/.config/autostart/cshell.desktop"
	fi
}


cleanupCertificates() {
	DeleteCertificate
}


cleanupAll(){
	cleanupCertificates
	cleanupTmp
	cleanupInstallDir
}


cleanupOnTrap() {
	echo "Installation has been interrupted"

	if [ ${CLEAN_ALL_ON_TRAP} = 0 ]
		then
			cleanupTmp
		else
			cleanupAll
			echo "Your previous version of ${FULL_PRODUCT_NAME} has already been removed"
			echo "Please restart installation script"
	fi
}
#-------------------------------------------------
#  CShell Installer
#
#  Script logic:
#	 1. Check for SU
#	 2. Check for openssl & certutils
#	 3. Check if CShell is instgalled and runnung
#	 4. Extract files
#	 5. Move files to approrpiate locations
#	 6. Add launcher to autostart
#	 7. Install certificates if it is required
#	 8. Start launcher
#
#-------------------------------------------------

trap cleanupOnTrap 2
trap cleanupOnTrap 3
trap cleanupOnTrap 13
trap cleanupOnTrap 15

CLEAN_ALL_ON_TRAP=0
#check that root has access to DISPLAY
USER_NAME=`GetUserName`

line=`xhost | grep -Fi "localuser:$USER_NAME"`
if [ -z "$line" ]
then
	xhost +"si:localuser:$USER_NAME" > /dev/null 2>&1
	res=$?
	if [ ${res} != 0 ]
	then
		echo "Please add \"root\" and \"$USER_NAME\" to X11 access list"
		exit 1
	fi
fi

line=`xhost | grep -Fi "localuser:root"`
if [ -z "$line" ]
then
	xhost +"si:localuser:root" > /dev/null 2>&1
	res=$?
	if [ ${res} != 0 ]
	then
		echo "Please add \"root\" and \"$USER_NAME\" to X11 access list"
		exit 1
	fi
fi


#choose privileges elevation mechanism
getSU()
{
	#handle Ubuntu
	string=`cat /etc/os-release | grep -i "^id=" | grep -Fi "ubuntu"`
	if [ ! -z $string ]
	then
		echo "sudo"
		return
	fi

	#handle Fedora 28 and later
	string=`cat /etc/os-release | grep -i "^id=" | grep -Fi "fedora"`
	if [ ! -z $string ]
	then
		ver=$(cat /etc/os-release | grep -i "^version_id=" | sed -n 's/.*=\([0-9]\)/\1/p')
		if [ "$((ver))" -ge 28 ]
		then
			echo "sudo"
			return
		fi
	fi

	echo "su"
}

# Check if supper user permissions are required
if IsNotSupperUser
then

    # show explanation if sudo password has not been entered for this terminal session
    sudo -n true > /dev/null 2>&1
    res=$?

    if [ ${res} != 0 ]
        then
        echo "The installation script requires root permissions"
        echo "Please provide the root password"
    fi

    #rerun script wuth SU permissions

    typeOfSu=$(getSU)
    if [ "$typeOfSu" = "su" ]
    then
    	su -c "sh $0 $*"
    else
    	sudo sh "$0" "$*"
    fi

    exit 1
fi

#check if openssl is installed
openssl_ver=$(openssl version | awk '{print $2}')

if [ -z $openssl_ver ]
   then
       echo "Please install openssl."
       exit 1
fi

#check if certutil is installed
certutil -H > /dev/null 2>&1

STATUS=$?
if [ ${STATUS} != 1 ]
   then
       echo "Please install certutil."
       exit 1
fi

#check if xterm is installed
xterm -h > /dev/null 2>&1

STATUS=$?
if [ ${STATUS} != 0 ]
   then
       echo "Please install xterm."
       exit 1
fi

echo "Start ${FULL_PRODUCT_NAME} installation"

#create CShell dir
mkdir -p ${INSTALL_DIR}/tmp

STATUS=$?
if [ ${STATUS} != 0 ]
   then
	   show_error "Cannot create temporary directory ${INSTALL_DIR}/tmp"
	   exit 1
fi

#extract archive to ${INSTALL_DIR/tmp}
echo -n "Extracting ${SHORT_PRODUCT_NAME}... "

ExtractCShell "${ARCHIVE_OFFSET}" "$0"
STATUS=$?
if [ ${STATUS} != 0 ]
	then
		cleanupTmp
		exit 1
fi
echo "Done"

#Shutdown CShell
echo -n "Installing ${SHORT_PRODUCT_NAME}... "

if [ $(IsCShellStarted) = 1 ]
    then
        echo
        echo "Shutdown ${SHORT_PRODUCT_NAME}"
        KillCShell
        STATUS=$?
        if [ ${STATUS} != 0 ]
            then
                show_error "Cannot shutdown ${SHORT_PRODUCT_NAME}"
                exit 1
        fi

        #wait up to 10 sec for CShell to close
        for i in $(seq 1 10)
            do
                if [ $(IsCShellStarted) = 0 ]
                    then
                        break
                    else
                        if [ $i = 10 ]
                            then
                                show_error "Cannot shutdown ${SHORT_PRODUCT_NAME}"
                                exit 1
                            else
                                sleep 1
                        fi
                fi
        done
fi

#remove CShell files
CLEAN_ALL_ON_TRAP=1

find ${INSTALL_DIR} -maxdepth 1 -type f -delete

#remove certificates. This will result in re-issuance of certificates
cleanupCertificates
if [ $? -ne 0 ]
then
	show_error "Cannot delete certificates"
	exit 1
fi

#copy files to appropriate locaton
mv -f ${INSTALL_DIR}/tmp/* ${INSTALL_DIR}
STATUS=$?
if [ ${STATUS} != 0 ]
   then
	   show_error "Cannot move files from ${INSTALL_DIR}/tmp to ${INSTALL_DIR}"
	   cleanupTmp
	   cleanupInstallDir
	   exit 1
fi


chown root:root ${INSTALL_DIR}/*
STATUS=$?
if [ ${STATUS} != 0 ]
   then
	   show_error "Cannot set ownership to ${SHORT_PRODUCT_NAME} files"
	   cleanupTmp
	   cleanupInstallDir
	   exit 1
fi

chmod 711 ${INSTALL_DIR}/launcher

STATUS=$?
if [ ${STATUS} != 0 ]
   then
	   show_error "Cannot set permissions to ${SHORT_PRODUCT_NAME} launcher"
	   cleanupTmp
	   cleanupInstallDir
	   exit 1
fi

#copy autostart content to .desktop files
AUTOSTART_DIR=`GetUserHomeDir`

if [  -z $AUTOSTART_DIR ]
	then
		show_error "Cannot obtain HOME dir"
		cleanupTmp
		cleanupInstallDir
		exit 1
	else
	    AUTOSTART_DIR="${AUTOSTART_DIR}/.config/autostart"
fi


if [ ! -d ${AUTOSTART_DIR} ]
	then
		mkdir ${AUTOSTART_DIR}
		STATUS=$?
		if [ ${STATUS} != 0 ]
			then
				show_error "Cannot create directory ${AUTOSTART_DIR}"
				cleanupTmp
				cleanupInstallDir
				exit 1
		fi
		chown $USER_NAME:$USER_GROUP ${AUTOSTART_DIR}
fi


if [ -f ${AUTOSTART_DIR}/cshel.desktop ]
	then
		rm -f ${AUTOSTART_DIR}/cshell.desktop
fi


mv ${INSTALL_DIR}/desktop-content ${AUTOSTART_DIR}/cshell.desktop
STATUS=$?

if [ ${STATUS} != 0 ]
   	then
		show_error "Cannot move desktop file to ${AUTOSTART_DIR}"
		cleanupTmp
		cleanupInstallDir
	exit 1
fi
chown $USER_NAME:$USER_GROUP ${AUTOSTART_DIR}/cshell.desktop

echo "Done"


#install certificate
echo -n "Installing certificate... "

if [ ! -d ${INSTALL_CERT_DIR} ]
   then
       mkdir -p ${INSTALL_CERT_DIR}
		STATUS=$?
		if [ ${STATUS} != 0 ]
			then
				show_error "Cannot create ${INSTALL_CERT_DIR}"
				cleanupTmp
				cleanupInstallDir
				exit 1
		fi

		installCerts
		STATUS=$?
		if [ ${STATUS} != 0 ]
			then
				cleanupTmp
				cleanupInstallDir
				cleanupCertificates
				exit 1
		fi
   else
       if [ -f ${BAD_CERT_FILE} ] || [ ! -f ${INSTALL_CERT_DIR}/${CERT_NAME}.crt ] || [ ! -f ${INSTALL_CERT_DIR}/${CERT_NAME}.p12 ]
          then
			cleanupCertificates
			installCerts
			STATUS=$?
			if [ ${STATUS} != 0 ]
				then
					cleanupTmp
					cleanupInstallDir
					cleanupCertificates
					exit 1
			fi
		 else
		   #define FF database

			FF_DATABASES=$(GetFFDatabases)
			FF_DATABASES=$(echo "$FF_DATABASES" | sed 's/<|>/ /')

			for ff_db in $FF_DATABASES
			do
				ff_db=$(echo "$ff_db" | sed 's/<+>/ / g')

				CSHELL_CERTS=`certutil -L -d "${ff_db}" | grep -F -i "${CERT_NAME}" | awk '{print $1}'`
	       if [ -z "$CSHELL_CERTS" ]
				then
					installFirefoxCert "$ff_db"
				STATUS=$?
				if [ ${STATUS} != 0 ]
					then
						cleanupTmp
						cleanupInstallDir
						cleanupCertificates
						exit 1
				fi
	       fi
			done

			#check if certificate exists in Chrome and install it
			CHROME_PROFILE_PATH=$(GetChromeProfilePath)
			CSHELL_CERTS=`certutil -L -d "sql:${CHROME_PROFILE_PATH}" | grep -F -i "${CERT_NAME}" | awk '{print $1}'`
			if [ -z "$CSHELL_CERTS" ]
				then
					installChromeCert
					STATUS=$?
					if [ ${STATUS} != 0 ]
						then
							cleanupTmp
							cleanupInstallDir
							cleanupCertificates
							exit 1
					fi

	       fi
       fi

fi
echo "Done"


#set user permissions to all files and folders

USER_GROUP=`GetFirstUserGroup`

chown $USER_NAME:$USER_GROUP ${INSTALL_DIR}
chown $USER_NAME:$USER_GROUP ${INSTALL_DIR}/*
chown $USER_NAME:$USER_GROUP ${INSTALL_CERT_DIR}
chown $USER_NAME:$USER_GROUP ${INSTALL_CERT_DIR}/*


if [ -d ${LOGS_DIR} ]
   then
   		rm -rf ${LOGS_DIR}
fi

mkdir ${LOGS_DIR}
chown $USER_NAME:$USER_GROUP ${LOGS_DIR}

#start cshell
echo -n "Starting ${SHORT_PRODUCT_NAME}... "

r=`exec su $USER_NAME -c /bin/sh << eof
${INSTALL_DIR}/launcher
eof`

res=$( echo "$r" | grep -i "CShell Started")

if [ "$res" ]
then
    cleanupTmp
    echo "Done"
    echo "Installation complete"
else
		show_error "Cannot start ${SHORT_PRODUCT_NAME}"
		exit 1
fi


exit 0
