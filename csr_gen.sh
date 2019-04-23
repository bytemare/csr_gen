#!/bin/bash

: '
	SPDX-License-Identifier: GPL-3.0-or-later

	Copyright (C) 2016-2017 Bytemare <d@bytema.re>. All Rights Reserved.
'


# Launch like that : ./csr_gen.sh ec secp256k1 csr_gen.cnf



# Organisational Data : Replaces the req_distiguished_name fiel stuff in conf file
C_C="" 		# Country 2-character Code (e.g. FR)
C_ST="" 	# State (e.g. Ile-De-France)
C_L="" 		# Locality (e.g. Paris)
C_O=""		# Organisation (e.g. Google Inc.)
C_OU=""		# Organisational Unit (e.g. IT-Security-Departement)
C_CN=""		# Common Name (typically host+domain, should be the same than the address, like "www.website.com")
C_EMAIL=""	# Email (you get it)


# Subject to insert into CSR
#SUBJECT="/C=$C_C/ST=$C_ST/L=$C_L/O=$C_O/OU=$C_OU/CN=$C_CN/emailAddress=$C_EMAIL"
SUBJECT="/"


# Values for cert types
SUPPORTED_TYPES="rsa dsa ec"
SUPPORTED_SIZES="2048 3072 4096 8192"
SUPPORTED_CURVES="secp256k1 secp384r1 secp521r1 prime256v1"

# Openssl commands
OPENSSL=openssl

# Working Directory
WD=.

# User Input
KEY_TYPE=$1
KEY_SIZE_CURVE=$2

# Certificate Configuration
#CNF_FILE=signing.cnf
CNF_FILE=$3

# Keyfiles info
CUR=${KEY_TYPE}-${KEY_SIZE_CURVE}
DIR=$WD/$CUR
CSR_FILE=$DIR/$CUR.csr
CRT_FILE=$DIR/cert_$CUR.crt
KEY_FILE=$DIR/private_$CUR.key
PUB_KEY_FILE=$DIR/public_$CUR.key



#
# Verification methods for user input
#
contains() {
        # If $2 is contained in the $3 list of elements
        if ! [[ " $3 " =~ " $2 " ]]; then
                echo "[Error] $1 is not valid : $2"
                exit 1
        fi
}


check_key_type(){
        contains "Key type"  ${KEY_TYPE} "${SUPPORTED_TYPES}"
}


check_size(){
        contains "Key size/curve" ${KEY_SIZE_CURVE} "${SUPPORTED_SIZES} ${SUPPORTED_CURVES}"
}


check_dir(){
	if [ -d "$DIR" ]; then
		echo "[Error] The directory $DIR already exists. Please rename it to generate new keys with these parameters."
		exit 1
	fi
	
	echo "[i] Creating directory to store material : $DIR"
	mkdir -p $DIR
}


clean_quit(){
	rm -rf $DIR
}


#
# Make DSA Certificate (EC option specified in function argument)
#
make_dsa_cert(){
        PKEYOPT=$1
        TMP_PARAM_FILE="${KEY_FILE}-param.cnf"

        # Generate parameters and store them in temporary file
        $OPENSSL genpkey -genparam -algorithm ${KEY_TYPE} -pkeyopt ${PKEYOPT}:${KEY_SIZE_CURVE} -out ${TMP_PARAM_FILE}

        # Generate keys
        $OPENSSL genpkey -out ${KEY_FILE} -paramfile ${TMP_PARAM_FILE}
        rm ${TMP_PARAM_FILE}
}


#
# Generate public-private key-pair given algorithm and key-length
#
generate_keys(){

        # For DSA and ECDSA certificates, the new genpkey command has a special behaviour. These are the pkeyopt:
        # DSA : "dsa_paramgen_bits"
        # ECDSA : "ec_paramgen_curve"

        if [[ ${KEY_TYPE} == "rsa" ]]; then

                $OPENSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${KEY_SIZE_CURVE} -out ${KEY_FILE}

        elif [[ ${KEY_TYPE} == "dsa" ]]; then

                make_dsa_cert "dsa_paramgen_bits"

        elif [[ ${KEY_TYPE} == "ec" ]]; then

                make_dsa_cert "ec_paramgen_curve"
        else
                echo "[Error] ERROR : Key type \"${KEY_TYPE}\" not recognized."
                echo "[!] This message should not appear !!!"
		clean_quit
                exit 1;
        fi

        if [[ $? -ne 0 ]]; then
                echo "[Error] ERROR : Certificate creation failed."
		clean_quit
                exit 1
        else
                echo "[Ok] Created private key ${KEY_FILE}."
        fi
}


#
# Make CSR : builds a certificate signing request
#
make_csr(){

        openssl req -new -key ${KEY_FILE} -nodes -out ${CSR_FILE} -subj $SUBJECT -config ${CNF_FILE}
        if [[ $? -ne 0 ]]; then
                echo "[Error] ERROR : CSR creation failed."
		clean_quit
                exit 1
        else
                echo "[Ok] Created CSR ${CSR_FILE}."
        fi
}


#
# Extract public key from private key
#
extract_public_from_private(){

        EXTRACT_COMMAND=${KEY_TYPE}
        openssl ${EXTRACT_COMMAND} -in ${KEY_FILE} -pubout -out ${PUB_KEY_FILE}
        if [[ $? -ne 0 ]]; then
                echo "[Error] ERROR : Public Key extraction failed."
		clean_quit
                exit 1
        else
                echo "[Ok] Extracted public key ${PUB_KEY_FILE}."
        fi
}


#
# Clean up : remove temprorary files, CSR and changes permissions on key files
#
clean_up(){

        #mv ${PUB_KEY_FILE} $DIR/pkey.key

        #rm ${CSR_FILE}

        chmod 400 ${KEY_FILE} #${CRT_FILE} ${PUB_KEY_FILE} #$DIR/pkey.key

}


main(){

        check_key_type ${KEY_TYPE}
        check_size ${KEY_SIZE_CURVE}
	    check_dir ${KEY_TYPE} ${KEY_SIZE_CURVE}

        if [[ $? -ne 0 ]]; then
                echo "[Error] The only thing you created was an error."
                exit 1
        fi

        #
        # Generate keys pairs : given user input, generates RSA, DSA or ECDSA key-pairs/parameters.
        #
        generate_keys

        #
        # Make CSR
        #
        make_csr

	# Clean up before exiting
        clean_up
}



# Fire.
main
