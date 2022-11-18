#!/bin/bash

showHelp() {
	cat << EOF  
Usage: 
./S3APISigV4.sh -O <operation> -e <endpoint> -a <access_key> -s <secret_key> -b <bucket> -o <object>

Example:
./S3APISigV4.sh -O createBucket -a minioadmin -s minioadmin -e myminio.net:9000 -b mybucket
./S3APISigV4.sh -O listBuckets -a minioadmin -s minioadmin -e myminio.net:9000
./S3APISigV4.sh -O deleteBucket -a minioadmin -s minioadmin -e myminio.net:9000 -b mybucket
./S3APISigV4.sh -O uploadObject -a minioadmin -s minioadmin -e myminio.net:9000 -b mybucket -f ./testfile
./S3APISigV4.sh -O listObjects -a minioadmin -s minioadmin -e myminio.net:9000 -b mybucket
./S3APISigV4.sh -O downloadObject -a minioadmin -s minioadmin -e myminio.net:9000 -b mybucket -o testfile
./S3APISigV4.sh -O deleteObject -a minioadmin -s minioadmin -e myminio.net:9000 -b mybucket -o testfile

-h, --help		Display help

-O, --operaion		S3 Operation

-b, --bucket		The bucket name

-o, --object		The object name

-r, --region		The region

-f, --file-path		The file path

-a, --access-key	The access key

-s, --secret-key	The secret key

-e, --endpoint		S3 server endpoint

-H,			Use http

-l,			List all opration supported

EOF
}

showOperations() {
	echo "createBucket, listBuckets, deleteBucket, listObjects, uploadObject, downloadObject, deleteObject"
}


OPERATION=""
BUCKET_NAME=""
OBJECT_NAME=""
FILE_PATH=""
REGION="us-east-1"
ACCESS_KEY=""
SECRET_KEY=""
ENDPOINT=""
PROTOCOL="https"
SIGNATURE_ALGO="AWS4-HMAC-SHA256"
SERVICE="s3"

options=$(getopt -l "help,operation:,bucket:,object:,region:,file-path:,access-key:,secret-key:,endpoint:" -o "hO:b:o:r:f:a:s:e:Hl" -a -- "$@")

eval set -- "$options"

while true
do
	case "$1" in
		-h|--help) 
			showHelp
			exit 0
			;;
		-l)
			showOperations
			exit 0
			;;
		-O|--operation) 
			shift
			OPERATION="$1"
			;;
		-b|--bucket)
			shift
			BUCKET_NAME="$1"
			;;
		-o|--object)
			shift
			OBJECT_NAME="$1"
			;;
		-f|--file-path)
			shift
			FILE_PATH="$1"
			;;
		-r|--region)
			shift
			REGION="$1"
			;;
		-a|--accress-key)
			shift
			ACCESS_KEY="$1"
			;;
		-s|--secret-key)
			shift
			SECRET_KEY="$1"
			;;
		-e|--endpoint)
			shift
			ENDPOINT="$1"
			;;
		-H)
			PROTOCOL="http"
			;;
		--)
			shift
			break;;
	esac
	shift
done

HTTP_METHOD=""
TARGET_URI=""
HOSTNAME=$(printf $ENDPOINT | cut -d ":" -f 1)
DATE_S=$(date -u +'%Y%m%d')
DATE_L=$(date -u +'%Y%m%dT%H%M%SZ')
EMPTYSHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

headers_json='{}'

appendHeader() {
	local key=$1
	local val=$2
	headers_json=$(echo $headers_json | jq --arg key "$key" --arg val "$val" '. += {($key):$val}')
}

generateHeaders() {
	ret=$(echo -n $headers_json | jq -r 'keys[] as $k | "\($k):\(.[$k])"')

	echo "$ret"
}

generateSignedHeaders() {
	ret=$(echo -n $headers_json | jq -r 'keys[] as $k | "\($k)"' | xargs | sed -e 's/ /;/g')

	echo "$ret"
}

generateCanonicalRequestHash() {
	HTTPMethod=$1
	CanonicalURI=$2
	CanonicalQueryString=$3
	CanonicalHeaders=$4
	SignedHeaders=$5
	HashedPayload=$6

	CanonicalRequest="$HTTPMethod\n$CanonicalURI\n$CanonicalQueryString\n$CanonicalHeaders\n\n$SignedHeaders\n$HashedPayload"
	CanonicalRequestHash=$(printf "${CanonicalRequest}" | openssl dgst -sha256 | sed 's/^.* //')

	echo "$CanonicalRequestHash"
}

generateStringToSign() {
	CanonicalRequestHash=$1

	StringToSign="$SIGNATURE_ALGO\n$DATE_L\n${DATE_S}/${REGION}/$SERVICE/aws4_request\n$CanonicalRequestHash"

	echo "$StringToSign"
}

generateSignKey() {
	tmp0="AWS4${SECRET_KEY}"
	tmp1=$(printf "${DATE_S}" | openssl dgst -sha256 -mac hmac -macopt key:"${tmp0}" | sed 's/^.* //')
	tmp2=$(printf "${REGION}" | openssl dgst -sha256 -mac hmac -macopt hexkey:"${tmp1}" | sed 's/^.* //')
	tmp3=$(printf "${SERVICE}" | openssl dgst -sha256 -mac hmac -macopt hexkey:"${tmp2}" | sed 's/^.* //')
	SignKey=$(printf "aws4_request" | openssl dgst -sha256 -mac hmac -macopt hexkey:"${tmp3}" | sed 's/^.* //')

	echo "$SignKey"
}

generateSignature() {
	SignKey=$1
	StringToSign=$2

	signature=$(printf "${StringToSign}" | openssl dgst -sha256 -mac hmac -macopt hexkey:${SignKey} | sed 's/^.* //')

	echo "$signature"
}

doCreateBucket() {
	echo "Do CreateBucket" >&2

	appendHeader "host" "$HOSTNAME"
	appendHeader "x-amz-content-sha256" "$EMPTYSHA256"
	appendHeader "x-amz-date" "$DATE_L"

	HTTP_METHOD="PUT"
	TARGET_URI="/${BUCKET_NAME}"
	HEADERS=$(generateHeaders)
	SIGNED_HEADERS=$(generateSignedHeaders)
	REQ_HASH=$(generateCanonicalRequestHash "$HTTP_METHOD" "$TARGET_URI" "" "$HEADERS" "$SIGNED_HEADERS" "$EMPTYSHA256")
	STRING_TO_SIGN=$(generateStringToSign "$REQ_HASH")
	SIGN_KEY=$(generateSignKey)
	SIGNATURE=$(generateSignature "$SIGN_KEY" "$STRING_TO_SIGN")

	ret=$(curl -X ${HTTP_METHOD} -k \
		--header "Host: ${HOSTNAME}" \
		--header "X-Amz-Content-SHA256: ${EMPTYSHA256}" \
		--header "X-Amz-Date: ${DATE_L}" \
		--header "Authorization: ${SIGNATURE_ALGO} Credential=${ACCESS_KEY}/${DATE_S}/${REGION}/s3/aws4_request, SignedHeaders=${SIGNED_HEADERS}, Signature=${SIGNATURE}" \
		${PROTOCOL}://${ENDPOINT}/${BUCKET_NAME})

	echo "$ret"
}

doDeleteBucket() {
	echo "Do doDeleteBucket" >&2
	appendHeader "host" "$HOSTNAME"
	appendHeader "x-amz-content-sha256" "$EMPTYSHA256"
	appendHeader "x-amz-date" "$DATE_L"

	HTTP_METHOD="DELETE"
	TARGET_URI="/${BUCKET_NAME}"
	HEADERS=$(generateHeaders)
	SIGNED_HEADERS=$(generateSignedHeaders)
	REQ_HASH=$(generateCanonicalRequestHash "$HTTP_METHOD" "$TARGET_URI" "" "$HEADERS" "$SIGNED_HEADERS" "$EMPTYSHA256")
	STRING_TO_SIGN=$(generateStringToSign "$REQ_HASH")
	SIGN_KEY=$(generateSignKey)
	SIGNATURE=$(generateSignature "$SIGN_KEY" "$STRING_TO_SIGN")

	ret=$(curl -X ${HTTP_METHOD} -k \
		--header "Host: ${HOSTNAME}" \
		--header "X-Amz-Content-SHA256: ${EMPTYSHA256}" \
		--header "X-Amz-Date: ${DATE_L}" \
		--header "Authorization: ${SIGNATURE_ALGO} Credential=${ACCESS_KEY}/${DATE_S}/${REGION}/s3/aws4_request, SignedHeaders=${SIGNED_HEADERS}, Signature=${SIGNATURE}" \
		${PROTOCOL}://${ENDPOINT}/${BUCKET_NAME})

	echo "$ret"
}

doListBuckets() {
	echo "Do ListBuckets" >&2

	appendHeader "host" "$HOSTNAME"
	appendHeader "x-amz-content-sha256" "$EMPTYSHA256"
	appendHeader "x-amz-date" "$DATE_L"

	HTTP_METHOD="GET"
	TARGET_URI="/"
	HEADERS=$(generateHeaders)
	SIGNED_HEADERS=$(generateSignedHeaders)
	REQ_HASH=$(generateCanonicalRequestHash "$HTTP_METHOD" "$TARGET_URI" "" "$HEADERS" "$SIGNED_HEADERS" "$EMPTYSHA256")
	STRING_TO_SIGN=$(generateStringToSign "$REQ_HASH")
	SIGN_KEY=$(generateSignKey)
	SIGNATURE=$(generateSignature "$SIGN_KEY" "$STRING_TO_SIGN")

	ret=$(curl -X ${HTTP_METHOD} -k \
		--header "Host: ${HOSTNAME}" \
		--header "X-Amz-Content-SHA256: ${EMPTYSHA256}" \
		--header "X-Amz-Date: ${DATE_L}" \
		--header "Authorization: ${SIGNATURE_ALGO} Credential=${ACCESS_KEY}/${DATE_S}/${REGION}/s3/aws4_request, SignedHeaders=${SIGNED_HEADERS}, Signature=${SIGNATURE}" \
		${PROTOCOL}://${ENDPOINT}/)

	echo "$ret"
}

doListObjects() {
	echo "Do ListObjects" >&2

	appendHeader "host" "$HOSTNAME"
	appendHeader "x-amz-content-sha256" "$EMPTYSHA256"
	appendHeader "x-amz-date" "$DATE_L"

	HTTP_METHOD="GET"
	TARGET_URI="/${BUCKET_NAME}"
	HEADERS=$(generateHeaders)
	SIGNED_HEADERS=$(generateSignedHeaders)
	REQ_HASH=$(generateCanonicalRequestHash "$HTTP_METHOD" "$TARGET_URI" "" "$HEADERS" "$SIGNED_HEADERS" "$EMPTYSHA256")
	STRING_TO_SIGN=$(generateStringToSign "$REQ_HASH")
	SIGN_KEY=$(generateSignKey)
	SIGNATURE=$(generateSignature "$SIGN_KEY" "$STRING_TO_SIGN")

	ret=$(curl -X ${HTTP_METHOD} -k \
		--header "Host: ${HOSTNAME}" \
		--header "X-Amz-Content-SHA256: ${EMPTYSHA256}" \
		--header "X-Amz-Date: ${DATE_L}" \
		--header "Authorization: ${SIGNATURE_ALGO} Credential=${ACCESS_KEY}/${DATE_S}/${REGION}/s3/aws4_request, SignedHeaders=${SIGNED_HEADERS}, Signature=${SIGNATURE}" \
		${PROTOCOL}://${ENDPOINT}/${BUCKET_NAME})

	echo "$ret"
}

doUploadObject() {
	echo "Do UploadObject" >&2

	FILESHA256=$(openssl sha -sha256 "${FILE_PATH}" | sed 's/^.* //')

	appendHeader "host" "$HOSTNAME"
	appendHeader "x-amz-content-sha256" "$FILESHA256"
	appendHeader "x-amz-date" "$DATE_L"

	FILE_NAME="${FILE_PATH##*/}"
	HTTP_METHOD="PUT"
	TARGET_URI="/${BUCKET_NAME}/${FILE_NAME}"
	HEADERS=$(generateHeaders)
	SIGNED_HEADERS=$(generateSignedHeaders)
	REQ_HASH=$(generateCanonicalRequestHash "$HTTP_METHOD" "$TARGET_URI" "" "$HEADERS" "$SIGNED_HEADERS" "$FILESHA256")
	STRING_TO_SIGN=$(generateStringToSign "$REQ_HASH")
	SIGN_KEY=$(generateSignKey)
	SIGNATURE=$(generateSignature "$SIGN_KEY" "$STRING_TO_SIGN")

	ret=$(curl -X ${HTTP_METHOD} -k --upload-file "${FILE_PATH}" \
		--header "Host: ${HOSTNAME}" \
		--header "X-Amz-Content-SHA256: ${FILESHA256}" \
		--header "X-Amz-Date: ${DATE_L}" \
		--header "Authorization: ${SIGNATURE_ALGO} Credential=${ACCESS_KEY}/${DATE_S}/${REGION}/s3/aws4_request, SignedHeaders=${SIGNED_HEADERS}, Signature=${SIGNATURE}" \
		${PROTOCOL}://${ENDPOINT}/${BUCKET_NAME}/${FILE_NAME})

	echo "$ret"
}

doDownloadObject() {
	echo "Do DownloadObject" >&2

	appendHeader "host" "$HOSTNAME"
	appendHeader "x-amz-content-sha256" "$EMPTYSHA256"
	appendHeader "x-amz-date" "$DATE_L"

	HTTP_METHOD="GET"
	TARGET_URI="/${BUCKET_NAME}/${OBJECT_NAME}"
	HEADERS=$(generateHeaders)
	SIGNED_HEADERS=$(generateSignedHeaders)
	REQ_HASH=$(generateCanonicalRequestHash "$HTTP_METHOD" "$TARGET_URI" "" "$HEADERS" "$SIGNED_HEADERS" "$EMPTYSHA256")
	STRING_TO_SIGN=$(generateStringToSign "$REQ_HASH")
	SIGN_KEY=$(generateSignKey)
	SIGNATURE=$(generateSignature "$SIGN_KEY" "$STRING_TO_SIGN")

	ret=$(curl -X ${HTTP_METHOD} -k -O \
		--header "Host: ${HOSTNAME}" \
		--header "X-Amz-Content-SHA256: ${EMPTYSHA256}" \
		--header "X-Amz-Date: ${DATE_L}" \
		--header "Authorization: ${SIGNATURE_ALGO} Credential=${ACCESS_KEY}/${DATE_S}/${REGION}/s3/aws4_request, SignedHeaders=${SIGNED_HEADERS}, Signature=${SIGNATURE}" \
		${PROTOCOL}://${ENDPOINT}/${BUCKET_NAME}/${OBJECT_NAME})

	echo "$ret"
}

doDeleteObject() {
	echo "Do doDeleteObject" >&2
	appendHeader "host" "$HOSTNAME"
	appendHeader "x-amz-content-sha256" "$EMPTYSHA256"
	appendHeader "x-amz-date" "$DATE_L"

	HTTP_METHOD="DELETE"
	TARGET_URI="/${BUCKET_NAME}/${OBJECT_NAME}"
	HEADERS=$(generateHeaders)
	SIGNED_HEADERS=$(generateSignedHeaders)
	REQ_HASH=$(generateCanonicalRequestHash "$HTTP_METHOD" "$TARGET_URI" "" "$HEADERS" "$SIGNED_HEADERS" "$EMPTYSHA256")
	STRING_TO_SIGN=$(generateStringToSign "$REQ_HASH")
	SIGN_KEY=$(generateSignKey)
	SIGNATURE=$(generateSignature "$SIGN_KEY" "$STRING_TO_SIGN")

	ret=$(curl -X ${HTTP_METHOD} -k \
		--header "Host: ${HOSTNAME}" \
		--header "X-Amz-Content-SHA256: ${EMPTYSHA256}" \
		--header "X-Amz-Date: ${DATE_L}" \
		--header "Authorization: ${SIGNATURE_ALGO} Credential=${ACCESS_KEY}/${DATE_S}/${REGION}/s3/aws4_request, SignedHeaders=${SIGNED_HEADERS}, Signature=${SIGNATURE}" \
		${PROTOCOL}://${ENDPOINT}/${BUCKET_NAME}/${OBJECT_NAME})

	echo "$ret"
}

case "$OPERATION" in
	createBucket) 
		resp=$(doCreateBucket)
		;;
	deleteBucket)
		resp=$(doDeleteBucket)
		;;
	listBuckets)
		resp=$(doListBuckets)
		;;
	listObjects)
		resp=$(doListObjects)
		;;
	uploadObject)
		resp=$(doUploadObject)
		;;
	downloadObject)
		resp=$(doDownloadObject)
		;;
	deleteObject)
		resp=$(doDeleteObject)
		;;
	*)
		echo "Invalid operation"
		exit 1
		;;
esac

echo "$resp"
#echo "$resp" | xmlstarlet format --indent-tab
