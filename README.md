Usage: 

`./S3APISigV4.sh -O <operation> -e <endpoint> -a <access_key> -s <secret_key> -b <bucket> -o <object>`

Example:

Create Bucket

`./S3APISigV4.sh -O createBucket -a minioadmin -s minioadmin -e myminio.net:9000 -b mybucket`

List All Buckets

`./S3APISigV4.sh -O listBuckets -a minioadmin -s minioadmin -e myminio.net:9000`

Upload Object to Specific Bucket

`./S3APISigV4.sh -O uploadObject -a minioadmin -s minioadmin -e myminio.net:9000 -b mybucket -f ./testfile`

List All Objects in Specific Bucket

`./S3APISigV4.sh -O listObjects -a minioadmin -s minioadmin -e myminio.net:9000 -b mybucket`

Download Object from Specific Bucket

`./S3APISigV4.sh -O downloadObject -a minioadmin -s minioadmin -e myminio.net:9000 -b mybucket -o testfile`

