vibe-s3 - S3 object store client using Vibe.d's HTTP client
========

### This library is highly alpha and mostly untested. Use at your own risk

Examples
--------
Example projects showing usage available under `examples/`

To run the examples you need to export your credentials:

```bash
export S3_BUCKET=mybucket
export S3_ENDPOINT=s3.us-east-2.amazonaws.com
export S3_REGION=us-east-2
export S3_ACCESS_KEY_NAME=xxx
export S3_ACCESS_KEY_ID=xxx
export S3_ACCESS_KEY_SECRET=xxx
```

Usage
-----
```d
S3CredentialSource creds = new StaticS3CredSource(s3AccessKeyId,s3AccessKeySecret,s3AccessKeyName);
ObjectStoreClient s3 = new S3Client(s3Endpoint,s3Region,creds,s3Config);

BucketItemListing list = s3.list("mybucket");

s3.upload("mybucket/remotefile.txt", "localfile.txt");

s3.download("mybucket/remotefile.txt", "localfile.txt");
```

Build
-----
```bash
dub build
```

Dependencies
-----
* Vibe.d
* OpenSSL 1.1.x

Note for OS X: 
you need to force use Homebrews OpenSSL
`brew link --force openssl`