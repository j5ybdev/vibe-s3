module vibes3.s3model;

import vibe.d : InetHeaderMap;
import std.datetime;

enum OCTET_STREAM = "application/octet-stream";
enum DEFAULT_MAX_ERR_RETRY = 2;
enum DEFAULT_SCHEME = "https";
enum DEFAULT_CHUNK_SIZE = 512*1024; // 512KB
enum MIN_PART_SIZE = 5*1024*1024; // 5MB
enum DEFAULT_PART_SIZE = MIN_PART_SIZE;

enum StorageClass: string {
    STANDARD = "STANDARD",
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY",
    GLACIER = "GLACIER"
}

/// holds which s3 to use
struct S3Config {
    string endpoint;
    string url;
}

/// Holds onto static s3 credentials
struct S3Credentials {
    string accessKeyName;
    string accessKeyID;
    string accessKeySecret;
    string sessionToken;
}

/// Settings for the behavior of the s3 client
struct S3ClientConfig {
    uint maxErrorRetry = DEFAULT_MAX_ERR_RETRY;
    string scheme = DEFAULT_SCHEME;
    bool connectionPooledUpload = false;
}

struct UploadOptions {
    string contentType = OCTET_STREAM;
    StorageClass storageClass = StorageClass.STANDARD;
    size_t chunkSize = DEFAULT_CHUNK_SIZE;
    size_t partSize = DEFAULT_PART_SIZE;
    SysTime expires = SysTime.init;
    InetHeaderMap headers = InetHeaderMap.init;
}

struct UploadPartOptions {
    string contentType = OCTET_STREAM;
    size_t chunkSize = DEFAULT_CHUNK_SIZE;
}

struct DownloadOptions {
    string[string] queryParameters = null;
    InetHeaderMap headers = InetHeaderMap.init;
}

struct ListOptions {
    string delimiter;
    string prefix;
    string marker;
    uint maxKeys = 0;
}

struct Owner {
    string id;
    string displayName;
}

struct BucketListing {
    Owner owner;
    Bucket[] buckets;
}

struct Bucket {
    string name;
    SysTime creationDate;
}

struct BucketItemListing {
    string bucketName;
    string prefix;
    int maxKeys;
    bool truncated;
    string marker;
    BucketItem[] items;
}

struct BucketItem {
    string key;
    SysTime lastModified;
    string etag;
    ulong size;
    Owner owner;
    StorageClass storageClass;
    string type;
}

struct ErrorDetails {
    string code;
    string message;
}