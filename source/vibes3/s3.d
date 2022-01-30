module vibes3.s3;

/**
* S3 client
*
* References:
* https://developers.digitalocean.com/documentation/spaces/#aws-s3-compatibility
* https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html
* 
* Modified from: https://github.com/tamediadigital/vibe-s3/
* 2020-11-10
*/
import vibe.d;
import vibe.core.stream;
import vibe.core.core;
import vibe.core.log;
import vibe.data.json;
import vibe.http.client;
import vibe.inet.message;
import vibe.http.common;
import std.algorithm;
import std.datetime;
import std.random;
import std.range;
import std.stdio;
import std.string;
import std.conv;
import std.digest.sha;
import std.math;
import std.string;
import std.format;
import std.array: appender;
import std.typecons: Tuple, tuple;
import memutils.all;
import vibes3.sigv4;
import vibes3.s3model;
import vibes3.s3xml;
import dxml.parser: parseXML;

enum S3 = "s3";

/**
* Credentials may change during the runtime of the app
*/
interface S3CredentialSource {
    /**
     * Retrieve the current set of credentials
     */
    S3Credentials get();

    /**
     * Called when credentials turn out to be rejected by the backend
     */
    void credentialsInvalid(in ref S3Credentials creds, string reason);
}

/**
  Provider of a static set of S3 credentials
  This will never use a session token, since the credentials have to be root or
  static IAM credentials.
 */
class StaticS3CredSource : S3CredentialSource {
    private S3Credentials creds;

    this(string keyID, string keySecret, string keyName = null) {
        S3Credentials c = {
            accessKeyID: keyID,
            accessKeySecret: keySecret,
            accessKeyName: keyName
        };
        creds = c;
    }

    S3Credentials get() {
        return creds;
    }

    void credentialsInvalid(in ref S3Credentials creds, string reason) {
        // Nothing we can do about this, just throw an exception
        throw new Exception("Static credentials with ID " ~ creds.accessKeyID ~ " rejected because: " ~ reason);
    }
}

interface ObjectStoreClient {
    BucketListing listBuckets(ListOptions options = ListOptions());
    BucketItemListing list(string bucket, ListOptions options = ListOptions());
    void upload(string resource, string sourcePath, UploadOptions options = UploadOptions());
    void upload(string resource, RandomAccessStream input, UploadOptions options = UploadOptions());
    void multipartUpload(string resource, scope InputStream input, UploadOptions options = UploadOptions());
    string uploadPart(string resource, string id, size_t part, RandomAccessStream input,
        in UploadPartOptions options = UploadPartOptions());
    string startMultipartUpload(string resource, UploadOptions options = UploadOptions());
    void completeMultipartUpload(string resource, string id, in Tuple!(string, size_t)[] parts, 
        InetHeaderMap headers = InetHeaderMap.init);
    void abortMultipartUpload(string resource, string id);
    void info(string resource, scope void delegate(scope HTTPClientResponse) del,
        DownloadOptions options = DownloadOptions());
    void download(string resource, scope void delegate(scope HTTPClientResponse) del,
        DownloadOptions options = DownloadOptions());
    void download(string resource, scope void delegate(scope InputStreamProxy) del,
        DownloadOptions options = DownloadOptions());
    void download(OutputStream)(string resource, scope OutputStream stream,
        DownloadOptions options = DownloadOptions());
    void download(string resource, string saveTo,
        DownloadOptions options = DownloadOptions());
    void deleteObject(string resource);
}

class NoOpObjectStoreClient : ObjectStoreClient {
    BucketListing listBuckets(ListOptions options = ListOptions()) { return BucketListing(); }
    BucketItemListing list(string bucket, ListOptions options = ListOptions()) { return BucketItemListing(); }
    void upload (string resource, string sourcePath, UploadOptions options = UploadOptions()) {}
    void upload(string resource, RandomAccessStream input, UploadOptions options = UploadOptions()) {}
    void multipartUpload(string resource, scope InputStream input, UploadOptions options = UploadOptions()) {}
    string uploadPart(string resource, string id, size_t part, RandomAccessStream input,
       in UploadPartOptions options = UploadPartOptions()) { return null; }
    string startMultipartUpload(string resource, UploadOptions options = UploadOptions()) { return null; }
    void completeMultipartUpload(string resource, string id, in Tuple!(string, size_t)[] parts,
        InetHeaderMap headers = InetHeaderMap.init) {}
    void abortMultipartUpload(string resource, string id) {}
    void info(string resource, scope void delegate(scope HTTPClientResponse) del,
        DownloadOptions options = DownloadOptions()) {}
    void download(string resource, scope void delegate(scope HTTPClientResponse) del,
        DownloadOptions options = DownloadOptions()) {}
    void download(string resource, scope void delegate(scope InputStreamProxy) del,
        DownloadOptions options = DownloadOptions()) {}
    void download(OutputStream)(string resource, scope OutputStream stream,
        DownloadOptions options = DownloadOptions()) {}
    void download(string resource, string saveTo,
        DownloadOptions options = DownloadOptions()) {}
    void deleteObject(string resource) {}
}


class S3Client : RESTClient, ObjectStoreClient {

    this(string endpoint, string region, S3CredentialSource credsSource, S3ClientConfig config = S3ClientConfig()) {
        enforce(region.length, "Region should be defined.");
        super(endpoint, region, S3, credsSource, config);
    }

    BucketListing listBuckets(ListOptions options = ListOptions()) {
        assert(options.maxKeys <= 1000);
        
        // make listing request
        InetHeaderMap headers;
        auto resp = doRequest(HTTPMethod.GET, "/", listOptionsToParams(options), headers);
        auto xml = parseXML(readResponse(resp));
        resp.dropBody();
        resp.destroy();

        BucketListing listing = readXmlListBucketResults(xml);

        return listing;
    }

    BucketItemListing list(string bucket, ListOptions options = ListOptions()) {
        assert(options.maxKeys <= 1000);

        // make listing request
        InetHeaderMap headers;
        headers[HDR_HOST] = format("%s.%s", bucket, endpoint);
        auto resp = doRequest(HTTPMethod.GET, "/", listOptionsToParams(options), headers);
        auto xml = parseXML(readResponse(resp));
        resp.dropBody();
        resp.destroy();

        return readXmlBucketItemListing(xml);
    }

    /**
    * Upload by specifying the path of the file to upload
    */
    void upload(string resource,
            string sourcePath,
            UploadOptions options = UploadOptions()) {

        auto fs = new FileInStream(sourcePath);
        scope(exit) {
            logDebug("Closing upload file read stream");
            fs.close();
        }
        upload(resource,fs,options);
    }

    void upload(string resource,
            RandomAccessStream input,
            UploadOptions options = UploadOptions()) {

        options.headers[HDR_CONTENT_TYPE] = options.contentType;
        options.headers[HDR_STORAGE_CLASS] = options.storageClass.to!string;
        string[] signedHeaders = [HDR_STORAGE_CLASS];
        doUpload(HTTPMethod.PUT, resource, null, options.headers, signedHeaders, input, options.chunkSize);
    }

    /++
    On_failure: aborts multipart upload.
    +/
    void multipartUpload(string resource,
                        scope InputStream input,
                        UploadOptions options = UploadOptions()) {
        import std.array: appender, uninitializedArray;
        import std.algorithm.comparison: min;
        logDebug("multipartUpload for %s ...", resource);
        enforce(options.partSize >= MIN_PART_SIZE, "multipartUpload: minimal allowed part size is 5 MB.");
        auto id = startMultipartUpload(resource, options);
        scope(failure) {
            logWarn("aborting multipart upload for resource=%s, uploadId=%s", resource, id);
            try {
                abortMultipartUpload(resource, id);
            }
            catch(Exception e) {
                logWarn(e.msg);
            }
        }

        auto buf = uninitializedArray!(ubyte[])(options.partSize);
        auto etags = appender!(Tuple!(string, size_t)[]);

        size_t least = input.leastSize;
        for (size_t part = 1;;part++) {
            size_t length;
            do {
                auto newLength = least + length;
                if (newLength > buf.length) {
                    newLength = buf.length;
                }
                input.read(buf[length .. newLength]);
                length = newLength;
                least = input.leastSize;

            } while(least && length < buf.length);

            logDebug("buf.length = %s", buf.length);
            logDebug("least = %s", least);
            logDebug("multipartUpload: sending %s bytes for part %s ...", length, part);
            UploadPartOptions pOptions = {
                contentType: options.contentType,
                chunkSize: options.chunkSize
            };

            auto etag = uploadPart(resource, id, part, createMemoryStream(buf[0 .. length], false),pOptions);
            etags.put(tuple(etag, part));
            if (least == 0) break;
        }
        enforce(etags.data, "At least one part should be uploaded.");
        completeMultipartUpload(resource, id, etags.data);
    }
    string uploadPart(string resource,
                    string id,
                    size_t part,
                    RandomAccessStream input,
                    in UploadPartOptions options = UploadPartOptions()) {
        
        string[string] queryParameters = [
            "partNumber": part.to!string,
            "uploadId": id,
        ];
        InetHeaderMap headers;
        headers[HDR_CONTENT_TYPE] = options.contentType;
        const string etag = doUpload(HTTPMethod.PUT, resource, queryParameters, headers, null, input, options.chunkSize);
        return etag;
    }

    string startMultipartUpload(string resource, UploadOptions options = UploadOptions()) {

        options.headers[HDR_CONTENT_TYPE] = options.contentType;
        options.headers[HDR_STORAGE_CLASS] = options.storageClass.to!string;
        if (options.expires != SysTime.init) {
            options.headers[HDR_EXPIRES] = webFormatTime(options.expires);
        }
        auto httpResp = doRequest(HTTPMethod.POST, resource, ["uploads":null], options.headers);
        scope(exit) {
            httpResp.dropBody();
            httpResp.destroy();
        }
        auto xml = parseXML(readResponse(httpResp));
        return readXmlInitMultiUploadResult(xml);
    }

    void completeMultipartUpload(string resource,
                                string id,
                                in Tuple!(string, size_t)[] parts,
                                InetHeaderMap headers = InetHeaderMap.init) {
        
        auto app = appender!(char[]);
        app.put(`<CompleteMultipartUpload>`);
        FormatSpec!char fmt;
        foreach(ref part; parts) {
            app.put(`<Part><PartNumber>`);
            app.formatValue(part[1], fmt);
            app.put(`</PartNumber><ETag>`);
            app.put(part[0]);
            app.put(`</ETag></Part>`);
        }
        app.put(`</CompleteMultipartUpload>`);
        auto httpResp = doRequest(HTTPMethod.POST, resource, ["uploadId":id], headers, cast(ubyte[])app.data);
        httpResp.dropBody();
        httpResp.destroy();
    }

    void abortMultipartUpload(string resource, string id) {
        auto httpResp = doRequest(HTTPMethod.DELETE, resource, ["uploadId":id], InetHeaderMap.init);
        httpResp.dropBody();
        httpResp.destroy();
    }


    void info(string resource, scope void delegate(scope HTTPClientResponse) del,
                DownloadOptions options = DownloadOptions()) {
        auto httpResp = doRequest(HTTPMethod.HEAD, resource, options.queryParameters, options.headers);
        scope(exit) {
            httpResp.dropBody();
            httpResp.destroy();
        }
        del(httpResp);
    }

    void download(string resource, scope void delegate(scope HTTPClientResponse) del,
                DownloadOptions options = DownloadOptions()) {
        auto httpResp = doRequest(HTTPMethod.GET, resource, options.queryParameters, options.headers);
        scope(exit) {
            httpResp.dropBody();
            httpResp.destroy();
        }
        del(httpResp);
    }

    /++
    Returns:
        Response headers list, which has type  DictionaryList!(string,false,12L,false)
    +/
    void download(string resource, scope void delegate(scope InputStreamProxy) del,
                DownloadOptions options = DownloadOptions()) {
        download(resource, (scope HTTPClientResponse resp) {
            del(resp.bodyReader);            
        }, options);
    }

    /// ditto
    void download(OutputStream)(string resource, scope OutputStream stream,
            DownloadOptions options = DownloadOptions()) {
        download(resource, (scope InputStreamProxy input) { input.pipe(stream); }, options);
    }

    /// ditto
    void download(string resource, string saveTo,
            DownloadOptions options = DownloadOptions()) {
        logDebug("writing file " ~ saveTo);
        auto file = openFile(saveTo, FileMode.createTrunc);
        scope(exit) file.close();
        download(resource, file, options);
    }

    void deleteObject(string resource) {
        InetHeaderMap headers;
        headers[HDR_CONTENT_TYPE] = TEXT_PLAIN;
        string[string] queryParams;
        auto httpResp = doRequest(HTTPMethod.DELETE, resource, queryParams, headers);
        httpResp.dropBody();
        httpResp.destroy();
    }

    private string[string] listOptionsToParams(ref ListOptions options) {
        string[string] queryParameters;
        if (options.delimiter !is null) queryParameters["delimiter"] = options.delimiter;
        if (options.prefix !is null)    queryParameters["prefix"]    = options.prefix;
        if (options.marker !is null)    queryParameters["marker"]    = options.marker;
        if (options.maxKeys)            queryParameters["max-keys"]  = options.maxKeys.to!string;
        return queryParameters;
    }
}

abstract class RESTClient {
    immutable string endpoint;
    immutable string region;
    immutable string service;

    private S3CredentialSource m_credsSource;
    private S3ClientConfig m_config;

    this(string endpoint, string region, string service, S3CredentialSource credsSource,
             S3ClientConfig config=S3ClientConfig()) {
        this.region = region;
        this.endpoint = endpoint;
        this.service = service;
        this.m_credsSource = credsSource;
        this.m_config = config;
    }

    protected:

    static string buildQueryParameterString(in string[string] queryParameters) {
        import vibe.textfilter.urlencode : urlEncode;

        auto stringBuilder = appender!string;
        int i = 0;
        foreach(qp; queryParameters.byKeyValue()) {
            if (i != 0) stringBuilder.put("&");

            stringBuilder.put(urlEncode(qp.key));
            if (qp.value) {
                stringBuilder.put("=");
                stringBuilder.put(urlEncode(qp.value));
            }
            i++;
        }
        return stringBuilder.data;
    }

    

    HTTPClientResponse doRequest(HTTPMethod method,
                                string resource,
                                string[string] queryParameters,
                                in InetHeaderMap headers,
                                in ubyte[] reqBody = null) {

        if (!resource.startsWith("/")) {
            resource = "/" ~ resource;
        }

        //Initialize credentials
        auto creds = m_credsSource.get();

        const string queryString = buildQueryParameterString(queryParameters);

        auto retries = ExponentialBackoff(m_config.maxErrorRetry);
        foreach (triesLeft; retries) {

            HTTPClientResponse resp;
            scope (failure) {
                if (resp) {
                    resp.dropBody();
                    resp.destroy();
                }
            }

            auto url = format("%s://%s%s?%s", m_config.scheme, endpoint, resource, queryString);
            resp = requestHTTP(url, (scope HTTPClientRequest req) {
                req.method = method;
                
                foreach (key, value; headers.byKeyValue) {
                    req.headers[key] = value;
                }

                // signing these headers cause the request to fail
                foreach (h; NOSIGN_HEADERS) {
                    req.headers.remove(h);
                }

                if (HDR_HOST !in req.headers) req.headers[HDR_HOST] = endpoint;
                auto timeString = currentTimeString();
                req.headers[HDR_AMZ_DATE] = timeString;
                req.headers[HDR_AMZ_CONTENT_SHA256] = sha256Of(reqBody).toHexString().toLower();
                if (creds.sessionToken && !creds.sessionToken.empty) {
                    req.headers[HDR_AMZ_SEC_TOKEN] = creds.sessionToken;
                }
                signRequest(req, queryParameters, reqBody, creds, timeString, region, service);
                if (reqBody) {
                    req.writeBody(reqBody);
                }
            });
            checkForError(resp);
            return resp;
        }
        assert(0); // if we make it here the request failed
    }

    string doUpload(HTTPMethod method, string resource, string[string] queryParameters,
                                in InetHeaderMap headers, in string[] additionalSignedHeaders,
                                scope RandomAccessStream payload, ulong blockSize = DEFAULT_CHUNK_SIZE) {

        auto retries = ExponentialBackoff(m_config.maxErrorRetry);
        foreach (triesLeft; retries) {
            payload.seek(0);
            logDebug("calling doUpload()");
            return doUpload(method, resource, queryParameters, headers, additionalSignedHeaders,
                            payload, payload.size, blockSize);
        }
        assert(0);
    }

    string doUpload(HTTPMethod method, string resource, string[string] queryParameters,
                                in InetHeaderMap headers, in string[] additionalSignedHeaders,
                                scope InputStream payload, ulong payloadSize, ulong blockSize = DEFAULT_CHUNK_SIZE) {

        // Calculate the body size upfront for the "Content-Length" header
        auto base16 = (ulong x) => ceil(log2(x)/4).to!ulong;
        enum ulong signatureSize = ";chunk-signature=".length + 64;
        immutable ulong numFullSizeBlocks = payloadSize / blockSize;
        immutable ulong lastBlockSize = payloadSize % blockSize;
        
        immutable ulong bodySize =  numFullSizeBlocks * (base16(blockSize)  + signatureSize + 4 + blockSize) // Full-Sized blocks (4 = 2*"\r\n")
                                 + (lastBlockSize  ? (base16(lastBlockSize) + signatureSize + 4 + lastBlockSize) : 0) // Part-Sized last block
                                 + (1 + signatureSize + 4); // Finishing 0-sized block
        

        scope(failure) {
            logDebug("Upload failure!");
            /*
            if (resp) {
                resp.dropBody();
                resp.destroy();
            }
            */
        }

        auto creds = m_credsSource.get();
        string etag = null;

        // build URL
        if (!resource.startsWith("/")) {
            resource = "/" ~ resource;
        }
        auto urlStr = m_config.scheme ~ "://" ~ endpoint ~ resource;
        if (queryParameters !is null) {
            urlStr ~= "?" ~ buildQueryParameterString(queryParameters);
        }
        const URL url = URL.parse(urlStr);
        const bool useTls = url.schema == "https";

        HTTPClientSettings settings = new HTTPClientSettings;
        settings.connectTimeout = 10.seconds;
        settings.readTimeout = 30.seconds;
	    settings.defaultKeepAliveTimeout = 0.seconds; // closes connection immediately after receiving the data.

        logDebug("doUpload to %s", urlStr);

        auto reqHandler = delegate(scope HTTPClientRequest req) {
            req.method = method;
            req.requestURI = url.pathString;
            
            //Initialize the headers
            foreach(key, value; headers.byKeyValue) {
                req.headers[key] = value;
            }

            //Since we might be doing retries, update the date
            const string isoTimeString = currentTimeString();
            req.headers[HDR_AMZ_DATE] = isoTimeString;
            auto date = isoTimeString.dateFromISOString;
            auto time = isoTimeString.timeFromISOString;
            
            req.contentType = OCTET_STREAM;
            if (HDR_CONTENT_TYPE in headers) {
                req.contentType = headers[HDR_CONTENT_TYPE];
            }
            
            req.headers[HDR_CONTENT_LENGTH] = bodySize.to!string;
            req.headers[HDR_AMZ_CONTENT_SHA256] = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
            req.headers[HDR_AMZ_DEC_CONTENT_LEN] = payloadSize.to!string;

            //Seems not to be working properly (S3 returns error if "Content-Length" is not used)
//                req.headers["Transfer-Encoding"] = "chunked";
//                if ("Content-Length" in headers)
//                    req.headers.remove("Content-Length");

            auto canonicalRequest = CanonicalRequest(
                method.to!string,
                resource,
                queryParameters,
                [
                    HDR_HOST:                       req.headers[HDR_HOST],
                    "content-length":               req.headers[HDR_CONTENT_LENGTH],
                    HDR_AMZ_CONTENT_SHA256:         req.headers[HDR_AMZ_CONTENT_SHA256],
                    HDR_AMZ_DATE:                   req.headers[HDR_AMZ_DATE],
                    HDR_AMZ_DEC_CONTENT_LEN: req.headers[HDR_AMZ_DEC_CONTENT_LEN],
                ],
                null
            );

            foreach (key; additionalSignedHeaders) {
                canonicalRequest.headers[key] = req.headers[key];
            }

            // Calculate the seed signature
            auto signableRequest = SignableRequest(date, time, region, service, canonicalRequest);
            auto key = signingKey(creds.accessKeySecret, date, region, service);
            auto binarySig = key.sign(cast(ubyte[]) signableRequest.signableStringForStream);
            auto credScope = date ~ "/" ~ region ~ "/" ~ service;
            const string authHeader = createSignatureHeader(creds.accessKeyID, credScope, canonicalRequest.headers, binarySig);
            req.headers[HDR_AUTH] = authHeader;

            // Write the data in chunks to the stream
            auto outputStream = createChunkedOutputStream(req.bodyWriter);
            outputStream.maxBufferSize = blockSize;

            string signature = binarySig.toHexString().toLower();
            outputStream.chunkExtensionCallback = (in ubyte[] data) @safe {
                logDebug("doUpload: chunkExtensionCallback data is %s bytes", data.length);
                auto chunk = SignableChunk(date, time, region, service, signature, hash(data));
                signature = key.sign(chunk.signableString.representation).toHexString().toLower();
                return "chunk-signature=" ~ signature;
            };
            logDebug("doUpload: write payload");
            payload.pipe(outputStream);
            logDebug("doUpload: finalize ... ");
            outputStream.finalize();
            logDebug("doUpload: finalized.");
        };

        auto respHandler = delegate(scope HTTPClientResponse resp) {
            etag = resp.headers.get("ETag");
            logDebug("do upload checking for error");
            if (resp.statusCode < 400) resp.dropBody();
            checkForError(resp);
        };

        if (m_config.connectionPooledUpload) {
            // the normal connection pooled request - but this seems to have a
            // bug where a 2nd request fails
            requestHTTP(url,reqHandler,respHandler,settings);
        }
        else {
            // manually create a connection and kill it
            HTTPClient cl = new HTTPClient();
            scope(exit) cl.disconnect();
            cl.connect(url.host,url.port,useTls,settings);
            cl.request(reqHandler,respHandler);
        }

        logDebug("do upload returning");
        return etag;
    }

    string readResponse(HTTPClientResponse response) {
        auto stringBuilder = appender!string;
        auto reader = response.bodyReader;

        auto buffer = ThreadMem.alloc!(ubyte[])(1024);
        scope(exit) ThreadMem.free(buffer);

        while(reader.leastSize > 0) {
            auto size = min(reader.leastSize,buffer.length);
            auto bytes = buffer[0..size];
            reader.read(bytes);
            stringBuilder.put(bytes);
        }
        return stringBuilder.data;
    }

    void checkForError(HTTPClientResponse response, 
                        string file = __FILE__,
                        size_t line = __LINE__,
                        Throwable next = null) {
        
        if (response.statusCode < 400) {
            logDebug("SUCCESSFUL. HTTP %d", response.statusCode);
            return; // No error
        }
        auto xml = parseXML(readResponse(response));
        auto err = readXmlError(xml);
        logError("Error HTTP %d %s: %s", response.statusCode, err.code, err.message);
        const bool retriable = response.statusCode / 100 == 5;
        throw makeException(err.code, retriable, err.message, file, line, next);
    }

    S3Exception makeException(string type, bool retriable, string message,
        string file = __FILE__, size_t line = __LINE__, Throwable next = null) {

        if (type == "UnrecognizedClientException" 
         || type == "InvalidSignatureException")
            throw new AuthorizationException(type, message, file, line, next);
        return new S3Exception(type, retriable, message, file, line, next);
    }
}

class S3Exception : Exception {
    immutable string type;
    immutable bool retriable;

    this(string type, bool retriable, string message, string file = __FILE__,
        size_t line = __LINE__, Throwable next = null) {
        
        super(type ~ ": " ~ message, file, line, next);
        this.type = type;
        this.retriable = retriable;
    }

    /**
      Returns the 'ThrottlingException' from 'com.amazon.coral.service#ThrottlingException'
     */
    @property string simpleType() {
        auto h = type.indexOf('#');
        if (h == -1) return type;
        return type[h+1..$];
    }
}

struct ExponentialBackoff {
    immutable uint maxRetries;
    uint tries = 0;
    uint maxSleepMs = 10;

    this(uint maxRetries) {
        this.maxRetries = maxRetries;
    }

    @property bool canRetry() {
        return tries < maxRetries;
    }

    @property bool finished() {
        return tries >= maxRetries + 1;
    }

    void inc() {
        tries++;
        maxSleepMs *= 2;
    }

    void sleep() {
        vibe.core.core.sleep(uniform!("[]")(1, maxSleepMs).msecs);
    }

    // defining opApply allows use in foreach
    int opApply(scope int delegate(uint) attempt) {
        int result = 0;
        for (; !finished; inc()) {
            try {
                result = attempt(maxRetries - tries);
                if (result)
                    return result;
            }
            catch (S3Exception e) {
                logWarn(typeid(e).name ~ " occurred at " ~ e.file ~ ":" ~ e.line.to!string ~ " : " ~ e.msg);
                // Retry if possible and retriable, otherwise give up.
                if (!canRetry || !e.retriable) throw e;
            }
            catch (Exception e) { //ssl errors from ssl.d
                logWarn(typeid(e).name ~ " occurred at " ~ e.file ~ ":" ~ e.line.to!string ~ " : " ~ e.msg);
                if (!canRetry) throw e;
            }
            sleep();
            logInfo("Retrying failed operation...");
        }
        return result;
    }
}

private static immutable NOSIGN_HEADERS = ["accept-encoding", "connection", "user-agent"];
private {
    enum HDR_AUTH = "Authorization";
    enum HDR_CONTENT_TYPE = "Content-Type";
    enum HDR_CONTENT_LENGTH = "Content-Length";
    enum HDR_EXPIRES = "Expires";
    enum HDR_STORAGE_CLASS = "x-amz-storage-class";
    enum HDR_HOST = "host";
    enum HDR_AMZ_DATE = "x-amz-date";
    enum HDR_AMZ_CONTENT_SHA256 = "x-amz-content-sha256";
    enum HDR_AMZ_SEC_TOKEN = "x-amz-security-token";
    enum HDR_AMZ_DEC_CONTENT_LEN = "x-amz-decoded-content-length";
}


private string currentTimeString() {
    // 2020-11-10T181449Z
    auto t = Clock.currTime(UTC());
    t.fracSecs = 0.seconds;
    return t.toISOString();
}

/**
* add a signed authorization header to the request
*/
private void signRequest(HTTPClientRequest req, string[string] queryParameters,
                         in ubyte[] requestBody, S3Credentials creds, 
                         string timeString, string region, string service) {
    const string dateString = dateFromISOString(timeString);
    const string credScope = dateString ~ "/" ~ region ~ "/" ~ service;

    SignableRequest signRequest;
    signRequest.dateString = dateString;
    signRequest.timeStringUTC = timeFromISOString(timeString);
    signRequest.region = region;
    signRequest.service = service;
    signRequest.canonicalRequest.method = req.method.to!string();

    auto pos = req.requestURL.indexOf("?");
    if (pos < 0) pos = req.requestURL.length;
    signRequest.canonicalRequest.uri = req.requestURL[0..pos];
    signRequest.canonicalRequest.queryParameters = queryParameters;

    auto reqHeaders = req.headers.toRepresentation;
    foreach (x; reqHeaders) {
        signRequest.canonicalRequest.headers[x.key] = x.value;
    }
    signRequest.canonicalRequest.payload = requestBody;

    ubyte[] signKey = signingKey(creds.accessKeySecret, dateString, region, service).dup;
    ubyte[] stringToSign = cast(ubyte[]) signableString(signRequest);
    auto signature = sign(signKey, stringToSign);

    const string authHeader = createSignatureHeader(creds.accessKeyID, credScope, signRequest.canonicalRequest.headers, signature);
    req.headers[HDR_AUTH] = authHeader;
}
// Wed, 21 Oct 2015 07:28:00 GMT
private string webFormatTime(SysTime st) {
    st.fracSecs = st.fracSecs.init;
    return webFormatTime(cast(DateTime) st);
}
// ditto
private string webFormatTime(DateTime dt) {
    auto timeStr = appender!string;
    timeStr.reserve(32);
    timeStr ~= capitalize(to!string(dt.dayOfWeek));
    timeStr ~= ", ";
    timeStr ~= format("%02d",dt.date.day);
    timeStr ~= " ";
    timeStr ~= capitalize(to!string(dt.date.month));
    timeStr ~= " ";
    timeStr ~= to!string(dt.date.year);
    timeStr ~= " ";
    timeStr ~= to!string(dt.timeOfDay);
    timeStr ~= " GMT";
   return timeStr.data;
}

unittest {
    assert(webFormatTime(SysTime(DateTime(2020, 10, 13, 12, 26, 34), UTC())) == "Tue, 13 Oct 2020 12:26:34 GMT");
}

class AuthorizationException : S3Exception {
    this(string type, string message, string file = __FILE__, size_t line = __LINE__, Throwable next = null) {
        super(type, false, message, file, line, next);
    }
}

/**
* Wrapper for the FileStream to be used as an RandomAccessStream
* Really confused as to why this doesn't already exist or what the alternative should be.
* Maybe that's what RandomAccessStreamProxy is for?
*/
class FileInStream : RandomAccessStream {
   private FileStream fs;
   
   this(string path) {
      fs = openFile(path,FileMode.read);
   }

   const(ubyte)[] peek() @safe {
      return fs.peek();
   }

   ulong read(scope ubyte[] dst, IOMode mode) @safe {
      return fs.read(dst,mode);
   }

   bool empty() @property {
      return fs.empty();
   }

   // deprecated
   bool dataAvailableForRead() @property {
      return fs.dataAvailableForRead();
   }

   // deprecated
   ulong leastSize() @property {
      return fs.leastSize();
   }

   void close() {
      fs.close();
   }

   ulong size() nothrow @property @safe const {
      return fs.size();
   }

   bool readable() const nothrow @property @safe {
       return fs.readable;
   }

   bool writable() const nothrow @property @safe {
       return fs.writable;
   }

   void seek(ulong offset) @safe {
       fs.seek(offset);
   }

   ulong tell() nothrow @safe {
       return fs.tell();
   }

   void finalize() @safe {
       fs.finalize();
   }

   void flush() @safe {
       fs.flush();
   }

   ulong write(const(ubyte[]) bytes, IOMode mode) @safe {
       return fs.write(bytes,mode);
   }
}