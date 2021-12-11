import std.stdio;
import std.file;
import std.random;
import std.process : environment;
import std.exception : enforce;
import vibe.vibe;
import vibes3.s3;
import vibes3.s3model;

void main() {

	const string s3Bucket = environment.get("S3_BUCKET")
			.enforce("BUCKET environment variable is not defined.");
	const string s3Endpoint = environment.get("S3_ENDPOINT")
			.enforce("S3_ENDPOINT environment variable is not defined.");
	const string s3Region = environment.get("S3_REGION")
			.enforce("S3_REGION environment variable is not defined.");
	const string s3AccessKeyName = environment.get("S3_ACCESS_KEY_NAME")
			.enforce("S3_ACCESS_KEY_NAME environment variable is not defined.");
	const string s3AccessKeyId = environment.get("S3_ACCESS_KEY_ID")
			.enforce("S3_ACCESS_KEY_ID environment variable is not defined.");
	const string s3AccessKeySecret = environment.get("S3_ACCESS_KEY_SECRET")
			.enforce("S3_ACCESS_KEY_SECRET environment variable is not defined.");

	runTask(() nothrow {
		const string localFile = "testfile.txt";
		const string localFileCompare = localFile ~ ".downloaded";

		try {
			S3ClientConfig s3Config;
			s3Config.scheme = "https";
			s3Config.connectionPooledUpload = false;

			S3CredentialSource creds = new StaticS3CredSource(s3AccessKeyId,s3AccessKeySecret,s3AccessKeyName);
			ObjectStoreClient s3 = new S3Client(s3Endpoint,s3Region,creds,s3Config);

			// list buckets
			writeln(s3.listBuckets().serializeToJsonString());

			// list bucket contents
			writeln(s3.list(s3Bucket).serializeToJsonString());

			// upload test
			auto rnd = Random(unpredictableSeed);
			string content = format("%x", uniform(int.min, int.max, rnd));
			writeFileUTF8(NativePath(localFile),content);
			string remoteFile = format("%s/%s", s3Bucket, localFile);

			s3.upload(remoteFile, localFile);

			// download test
			s3.download(remoteFile, localFileCompare);

			// compare
			string dlContent = readFileUTF8(localFileCompare);
			writefln("Downloaded file matches? %s", content == dlContent);

			// cleanup
			// No S3 delete yet so the file has to be removed from the bucket manually
			if (exists(localFile)) remove(localFile);
			if (exists(localFileCompare)) remove(localFileCompare);

		} catch (Exception e) {
			logError(e.msg);
		}

		exitEventLoop();
	});
	
	runApplication();
}
