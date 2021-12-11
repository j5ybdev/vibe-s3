module vibes3.s3xml;
import vibe.d;
import std.array : appender;
import vibes3.s3model;
import dxml.parser;
import dxml.util;
import std.datetime.systime;

BucketListing readXmlListBucketResults(ref EntityRange!(Config.init, string) xml) {
   // build the BucketListing data
   BucketListing listing;
   enforce(xml.front.name == "ListAllMyBucketsResult");
   xml.popFront();

   for (; !xml.empty; xml.popFront()) {
      if (xml.front.type == EntityType.elementStart) {
         switch (xml.front.name) {
            case "Owner":
               listing.owner = readXmlOwner(xml);
               break;
            case "Buckets":
               listing.buckets = readXmlBuckets(xml);
               break;
            default:
               logWarn("Unexpected ListBucketResult XML element %s", xml.front.name);
         }
      }
   }
   return listing;
}

unittest {
   import std.file : readText;
   auto xml = parseXML(readText("testdata/listallbucketresult.xml"));
   BucketListing bl = readXmlListBucketResults(xml);
   assert(bl.owner.id == "1234567");
   assert(bl.owner.displayName == "1234567");
   assert(bl.buckets[0].name == "mybucket");
}

BucketItemListing readXmlBucketItemListing(ref EntityRange!(Config.init, string) xml) {
   BucketItemListing listing;
   enforce(xml.front.name == "ListBucketResult");
   xml.popFront();
   auto items = appender!(BucketItem[]);

   for (; !xml.empty; xml.popFront()) {
      if (xml.front.type == EntityType.elementStart) {
         switch (xml.front.name) {
            case "Name":
               listing.bucketName = readXmlValue(xml);
               break;
            case "Prefix":
               listing.prefix = readXmlValue(xml);
               break;
            case "MaxKeys":
               listing.maxKeys = to!int(readXmlValue(xml));
               break;
            case "IsTruncated":
               listing.truncated = to!bool(readXmlValue(xml));
               break;
            case "Marker":
               listing.marker = readXmlValue(xml);
               break;
            case "Contents":
               items.put(readXmlBucketItem(xml));
               break;
            default:
               logWarn("Unexpected ListBucketResult XML element %s", xml.front.name);
         }
      }
   }
   listing.items = items.data;

   return listing;
}

unittest {
   import std.file : readText;
   auto xml = parseXML(readText("testdata/listbucketresult.xml"));
   BucketItemListing bil = readXmlBucketItemListing(xml);
   assert(bil.items[0].key == "f/");
   assert(bil.items[0].etag == "\"d41d8cd98f00b204e9800998ecf8427e\"");
   assert(bil.items[0].size == 0);
   assert(bil.items[0].storageClass == StorageClass.STANDARD);
   assert(bil.items[0].type == "Normal");
   assert(bil.items.length == 2);
   assert(bil.maxKeys == 1000);
   assert(bil.truncated == false);
   assert(bil.bucketName == "mybucket");
}

string readXmlInitMultiUploadResult(ref EntityRange!(Config.init, string) xml) {
   enforce(xml.front.name == "InitiateMultipartUploadResult");
   xml.popFront();

   for (; !xml.empty; xml.popFront()) {
      if (xml.front.type == EntityType.elementStart) {
         switch (xml.front.name) {
            case "UploadId":
               return readXmlValue(xml);
            default:
               break;
         }
      }
   }

   return null;
}

unittest {
   import std.file : readText;
   auto xml = parseXML(readText("testdata/initiatemultipartuploadresult.xml"));
   assert(readXmlInitMultiUploadResult(xml) == "32");
}

ErrorDetails readXmlError(ref EntityRange!(Config.init, string) xml) {
   enforce(xml.front.name == "Error");
   xml.popFront();

   ErrorDetails err;
   for (; !xml.empty; xml.popFront()) {
      if (xml.front.type == EntityType.elementStart) {
         switch (xml.front.name) {
            case "Code":
               err.code = readXmlValue(xml);
               break;
            case "Message":
               err.message = readXmlValue(xml);
               break;
            default:
               break;
         }
      }
   }
   return err;
}

unittest {
   import std.file : readText;
   auto xml = parseXML(readText("testdata/error.xml"));
   auto err = readXmlError(xml);
   assert(err.code == "AccessDenied");
   assert(err.message == "No Access");
}

private BucketItem readXmlBucketItem(ref EntityRange!(Config.init, string) xml) {
   BucketItem item;
   enforce(xml.front.name == "Contents");
   xml.popFront();

   for (; !xml.empty; xml.popFront()) {
      if (xml.front.type == EntityType.elementEnd
               && xml.front.name == "Contents") {
         return item;
      }
      if (xml.front.type == EntityType.elementStart) {
         switch (xml.front.name) {
            case "Key":
               item.key = readXmlValue(xml);
               break;
            case "ETag":
               item.etag = readXmlValue(xml);
               break;
            case "Size":
               item.size = to!ulong(readXmlValue(xml));
               break;
            case "LastModified":
               item.lastModified = SysTime.fromISOExtString(readXmlValue(xml));
               break;
            case "StorageClass":
               item.storageClass = readXmlValue(xml).toStorageClass();
               break;
            case "Owner":
               item.owner = readXmlOwner(xml);
               break;
            case "Type":
               item.type = readXmlValue(xml);
               break;
            default:
               logWarn("Unexpected Owner XML element %s", xml.front.name);
         }
      }
   }
   return item;
}

private Owner readXmlOwner(ref EntityRange!(Config.init, string) xml) {
   Owner owner;
   enforce(xml.front.name == "Owner");
   xml.popFront();

   for (; !xml.empty; xml.popFront()) {
      if (xml.front.type == EntityType.elementEnd
               && xml.front.name == "Owner") {
         return owner;
      }
      if (xml.front.type == EntityType.elementStart) {
         switch (xml.front.name) {
            case "ID":
               owner.id = readXmlValue(xml);
               break;
            case "DisplayName":
               owner.displayName = readXmlValue(xml);
               break;
            default:
               logWarn("Unexpected Owner XML element %s", xml.front.name);
         }
      }
   }
   return owner;
}

private Bucket[] readXmlBuckets(ref EntityRange!(Config.init, string) xml) {
   auto buckets = appender!(Bucket[]);
   enforce(xml.front.name == "Buckets");
   xml.popFront();

   for (; !xml.empty; xml.popFront()) {
      if (xml.front.type == EntityType.elementEnd
               && xml.front.name == "Buckets") {
         return buckets.data;
      }
      if (xml.front.type == EntityType.elementStart) {
         switch (xml.front.name) {
            case "Bucket":
               buckets.put(readXmlBucket(xml));
               break;
            default:
               logWarn("Unexpected Buckets XML element %s", xml.front.name);
         }
      }
      
   } 

   return buckets.data;
}

private Bucket readXmlBucket(ref EntityRange!(Config.init, string) xml) {
   Bucket bucket;
   enforce(xml.front.name == "Bucket");
   xml.popFront();

   for (; !xml.empty; xml.popFront()) {
      if (xml.front.type == EntityType.elementEnd
               && xml.front.name == "Bucket") {
            return bucket;
      }
      if (xml.front.type == EntityType.elementStart) {
         switch (xml.front.name) {
            case "Name":
               bucket.name = readXmlValue(xml);
               break;
            case "CreationDate":
               bucket.creationDate = SysTime.fromISOExtString(readXmlValue(xml));
               break;
            default:
               logWarn("Unexpected Bucket XML element %s", xml.front.name);
         }
      }
      
   }
   return bucket;
}

private string readXmlValue(ref EntityRange!(Config.init, string) xml) {
   xml.popFront();
   if (xml.front.type == EntityType.text) {
      return decodeXML(xml.front.text);
   }
   return null;
}

StorageClass toStorageClass(string sc) {
   switch (sc) {
      case "STANDARD":
         return StorageClass.STANDARD;
      case "GLACIER":
         return StorageClass.GLACIER;
      case "REDUCED_REDUNDANCY":
         return StorageClass.REDUCED_REDUNDANCY;
      default:
         logWarn("Unknown storage class %s", sc);
         return StorageClass.STANDARD;
   }
}