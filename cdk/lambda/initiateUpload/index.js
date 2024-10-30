
const { S3Client, CreateMultipartUploadCommand, UploadPartCommand, CompleteMultipartUploadCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

exports.handler = async (event) => {
  const s3Client = new S3Client({
    region: process.env.AWS_REGION,
  });

  // check if fileName exists in the query string
  if (!event.queryStringParameters || !event.queryStringParameters.fileName) {
    return {
      statusCode: 400,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': 'http://localhost:8000', // Be more specific in production
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key',
        'Access-Control-Allow-Methods': 'GET,OPTIONS'
      },
      body: JSON.stringify({ error: "fileName is required in query parameters" }),
    };
  }

  const fileName = event.queryStringParameters.fileName;
  const bucketName = process.env.BUCKET_NAME;
  const partCount = parseInt(event.queryStringParameters.partCount || "1", 10);

  try {
    // Generate pre-signed URL for initiating the multi-part upload
    const initiateCommand = new CreateMultipartUploadCommand({
      Bucket: bucketName,
      Key: fileName, 
    });
    
    const { UploadId } = await s3Client.send(initiateCommand);
    // check resposne
    console.log(`UploadId: ${UploadId}`);
    
    // Generate pre-signed URLs for uploading parts
    const partUrls = await Promise.all(
      Array.from({ length: partCount }, (_, i) => {
        const uploadPartCommand = new UploadPartCommand({
          Bucket: bucketName,
          Key: fileName,
          UploadId: UploadId, 
          PartNumber: i + 1,
        });
        return getSignedUrl(s3Client, uploadPartCommand, { expiresIn: 300 });
      })
    );
  
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:8000', // Be more specific in production
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key',
        'Access-Control-Allow-Methods': 'GET,OPTIONS'
      },
      body: JSON.stringify({
        uploadId: UploadId,
        partUrls: partUrls,
      }),
    };
  } catch (err) {
    console.error(err);
    return {
      statusCode: 500,
      headers: {
        'Access-Control-Allow-Origin': 'http://localhost:8000', // Be more specific in production
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key',
        'Access-Control-Allow-Methods': 'GET,OPTIONS'
      },
      body: JSON.stringify({ error: "Failed to generate pre-signed URLs" }),
    };
  }
};

