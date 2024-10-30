const { S3Client, CompleteMultipartUploadCommand } = require("@aws-sdk/client-s3");
const { DynamoDBClient, PutItemCommand } = require("@aws-sdk/client-dynamodb"); 

const s3Client = new S3Client({ region: process.env.AWS_REGION, });
const dynamoClient = new DynamoDBClient({ region: process.env.AWS_REGION }); 

const tableName = process.env.DYNAMODB_TABLE_NAME;

// Function to update DynamoDB
async function updateCodeSigningStatus(objectKey) { 
    const params = {
        TableName: tableName,
        Item: {
            objectKey: { S: objectKey },
            status: { S: 'initiated' },
            codeSignedUrl: { S: '' },
        } 
    };

    try {
        await dynamoClient.send(new PutItemCommand(params));
    } catch (error) {
        console.error("Error updating DynamoDB:", error);
        throw error;
    }
}    

exports.handler = async (event) => {
    const { uploadId, key, parts } = JSON.parse(event.body);
    const bucketName = process.env.BUCKET_NAME;

    console.log(`UploadId: ${uploadId}`);

    try {
        const command = new CompleteMultipartUploadCommand({
            Bucket: bucketName,
            Key: key,
            UploadId: uploadId,
            MultipartUpload: { Parts: parts }
        });
        const response = await s3Client.send(command);
        
        // Update DynamoDB with initial status
        await updateCodeSigningStatus(key);    

        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': 'http://localhost:8000',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'POST,OPTIONS',
            },
            body: JSON.stringify({
                message: 'Upload completed and processed file is ready',
                originalFileLocation: response.Location,
                //processedFileUrl: codeSignedFileInfo.processedFileUrl,
                //processedTimestamp: codeSignedFileInfo.timestamp
            })
        };
    } catch (error) {
        console.error("Error completing multipart upload:", error);
        return {
            statusCode: error.message.includes("Timeout") ? 504 : 500,
            headers: {
                'Access-Control-Allow-Origin': 'http://localhost:8000',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'POST,OPTIONS',
            },
            body: JSON.stringify({ 
                error: error.message.includes("Timeout") 
                    ? "Processed file not ready yet. Please try again later." 
                    : "Failed to complete multipart upload or retrieve processed file information"
            })
        };
    }
};
