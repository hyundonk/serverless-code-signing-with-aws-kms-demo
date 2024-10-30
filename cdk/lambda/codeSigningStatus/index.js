const { DynamoDBClient, GetItemCommand } = require('@aws-sdk/client-dynamodb');
const { S3Client, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const dynamoClient = new DynamoDBClient();
const s3Client = new S3Client();

exports.handler = async (event) => {
    // Get objectKey from query parameters
    const objectKey = event.queryStringParameters?.objectKey;
    
    if (!objectKey) {
        return {
            statusCode: 400,
            headers: {
                'Access-Control-Allow-Origin': 'http://localhost:8000',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'GET,OPTIONS',
            },
            body: JSON.stringify({ error: 'objectKey parameter is required' })
        };
    }

    try {
        const params = {
            TableName: process.env.DYNAMODB_TABLE_NAME,
            Key: {
                objectKey: { S: objectKey }
            }
        };

        const response = await dynamoClient.send(new GetItemCommand(params));

        if (!response.Item) {
            return {
                statusCode: 404,
                headers: {
                    'Access-Control-Allow-Origin': 'http://localhost:8000',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Methods': 'GET,OPTIONS',
                },
                body: JSON.stringify({ error: 'Record not found' })
            };
        }

        const status = response.Item.status.S;
        const codeSignedUrl = response.Item.codeSignedUrl.S;

        // If status is completed and URL exists, generate presigned URL
        if (status === 'completed' && codeSignedUrl) {
            try {
                // Extract bucket and key from the S3 URL
                const s3Url = new URL(codeSignedUrl);
                const bucket = s3Url.hostname.split('.')[0];
                const key = decodeURIComponent(s3Url.pathname.substring(1)); // Remove leading slash

                console.log('s3Url', s3Url);
                console.log('Bucket:', bucket);
                console.log('Key:', key);

                // Create GetObject command
                const getObjectCommand = new GetObjectCommand({
                    Bucket: bucket,
                    Key: key
                });

                // Generate presigned URL valid for 10 min (600 seconds)
                const presignedUrl = await getSignedUrl(s3Client, getObjectCommand, { 
                    expiresIn: 600 
                });

                return {
                    statusCode: 200,
                    headers: {
                        'Access-Control-Allow-Origin': 'http://localhost:8000',
                        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                        'Access-Control-Allow-Methods': 'GET,OPTIONS',
                    },
                    body: JSON.stringify({
                        status,
                        codeSignedUrl: presignedUrl
                    })
                };
            } catch (presignError) {
                console.error('Error generating presigned URL:', presignError);
                return {
                    statusCode: 500,
                    headers: {
                        'Access-Control-Allow-Origin': 'http://localhost:8000',
                        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                        'Access-Control-Allow-Methods': 'GET,OPTIONS',
                    },
                    body: JSON.stringify({ error: 'Error generating presigned URL' })
                };
            }
        }

        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': 'http://localhost:8000',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'GET,OPTIONS',
            },
            body: JSON.stringify({
                status,
                codeSignedUrl
            })
        };

    } catch (error) {
        console.error('Error querying DynamoDB:', error);
        return {
            statusCode: 500,
            headers: {
                'Access-Control-Allow-Origin': 'http://localhost:8000',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'GET,OPTIONS',
            },
            body: JSON.stringify({ error: 'Internal server error' })
        };
    }
};

