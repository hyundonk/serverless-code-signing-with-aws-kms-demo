import * as cdk from 'aws-cdk-lib';

import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as aws_events from 'aws-cdk-lib/aws-events';
import * as aws_events_targets from 'aws-cdk-lib/aws-events-targets';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { aws_apigateway as apigw } from "aws-cdk-lib";
import { Duration } from 'aws-cdk-lib';
import { Construct } from 'constructs';


export class InfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

	// Get KMS Key
	const main = kms.Key.fromLookup(this, 'KmsKey', {
		aliasName: 'alias/code-signing-ecc-20241023',
	});

    /*
	const main = new kms.Key(this, "main", {
		keySpec: kms.KeySpec.RSA_4096,
		keyUsage: kms.KeyUsage.SIGN_VERIFY,
		alias: "code-signing-demo",
		removalPolicy: RemovalPolicy.RETAIN,
	  });
*/

    // The code that defines your stack goes here
    const vpc = new ec2.Vpc(this, `demo-202410`, {
		vpcName: `${this.stackName}-demo-vpc`,
	    natGateways: 1,
	    maxAzs: 1,
    });

    // Create interface endpoint in VPC to access KMS service
	const ecsSecurityGroup = new ec2.SecurityGroup(this, 'ECSSecurityGroup', {
		vpc,
		allowAllOutbound: true,
		description: 'Security group for ECS tasks',
	});

    const endpoint = vpc.addInterfaceEndpoint("endpoint-kms", {
	    service: ec2.InterfaceVpcEndpointAwsService.KMS_FIPS,
	    privateDnsEnabled: true,
		securityGroups: [ecsSecurityGroup],
    });

    const bucketUploads = new s3.Bucket(this, "uploads", {
		bucketName: `${this.stackName}-demo-uploads-202410`,
	    versioned: true,
		encryption: s3.BucketEncryption.S3_MANAGED,
        removalPolicy: cdk.RemovalPolicy.DESTROY, // Use with caution in production
	    eventBridgeEnabled: true,
	    enforceSSL: true,
	    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
		cors: [
			{
			  allowedHeaders: ['*'],
			  allowedMethods: [s3.HttpMethods.GET, s3.HttpMethods.POST, s3.HttpMethods.PUT],
			  allowedOrigins: ['http://localhost:8000'],
			  exposedHeaders: ['ETag'],
			},
		],
    });

    const bucketResults = new s3.Bucket(this, "results", {
		bucketName: `${this.stackName}-demo-results-202410`,
	    versioned: true,
	    eventBridgeEnabled: true,
	    enforceSSL: true,
	    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    });

	// ADDED: Create DynamoDB table
	const codeSigningStatusTable = new dynamodb.Table(this, 'CodeSigningStatusTable', {
		tableName: 'codeSigningStatusTable',  
		partitionKey: {   
			name: 'objectKey', 
			type: dynamodb.AttributeType.STRING  
		},
		billingMode: dynamodb.BillingMode.PAY_PER_REQUEST, 
		removalPolicy: cdk.RemovalPolicy.DESTROY  // For development - adjust for prod 
	});                                                                                                

    // Create a Lambda function
    const initiateUpload = new lambda.Function(this, 'InitiateUpload', {
    	runtime: lambda.Runtime.NODEJS_18_X,
        handler: 'index.handler',
        code: lambda.Code.fromAsset('lambda/initiateUpload'),
        environment: {
          BUCKET_NAME: bucketUploads.bucketName,
        },
    });

	// NEW: Create a Lambda function for completing multipart uploads
	const completeUpload = new lambda.Function(this, 'CompleteUpload', {
		runtime: lambda.Runtime.NODEJS_18_X,
		handler: 'index.handler',
		code: lambda.Code.fromAsset('lambda/completeUpload'),
		environment: {
			DYNAMODB_TABLE_NAME: codeSigningStatusTable.tableName,
			BUCKET_NAME: bucketUploads.bucketName,
		},
		timeout: Duration.seconds(28),
	});

	const codeSigningStatus = new lambda.Function(this, 'CodeSigningStatus', {
		runtime: lambda.Runtime.NODEJS_18_X,
		handler: 'index.handler',
		code: lambda.Code.fromAsset('lambda/codeSigningStatus'),
		environment: {
		  BUCKET_NAME: bucketUploads.bucketName,
		  DYNAMODB_TABLE_NAME: codeSigningStatusTable.tableName,
		},
	});           

	// Grant DynamoDB read permissions to the Lambda
	codeSigningStatusTable.grantReadData(codeSigningStatus); 

	// grant dynamodb:PutItem to completeUpload
	completeUpload.addToRolePolicy(new iam.PolicyStatement({  
		actions: ['dynamodb:PutItem'],  
		resources: [codeSigningStatusTable.tableArn] 
	}));    
	  
    // Grant the Lambda function permission to generate pre-signed URLs for the S3 bucket
    bucketUploads.grantReadWrite(initiateUpload);
    bucketUploads.grantReadWrite(completeUpload);

	// Grant codeSigningStatus lambda function permission to generate pre-signed URL for the S3 object in bucketResults bucket
	bucketResults.grantRead(codeSigningStatus);
	
	// Create an API Gateway
	const api = new apigw.RestApi(this, 'UploadDemoApi', {
		restApiName: 'Upload Demo API',
		description: 'API for generating pre-signed URLs and completing multipart uploads for S3 uploads',
		defaultCorsPreflightOptions: {
			allowOrigins: ['http://localhost:8000'],
			allowMethods: ['GET', 'POST', 'OPTIONS'],
			allowHeaders: ['Content-Type', 'X-Amz-Date', 'Authorization', 'X-Api-Key', 'X-Amz-Security-Token'],
			allowCredentials: true,
		},
	});

	// Create an API Gateway resource
	const generateResource = api.root.addResource('initiate-upload');

	// Create an API Gateway method with integration response
	const generateIntegration = new apigw.LambdaIntegration(initiateUpload, {
		proxy: true,
		integrationResponses: [
			{
				statusCode: '200',
				responseParameters: {
				  'method.response.header.Access-Control-Allow-Origin': "'http://localhost:8000'",
				  'method.response.header.Access-Control-Allow-Headers': "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'",
				  'method.response.header.Access-Control-Allow-Methods': "'GET,OPTIONS'"
				},
			},
		],
	});

	generateResource.addMethod('GET', generateIntegration, {
        requestParameters: {
          'method.request.querystring.fileName': true,
        },      
        methodResponses: [
          {
            statusCode: '200',
            responseParameters: {
              'method.response.header.Access-Control-Allow-Origin': true,
              'method.response.header.Access-Control-Allow-Headers': true,
              'method.response.header.Access-Control-Allow-Methods': true,
            },
          },
        ],
    });

    // Create an API Gateway resource for completing multipart uploads
    const completeResource = api.root.addResource('complete-upload');

    // Create an API Gateway method for completing multipart uploads using the new Lambda function
    const completeIntegration = new apigw.LambdaIntegration(completeUpload, {
        proxy: true,
        integrationResponses: [
          {
            statusCode: '200',
            responseParameters: {
              'method.response.header.Access-Control-Allow-Origin': "'http://localhost:8000'",
              'method.response.header.Access-Control-Allow-Headers': "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'",
              'method.response.header.Access-Control-Allow-Methods': "'POST,OPTIONS'"
            },
          },
        ],
    });

	completeResource.addMethod('POST', completeIntegration, {
        methodResponses: [
          {
            statusCode: '200',
            responseParameters: {
              'method.response.header.Access-Control-Allow-Origin': true,
              'method.response.header.Access-Control-Allow-Headers': true,
              'method.response.header.Access-Control-Allow-Methods': true,
            },
          },
        ],
    });


	// Create an API Gateway resource
	const statusResource = api.root.addResource('code-signing-status');

	// Create an API Gateway method with integration response
	const statusIntegration = new apigw.LambdaIntegration(codeSigningStatus, {
		proxy: true,
		integrationResponses: [
			{
				statusCode: '200',
				responseParameters: {
				  'method.response.header.Access-Control-Allow-Origin': "'http://localhost:8000'",
				  'method.response.header.Access-Control-Allow-Headers': "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'",
				  'method.response.header.Access-Control-Allow-Methods': "'GET,OPTIONS'"
				},
			},
		],
	});

	statusResource.addMethod('GET', statusIntegration, {
        requestParameters: {
          'method.request.querystring.fileName': true,
        },      
        methodResponses: [
          {
            statusCode: '200',
            responseParameters: {
              'method.response.header.Access-Control-Allow-Origin': true,
              'method.response.header.Access-Control-Allow-Headers': true,
              'method.response.header.Access-Control-Allow-Methods': true,
            },
          },
        ],
    });



	// Create a reference to the existing ECR repository
	const signerRepo = ecr.Repository.fromRepositoryName(
    	this, 
    	'SignerRepository',
		'signer-demo'  // just the repository name, without the URI
	);

	// Create the Lambda function using the container image
	const signerLambda = new lambda.DockerImageFunction(this, 'SignerLambdaFunction', {
		code: lambda.DockerImageCode.fromEcr(
			signerRepo,{ 
				tagOrDigest: 'latest',
			 },
		),
		vpc: vpc,
		vpcSubnets: {
			subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS 
		},
		timeout: cdk.Duration.minutes(5),
		memorySize: 512,
		ephemeralStorageSize: cdk.Size.mebibytes(1024),
		environment: {
			KMS_KEY_ID: main.keyId,
			BUCKET_UPLOADS: bucketUploads.bucketName,
			BUCKET_RESULTS: bucketResults.bucketName,
			REGION: this.region,
			DYNAMODB_TABLE_NAME: codeSigningStatusTable.tableName,
		},
	});
				
	// Grant the Lambda function read/write permissions to the S3 bucket
	bucketUploads.grantReadWrite(signerLambda);

    // Grant access to S3 Bucket for results: Write
    bucketResults.grantWrite(signerLambda);


	// Grant DynamoDB write permissions to the signerLambda
	codeSigningStatusTable.grantWriteData(signerLambda);

	// Grant kms:DescribeKey permission to the singerLambda
	signerLambda.addToRolePolicy(new iam.PolicyStatement({
		actions: ['kms:DescribeKey', 'kms:Sign', 'kms:ListKeys'],
		resources: [main.keyArn],
	}))

	// Use EventBridge instead of S3 Event Notification 
	/*
	// Add S3 event notification to trigger the Lambda function
	bucketUploads.addEventNotification(
		s3.EventType.OBJECT_CREATED,
		new s3n.LambdaDestination(signerLambda)
	);
	*/

	// Create IAM role for EventBridge integration
	const eventRole = new iam.Role(this, "role", {
		assumedBy: new iam.ServicePrincipal("events.amazonaws.com"),
	});

	// Grant access to invoke signerLambda for EventBridge
	signerLambda.grantInvoke(eventRole);


	// create an EventBridge rule to trigger 'signerLambda' lambda when an object is uploaded to an S3 bucket
	new aws_events.Rule(this, "rule", {
		eventPattern: {
		source: ["aws.s3"],
		detailType: ["Object Created"],
		detail: {
			bucket: {
			name: [bucketUploads.bucketName],
			},
		},
		},
		targets: [
		new aws_events_targets.LambdaFunction(signerLambda, {
			event: aws_events.RuleTargetInput.fromObject({
			detail: aws_events.EventField.fromPath("$.detail"),
			}),
		}),
		],
  	});

	new cdk.CfnOutput(this, 'BucketUploadsName', {
		value: bucketUploads.bucketName,
		description: 'The name of the S3 bucket for uploads',
		exportName: 'BucketUploadsName', // optional: allows cross-stack references
	});

	new cdk.CfnOutput(this, 'bucketResults', {
		value: bucketResults.bucketName,
		description: 'The name of the S3 bucket for results',
		exportName: 'bucketResults', // optional: allows cross-stack references
	});

	// Output the API Gateway URL
	new cdk.CfnOutput(this, 'ApiGatewayUrl', {
		value: api.url,
		description: 'The URL of API Gateway',
		exportName: 'ApiGatewayUrl', // optional: allows cross-stack references
	});

  }
}
