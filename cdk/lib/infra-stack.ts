import * as cdk from 'aws-cdk-lib';

// import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as aws_events from 'aws-cdk-lib/aws-events';
import * as aws_events_targets from 'aws-cdk-lib/aws-events-targets';
import * as aws_stepfunctions_tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3n from 'aws-cdk-lib/aws-s3-notifications';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

import { aws_apigateway as apigw } from "aws-cdk-lib";

import { RemovalPolicy } from 'aws-cdk-lib';
import { Duration } from 'aws-cdk-lib';



import { PolicyStatement, Effect } from 'aws-cdk-lib/aws-iam';

import * as aws_stepfunctions from 'aws-cdk-lib/aws-stepfunctions';

import { Construct } from 'constructs';

import { StateMachine, Chain } from 'aws-cdk-lib/aws-stepfunctions';


import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';


export class InfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    // Get KMS Key
    const main = kms.Key.fromLookup(this, 'KmsKey', {
	    aliasName: this.node.tryGetContext('KMSKeyAliasName'),
    });

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

    // Create ECS Cluster

    const cluster = new ecs.Cluster(this, `cluster`, { 
		vpc,
		clusterName: `${this.stackName}-demo-cluster`
    });

    const executionRole = new iam.Role(this, 'TaskExecutionRole', {
	    assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
    });

    executionRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonECSTaskExecutionRolePolicy'));

    // Add ECR pull permissions
    executionRole.addToPolicy(new iam.PolicyStatement({
	    effect: iam.Effect.ALLOW,
	    actions: [
		    "ecr:GetAuthorizationToken",
		    "ecr:BatchCheckLayerAvailability",
		    "ecr:GetDownloadUrlForLayer",
		    "ecr:BatchGetImage"
	    ],
	    resources: ['*']  // You might want to restrict this to specific ECR repository ARNs
    }));

    const definition = new ecs.FargateTaskDefinition(this, `TaskDefinition`, {
	    memoryLimitMiB: 2048,
	    cpu: 1024,
	    executionRole: executionRole,
	    runtimePlatform: {
		    operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
	    },
    });

    //definition.executionRole

    const container = definition.addContainer('codesigning', {
	    image: ecs.ContainerImage.fromRegistry(`${this.account}.dkr.ecr.${this.region}.amazonaws.com/signer-demo:latest`),
	    memoryLimitMiB: 1024,  // Adjust as needed
	    cpu: 512,  // Adjust as needed
	    logging: new ecs.AwsLogDriver({
		    streamPrefix: 'signer-demo'
	    }),
    });

    const bucketUploads = new s3.Bucket(this, "uploads", {
	bucketName: this.node.tryGetContext('UploadsBucketName'),
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
	bucketName: this.node.tryGetContext('ResultsBucketName'),
        versioned: true,
        eventBridgeEnabled: true,
        enforceSSL: true,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    });

    // Grant access to S3 Bucket for uploads: Read & Delete
    bucketUploads.grantRead(definition.taskRole);
    bucketUploads.grantDelete(definition.taskRole);

    // Grant access to S3 Bucket for results: Write
    bucketResults.grantWrite(definition.taskRole);

    // Create DynamoDB table
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

    // Create a Lambda function for completing multipart uploads
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

    definition.taskRole.addToPrincipalPolicy(
	    new PolicyStatement({
		    effect: Effect.ALLOW,
		    actions: ["kms:DescribeKey", "kms:Sign"],
		    resources: [main.keyArn],
	    })
    );

    definition.taskRole.addToPrincipalPolicy(
	    new PolicyStatement({
		    effect: Effect.ALLOW,
		    actions: ["kms:ListKeys"],
		    resources: ["*"],
	    })
    );

    // allow taskRole to update-item on the dynamodb table
    definition.taskRole.addToPrincipalPolicy(
	    new PolicyStatement({
		    effect: Effect.ALLOW,
		    actions: ["dynamodb:UpdateItem"],
		    resources: [codeSigningStatusTable.tableArn],
	    })
    );
    // Create a new EcsRunTask, which is a Step Function task that runs an Amazon ECS task.
    const runTask = new aws_stepfunctions_tasks.EcsRunTask(this, `RunTask`, {
	    cluster,
	    taskDefinition: definition,
	    taskTimeout: aws_stepfunctions.Timeout.duration(Duration.minutes(60)),
	    launchTarget: new aws_stepfunctions_tasks.EcsFargateLaunchTarget({
		    platformVersion: ecs.FargatePlatformVersion.LATEST,
	    }),
	    assignPublicIp: false,
	    securityGroups: [ecsSecurityGroup],
	    subnets: vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }),

	    // tells Step Functions to wait for the ECS task to complete before moving to the next state in the workflow.
	    integrationPattern: aws_stepfunctions.IntegrationPattern.RUN_JOB,
	    resultPath: "$.RunTask",
	    containerOverrides: [
		    {
			    containerDefinition: definition.defaultContainer!,
			    environment: [
				    {
					    name: "KMS_KEY_ID",
					    value: main.keyId,
				    },
				    {
					    name: "FILE",
					    value: aws_stepfunctions.JsonPath.stringAt("$.detail.object.key"),
				    },
				    {
					    name: "BUCKET_UPLOADS",
					    value: bucketUploads.bucketName,
				    },
				    {
					    name: "BUCKET_RESULTS",
					    value: bucketResults.bucketName,
				    },
				    {
					    name: "REGION",
					    value: this.region,
				    },
				    {
					    name: "AWS_REGION",
					    value: this.region,
				    },
				    { // Dynamodb table name
					    name: "DYNAMODB_TABLE_NAME",
					    value: codeSigningStatusTable.tableName,
				    }
			    ],
		    },
	    ],
    });

    const stateMachine = new aws_stepfunctions.StateMachine(this, `machine`, {
	    definition: aws_stepfunctions.Chain.start(runTask),
	    timeout: Duration.minutes(5),
	    stateMachineName: "code-signing",
	    stateMachineType: aws_stepfunctions.StateMachineType.STANDARD,
	    tracingEnabled: true,
    });

    // Create IAM role for EventBridge integration

    const eventRole = new iam.Role(this, "role", {
	    assumedBy: new iam.ServicePrincipal("events.amazonaws.com"),
    });

    // Grant access to execute State Machine for IAM role
    stateMachine.grantStartExecution(eventRole);

	// Create event rule to trigger State Machine execution
/*
	const eventPattern = {
		source: ["aws.s3"],
		detailType: ["Object Created"],
		detail: {
		  bucket: {
			name: [bucketUploads.bucketName],
		  },
		},
	  };
	  new aws_events.Rule(this, "rule", {
		eventPattern: eventPattern,
		targets: [
		  new aws_events_targets.SfnStateMachine(stateMachine, {
			input: aws_events.RuleTargetInput.fromObject({
			  detail: aws_events.EventField.fromPath("$.detail"),
			}),
			role: eventRole,
		  }),
		],
	  });
*/
    // Trigger State Machine execution for S3 event
    // create an EventBridge rule to trigger a Step Function state machine when an object is uploaded to an S3 bucket
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
		    new aws_events_targets.SfnStateMachine(stateMachine, {
			    input: aws_events.RuleTargetInput.fromObject({
				    detail: aws_events.EventField.fromPath("$.detail"),
			    }),
			    role: eventRole,
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
