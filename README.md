Overview
This CloudFormation template, named CFT-AmazonConnectOperationalReview.yml, is designed to deploy the AWS resources needed to run an automated operational review for an Amazon Connect instance.
The template provisions an IAM Role with specific permissions and an AWS Lambda function to execute the review logic, along with a CloudWatch Log Group for logging.


 

📝 Details

📥 Parameters (User Inputs)
These values must be provided by the user when creating the stack, allowing the template to be reusable in different AWS accounts or environments.
 

Parameter	Type	Description	Usage in Template
AmazonConnectInstanceARN	String	The ARN of the target Amazon Connect instance.	Passed as an environment variable to the Lambda function.
AmazonConnectCloudWatchLogGroup	String	The ARN of the Amazon Connect CloudWatch Log Group.	Passed as an environment variable to the Lambda function.
AmazonS3ForReports	String	The name of an existing S3 bucket where the operational review reports will be uploaded.	Used to define an S3 PutObject permission in the IAM role and passed as an environment variable to the Lambda function.

🏗️ Resources (Infrastructure Components)
This is the core section defining the three AWS resources provisioned by the template.
 

1. IAM Role (AmazonConnectOperationalReviewLambdaExecutionRole)
This role grants the Lambda function the necessary permissions to operate.
 

  Trust Policy: Allows the AWS Lambda service (lambda.amazonaws.com) to assume the role.
 

    Managed Policies: Attaches standard AWS policies for broad, read-only access and basic Lambda execution:
    AWSLambdaBasicExecutionRole (for writing logs to CloudWatch)
    AmazonConnectReadOnlyAccess
    AWSCloudTrail_ReadOnlyAccess
    ServiceQuotasReadOnlyAccess
    CloudWatchReadOnlyAccess

Inline Policies: Attaches two custom policies:
PinpointPhoneNumberValidateReadOnlyAccess: Allows the action mobiletargeting:PhoneNumberValidate, which is likely used by the review logic to validate phone number formats.
PutObjectToS3-Review: Grants write permission (s3:PutObject) to the specific S3 bucket provided in the AmazonS3ForReports parameter, allowing the Lambda function to upload the final review report.
 

2. Lambda Function (LambdaFunctionAmazonConnectOperationalReviewauto)
This is the code execution environment for the operational review logic.

FunctionName: Set to a fixed value: "amazonConnectOperationalReview-auto".

Role: References the ARN of the IAM Role defined above using the intrinsic function !GetAtt.

Code Source: The deployment package (amazonConnectOperationalReview-auto.zip) is fetched from a globally shared S3 location (operations-review-code-share), indicating this is a pre-built solution from AWS.

Environment Variables: The input parameters are passed directly to the Lambda function's environment:
CONNECT_INSTANCE_ARN
CONNECT_CW_LOG_GROUP
S3_REPORTING_BUCKET
 

3. CloudWatch Log Group (LambdaLogGroup)
LogGroupName: Matches the expected log group for the Lambda function: "/aws/lambda/amazonConnectOperationalReview-auto".
 

RetentionInDays: Sets log retention to 30 days.
 

➡️ Outputs
These are the values exported by the stack, allowing other services or users to easily reference the deployed Lambda function.
 

Output	Description	Value
LambdaFunctionArn	ARN of the Lambda function	"Automated Amazon Connect Operational Review" (Note: This value is likely a placeholder/descriptive string, not the actual ARN).
LambdaFunctionName	Name of the Lambda function	"amazonConnectOperationalReview-auto"
