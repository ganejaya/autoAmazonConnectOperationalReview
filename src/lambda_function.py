import boto3
import json
import logging
import os
from botocore.exceptions import ClientError
from html import escape
from datetime import datetime
from datetime import datetime, timedelta
from collections import defaultdict
import statistics
import time
from collections import Counter
import helper_function as hf
from typing import Dict, List, Optional, Any, Tuple

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Format the datetime object into a string including the timezone name
currentDateAndTime = datetime.now()
datetime_string = currentDateAndTime.strftime("%Y-%m-%d %H:%M:%S %Z%z")

# Intialize (log group, AWS region, days back)
log_group = f'/aws/connect/ganesh-test-us-east-1'

# Initialize Connect client
connect_client = boto3.client('connect')

# Initialize S3 client
s3_client = boto3.client('s3')  

# Initialize CloudWatch client
cloudwatch_client = boto3.client('cloudwatch')

# Initialize CloudWatch logs client
logs_client = boto3.client('logs')

# Initialize CloudTrail client
cloudtrail_client = boto3.client('cloudtrail')    

# Initialize CloudWatch logs client
pinpoint_client = boto3.client('pinpoint')

# Parse instance_id and aws_region from Amazon Connect instance ARN    
def parse_connect_instance_arn(instance_arn):
    """
        ARN format: arn:aws:connect:region:account-id:instance/instance-id
    
    Args:
        instance_arn (str): Amazon Connect instance ARN
    
    Returns:
        dict: Contains instance_id, aws_region, account_id, and other components
    """
    
    if not instance_arn or not isinstance(instance_arn, str):
        raise ValueError("Invalid ARN provided in envonment variable - CONNECT_INSTANCE_ARN")
    
    # Split ARN by colons
    arn_parts = instance_arn.split(':')
    
    if len(arn_parts) < 6 or arn_parts[0] != 'arn' or arn_parts[2] != 'connect':
        raise ValueError(f"Invalid Connect instance ARN format: {instance_arn}")
    
    # Extract components
    aws_region = arn_parts[3]
    account_id = arn_parts[4]
    resource_part = arn_parts[5]  # instance/instance-id
    
    # Extract instance ID from resource part
    if not resource_part.startswith('instance/'):
        raise ValueError(f"Invalid resource type in ARN: {resource_part}")
    
    instance_id = resource_part.split('/', 1)[1]
    
    return {
        'instance_id': instance_id,
        'aws_region': aws_region,
        'account_id': account_id,
        'service': arn_parts[2],
        'partition': arn_parts[1],
        'resource_type': 'instance',
        'full_arn': instance_arn
    }


#Get various Service Quota elements for Amazon Connect
def get_connect_service_quotas():
    """Retrieve all Amazon Connect service quotas"""
    try:
        service_quotas = boto3.client('service-quotas')
        quotas = []
        
        # Use paginator to get all quotas
        paginator = service_quotas.get_paginator('list_service_quotas')
        
        for page in paginator.paginate(ServiceCode='connect'):
            quotas.extend(page['Quotas'])
        
        return quotas
    
    except ClientError as e:
        logger.error(f"Error retrieving service quotas: {e}")
        return []

#Upload to S3 bucket
def upload_string_to_s3(string_data, bucket_name, object_key, content_type):
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body=string_data,
            ContentType=content_type
        )
        print(f"Report uploaded successfully to https://{bucket_name}.s3.amazonaws.com/{object_key}. ETag: {response['ETag']}")
        return True
    except ClientError as e:
        print(f"Error uploading to S3: {e}")
        return False

#Get Connect Instance Details
def describe_connect_to_html(instance_id):
    try:
        # Describe the instance
        response = connect_client.describe_instance(InstanceId=instance_id)
        instance = response['Instance']
        
        # Generate HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Amazon Connect Instance - Operations Review</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .header {{ color: #232F3E; }}
                .section {{ margin: 20px 0; }}
            </style>
        </head>
        <body>
            <h1 class="header">Amazon Connect Instance - Operations Review</h1>
            <div class="section">
                <p><em>Generated on: {escape(datetime_string)} UTC</em></p>
            </div>
            <div class="section">
                <h2>Amazon Connect Instance Information</h2>
                <h3>Describe Connect</h3>
                <table>
                    <tr><th>Instance ID</th><td>{escape(instance.get('Id', 'N/A'))}</td></tr>
                    <tr><th>Instance ARN</th><td>{escape(instance.get('Arn', 'N/A'))}</td></tr>
                    <tr><th>Instance Alias</th><td>{escape(instance.get('InstanceAlias', 'N/A'))}</td></tr>
                    <tr><th>Identity Management Type</th><td>{escape(instance.get('IdentityManagementType', 'N/A'))}</td></tr>
                    <tr><th>Instance Status</th><td>{escape(instance.get('InstanceStatus', 'N/A'))}</td></tr>
                    <tr><th>Service Role</th><td>{escape(instance.get('ServiceRole', 'N/A'))}</td></tr>
                    <tr><th>Created Time</th><td>{escape(str(instance.get('CreatedTime', 'N/A')))}</td></tr>
                </table>
            </div>
        """
        
        # Add inbound/outbound calls configuration
        if 'InboundCallsEnabled' in instance or 'OutboundCallsEnabled' in instance:
            html_content += """
            <div class="section">
                <h3>Call Configuration</h3>
                <table style="width: 50%">
            """
            if 'InboundCallsEnabled' in instance:
                html_content += f"<tr><th>Inbound Calls Enabled</th><td>{escape(str(instance['InboundCallsEnabled']))}</td></tr>"
            if 'OutboundCallsEnabled' in instance:
                html_content += f"<tr><th>Outbound Calls Enabled</th><td>{escape(str(instance['OutboundCallsEnabled']))}</td></tr>"
            html_content += "</table></div></body></html>"

            logger.debug(f"\n🔄 REPLICATION CONFIGURATION:")
            html_content += """<div class="section">
                <h3>Replication Configuration</h3>"""

        # Replication configuration (if available)
            if 'ReplicationConfiguration' in response:
                replication = response['ReplicationConfiguration']
                html_content += """<table>
                    <tr><th>Replication Region</th><td>{escape(replication.get('ReplicationRegion', 'N/A'))}</td></tr>
                    <tr><th>Replication Status</th><td>{escape(replication.get('ReplicationStatus', 'N/A'))}</td></tr>
                    <tr><th>Replication Status Message</th><td>{escape(replication.get('ReplicationStatusMessage', 'N/A'))}</td></tr>
                </table>
                </div>"""

            else:
                logger.debug("No replication configuration available.")
                html_content += """<p>No replication configuration available.</p>
                    <h4>Recommendation</h4>
                    <ul>
                        Consider Amazon Connect Global Resiliency (ACGR) for resiliency requirements. ACGR provides customers with geographic telephony redundancy, offering a flexible solution to distribute inbound voice traffic and agents across linked instances with the same reserved capacity limit, in another Region in the event of unplanned Region outages or disruptions or other requirements.
                        Refer <a href="https://docs.aws.amazon.com/connect/latest/adminguide/disaster-recovery-resiliency.html" target="_blank"> documentation </a> for more information 
                    </ul>
                    </div>"""

        return html_content
        
    except Exception as e:
        return f"<html><body><h1>Error</h1><p>Error describing instance: {escape(str(e))}</p></body></html>"


# Get all phone numbers for the instance
def get_phone_numbers_with_basic_details(connect_client, instance_id):
    """Get all phone numbers with basic information"""
    
    phone_numbers = []
    
    try:
        # Use ListPhoneNumbersV2 for accurate type identification
        paginator = connect_client.get_paginator('list_phone_numbers_v2')
        
        for page in paginator.paginate(InstanceId=instance_id):
            for number_summary in page.get('ListPhoneNumbersSummaryList', []):
                try:
                    # Get basic information for each phone number
                    detailed_info = connect_client.describe_phone_number(
                        PhoneNumberId=number_summary['PhoneNumberId']
                    )
                    
                    phone_number_carrier = validate_phone_number_for_connect(number_summary['PhoneNumber'], number_summary['PhoneNumberCountryCode'])['carrier']

                    phone_number_info = {
                        "phone_number_id": number_summary['PhoneNumberId'],
                        "phone_number": number_summary['PhoneNumber'],
                        #'phone_number_arn': number_summary['PhoneNumberArn'],
                        "phone_number_type": number_summary['PhoneNumberType'],
                        "phone_number_country_code": number_summary['PhoneNumberCountryCode'],
                        "phone_number_carrier" : phone_number_carrier
                        }
                    
                    phone_numbers.append(phone_number_info)
        
                    logger.debug(f"📞 Phone Number: {number_summary['PhoneNumber']}")
                    logger.debug(f"📞 Phone Number Type: {number_summary['PhoneNumberType']}")
                    logger.debug(f"📞 Phone Number Carrier: {phone_number_carrier}")

                except Exception as e:
                    logger.error(f"Error getting details for phone number {number_summary['PhoneNumber']}: {str(e)}")
                    phone_numbers.append({
                        "phone_number_id": number_summary['PhoneNumberId'],
                        "phone_number": number_summary['PhoneNumber'],
                        #'phone_number_arn': number_summary['PhoneNumberArn'],
                        "phone_number_type": number_summary['PhoneNumberType'],
                        "phone_number_country_code": number_summary['PhoneNumberCountryCode'],
                        "phone_number_carrier" : phone_number_carrier,
                        "error": str(e)
                    })
        
        return phone_numbers
        
    except Exception as e:
        print(f"Error listing phone numbers: {str(e)}")
        return []

# Categorize phone numbers by type
def count_phone_numbers_by_type(connect_client, instance_id):
    """
    Count phone numbers by type using ListPhoneNumbersV2
    """
    
    # Initialize counters for all possible phone number types
    phone_type_counts = {
        'TOLL_FREE': 0,
        'DID': 0,
        'UIFN': 0,
        'SHARED': 0,
        'THIRD_PARTY_TF': 0,
        'THIRD_PARTY_DID': 0,
        'SHORT_CODE': 0
    }
    
    # Additional tracking
    country_counts = Counter()
    status_counts = Counter()
    total_numbers = 0
    
    try:
        # Use ListPhoneNumbersV2 for accurate type identification
        paginator = connect_client.get_paginator('list_phone_numbers_v2')
        
        for page in paginator.paginate(InstanceId=instance_id):
            for number_summary in page.get('ListPhoneNumbersSummaryList', []):
                total_numbers += 1
                
                # Count by type
                phone_type = number_summary.get('PhoneNumberType', 'UNKNOWN')
                if phone_type in phone_type_counts:
                    phone_type_counts[phone_type] += 1
                
                # Count by country
                country_code = number_summary.get('PhoneNumberCountryCode', 'UNKNOWN')
                country_counts[country_code] += 1
                
                # Get status information if available
                try:
                    detailed_info = connect_client.describe_phone_number(
                        PhoneNumberId=number_summary['PhoneNumberId']
                    )
                    status = detailed_info['ClaimedPhoneNumberSummary'].get('PhoneNumberStatus', 'UNKNOWN')
                    status_counts[status] += 1
                except Exception as e:
                    logger.error(f"Is this Error getting status for {number_summary['PhoneNumberId']}: {str(e)}")
                    status_counts['UNKNOWN'] += 1
        
        # Add additional information to the counts
        phone_type_counts['_metadata'] = {
            'total_numbers': total_numbers,
            'country_distribution': dict(country_counts),
            'status_distribution': dict(status_counts),
            'countries_count': len(country_counts),
            'most_common_country': country_counts.most_common(1)[0] if country_counts else None
        }
        
        return phone_type_counts
        
    except Exception as e:
        logger.error(f"Error listing phone numbers: {str(e)}")
        return phone_type_counts

#Carrier Diversity
def validate_phone_number_for_connect(phone_number, iso_country_code=None):
    """
    Validate a phone number using Amazon Pinpoint Phone Number Validation API
    to get service provider information for Amazon Connect phone numbers.
    
    Args:
        phone_number (str): The phone number to validate (include country code)
        iso_country_code (str, optional): Two-character ISO 3166-1 alpha-2 country code
    
    Returns:
        dict: Phone number validation response with carrier and other details
    """
    try:
        # Prepare the request
        request_params = {
            'NumberValidateRequest': {
                'PhoneNumber': phone_number
            }
        }
        
        # Add country code if provided
        if iso_country_code:
            request_params['NumberValidateRequest']['IsoCountryCode'] = iso_country_code
        
        # Call the phone number validation API
        response = pinpoint_client.phone_number_validate(**request_params)
        
        # Extract validation details
        validation_result = response['NumberValidateResponse']
        
        # Format the result for easy consumption
        result = {
            'original_number': validation_result.get('OriginalPhoneNumber'),
            'cleansed_e164': validation_result.get('CleansedPhoneNumberE164'),
            'cleansed_national': validation_result.get('CleansedPhoneNumberNational'),
            'carrier': validation_result.get('Carrier'),
            'phone_type': validation_result.get('PhoneType'),
            'phone_type_code': validation_result.get('PhoneTypeCode'),
            'country': validation_result.get('Country'),
            'country_code_iso2': validation_result.get('CountryCodeIso2'),
            'country_code_numeric': validation_result.get('CountryCodeNumeric'),
            'city': validation_result.get('City'),
            'timezone': validation_result.get('Timezone'),
            'zip_code': validation_result.get('ZipCode'),
            'is_valid': validation_result.get('PhoneType') != 'INVALID'
        }
        
        return result
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        return {
            'error': True,
            'error_code': error_code,
            'error_message': error_message,
            'original_number': phone_number
        }
    except Exception as e:
        return {
            'error': True,
            'error_message': str(e),
            'original_number': phone_number
        }


def get_connect_metric_simple(instance_id, metric_name, days_back):
    """
    Simple function to get a specific Amazon Connect metric
    """
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days_back)
    
    try:
        response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/Connect',
            MetricName=metric_name,
            Dimensions=[
                {'Name': 'InstanceId', 'Value': instance_id},
                {'Name': 'MetricGroup', 'Value': 'VoiceCalls'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,  # 1 hour
            Statistics=['Sum', 'Average', 'Maximum']
        )
        
        datapoints = response['Datapoints']
        
        if datapoints:
            # Sort by timestamp
            datapoints.sort(key=lambda x: x['Timestamp'])
            
            logger.debug(f"📊 {metric_name} (last {days_back} days):")
            
            if 'Sum' in datapoints[0]:
                total = sum(dp.get('Sum', 0) for dp in datapoints)
                logger.debug(f"   Total: {total:.0f}")
            
            if 'Average' in datapoints[0]:
                avg_values = [dp.get('Average', 0) for dp in datapoints]
                overall_avg = sum(avg_values) / len(avg_values)
                logger.debug(f"   Average: {overall_avg:.2f}")
            
            if 'Maximum' in datapoints[0]:
                max_values = [dp.get('Maximum', 0) for dp in datapoints]
                peak = max(max_values)
                logger.debug(f"   Peak: {peak:.0f}")
            
            return datapoints
        else:
            logger.debug(f"No data found for {metric_name}")
            return []
            
    except Exception as e:
        logger.error(f"Error getting {metric_name}: {str(e)}")
        return []

def get_contact_flows(instance_id):
    """Get all contact flows for the instance"""
    
    try:
        contact_flows = {}
        paginator = connect_client.get_paginator('list_contact_flows')
        
        for page in paginator.paginate(InstanceId=instance_id):
            for flow in page['ContactFlowSummaryList']:
                contact_flows[flow['Id']] = {
                    'name': flow['Name'],
                    'type': flow['ContactFlowType'],
                    'arn': flow['Arn']
                }
        
        return contact_flows
        
    except Exception as e:
        logger.debug(f"Error getting contact flows: {str(e)}")
        return {}

def run_log_insights_query(logs_client, log_group, query, start_time, end_time):
    """Execute CloudWatch Log Insights query"""
    
    try:
        # Start the query
        response = logs_client.start_query(
            logGroupName=log_group,
            startTime=int(start_time.timestamp()),
            endTime=int(end_time.timestamp()),
            queryString=query
        )
        
        query_id = response['queryId']
        
        # Wait for query to complete
        max_attempts = 30
        attempt = 0
        
        while attempt < max_attempts:
            time.sleep(2)
            
            result = logs_client.get_query_results(queryId=query_id)
            
            if result['status'] == 'Complete':
                return result['results']
            elif result['status'] == 'Failed':
                raise Exception(f"Query failed: {result.get('statistics', {})}")
            
            attempt += 1
        
        raise Exception("Query timeout")
        
    except Exception as e:
        logger.error(f"Error running query: {str(e)}")
        return []

def analyze_contact_flow_errors(logs_client, instance_id, start_time, end_time, contact_flows):
    """Analyze contact flow errors using CloudWatch Log Insights"""
        
    # Query for all contact flow errors
    error_query = """
    fields @timestamp, ContactId, ContactFlowId, ContactFlowModuleType, LogLevel, Message, Parameters
    | filter LogLevel = "ERROR"
    | stats count() as ErrorCount by ContactFlowId, ContactFlowModuleType, Message
    | sort ErrorCount desc
    """
    
    try:
        error_results = run_log_insights_query(logs_client, log_group, error_query, start_time, end_time)
        
        # Query for detailed error information
        detailed_error_query = """
        fields @timestamp, ContactId, ContactFlowId, ContactFlowModuleType, LogLevel, Message, Parameters
        | filter LogLevel = "ERROR"
        | sort @timestamp desc
        | limit 100
        """
        
        detailed_errors = run_log_insights_query(logs_client, log_group, detailed_error_query, start_time, end_time)
        
        # Process and categorize errors
        processed_errors = process_error_results(error_results, detailed_errors, contact_flows)
        
        return processed_errors
        
    except Exception as e:
        logger.error(f"Error analyzing contact flow errors: {str(e)}")
        return {}

def analyze_fatal_errors(logs_client, instance_id, start_time, end_time, contact_flows):
    """Analyze fatal errors in contact flows"""
        
    # Query for fatal errors and critical issues
    fatal_query = """
    fields @timestamp, ContactId, ContactFlowId, ContactFlowModuleType, Message, Parameters
    | filter Message like /FATAL/ or Message like /CRITICAL/ or Message like /EXCEPTION/ or Message like /TIMEOUT/
    | stats count() as FatalCount by ContactFlowId, Message
    | sort FatalCount desc
    """
    
    try:
        fatal_results = run_log_insights_query(logs_client, log_group, fatal_query, start_time, end_time)
        
        # Query for recent fatal errors with full context
        recent_fatal_query = """
        fields @timestamp, ContactId, ContactFlowId, ContactFlowModuleType, Message, Parameters
        | filter Message like /FATAL/ or Message like /CRITICAL/ or Message like /EXCEPTION/ or Message like /TIMEOUT/
        | sort @timestamp desc
        | limit 50
        """
        
        recent_fatals = run_log_insights_query(logs_client, log_group, recent_fatal_query, start_time, end_time)
        
        # Process fatal errors
        processed_fatals = process_fatal_results(fatal_results, recent_fatals, contact_flows)
        
        return processed_fatals
        
    except Exception as e:
        logger.error(f"Error analyzing fatal errors: {str(e)}")
        return {}

def process_error_results(error_results, detailed_errors, contact_flows):
    """Process and categorize error results"""
    
    processed = {
        'flows_with_errors': {},
        'error_categories': defaultdict(int),
        'module_errors': defaultdict(int),
        'recent_errors': []
    }
    
    # Process summary results
    for error in error_results:
        if len(error) >= 4:
            flow_id = error[0]['value'] if error[0]['field'] == 'ContactFlowId' else None
            module_type = error[1]['value'] if error[1]['field'] == 'ContactFlowModuleType' else None
            message = error[2]['value'] if error[2]['field'] == 'Message' else None
            count = int(error[3]['value']) if error[3]['field'] == 'ErrorCount' else 0
            
            if flow_id and flow_id in contact_flows:
                if flow_id not in processed['flows_with_errors']:
                    processed['flows_with_errors'][flow_id] = {
                        'flow_name': contact_flows[flow_id]['name'],
                        'flow_type': contact_flows[flow_id]['type'],
                        'total_errors': 0,
                        'error_types': {}
                    }
                
                processed['flows_with_errors'][flow_id]['total_errors'] += count
                processed['flows_with_errors'][flow_id]['error_types'][f"{module_type}: {message}"] = count
                
                # Categorize errors
                processed['error_categories'][categorize_error(message)] += count
                processed['module_errors'][module_type] += count
    
    # Process detailed errors
    for error in detailed_errors[:20]:  # Limit to recent 20 errors
        processed['recent_errors'].append(format_detailed_error(error, contact_flows))
    
    return processed

def process_fatal_results(fatal_results, recent_fatals, contact_flows):
    """Process fatal error results"""
    
    processed = {
        'flows_with_fatals': {},
        'fatal_categories': defaultdict(int),
        'recent_fatals': []
    }
    
    # Process fatal error summary
    for fatal in fatal_results:
        if len(fatal) >= 3:
            flow_id = fatal[0]['value'] if fatal[0]['field'] == 'ContactFlowId' else None
            message = fatal[1]['value'] if fatal[1]['field'] == 'Message' else None
            count = int(fatal[2]['value']) if fatal[2]['field'] == 'FatalCount' else 0
            
            if flow_id and flow_id in contact_flows:
                if flow_id not in processed['flows_with_fatals']:
                    processed['flows_with_fatals'][flow_id] = {
                        'flow_name': contact_flows[flow_id]['name'],
                        'flow_type': contact_flows[flow_id]['type'],
                        'total_fatals': 0,
                        'fatal_types': {}
                    }
                
                processed['flows_with_fatals'][flow_id]['total_fatals'] += count
                processed['flows_with_fatals'][flow_id]['fatal_types'][message] = count
                
                # Categorize fatal errors
                processed['fatal_categories'][categorize_fatal_error(message)] += count
    
    # Process recent fatal errors
    for fatal in recent_fatals[:10]:  # Limit to recent 10 fatals
        processed['recent_fatals'].append(format_detailed_error(fatal, contact_flows))
    
    return processed

"""Find contact flows where 'Set logging behavior' block is not enabled (set to TRUE)"""
def find_flows_without_logging_enabled(instance_id):
    
    flows_without_logging = []
    
    try:
        # Get all contact flows
        paginator = connect_client.get_paginator('list_contact_flows')
        page_iterator = paginator.paginate(InstanceId=instance_id)
        
        for page in page_iterator:
            for flow_summary in page['ContactFlowSummaryList']:
                flow_id = flow_summary['Id']
                flow_name = flow_summary['Name']
                flow_type = flow_summary['ContactFlowType']
                
                logger.debug(f"Analyzing flow: {flow_name} (ID: {flow_id})")

                try:
                    # Get detailed flow information including content
                    flow_details = connect_client.describe_contact_flow(
                        InstanceId=instance_id,
                        ContactFlowId=flow_id
                    )
                    
                    # Parse the flow content (JSON string)
                    flow_content = json.loads(flow_details['ContactFlow']['Content'])

                    # Check if logging is enabled in this flow
                    logging_enabled = check_logging_behavior_in_flow(flow_content)
                    logger.debug(f"logging_enabled: {logging_enabled}")

                    if not logging_enabled:
                        flows_without_logging.append({
                            'FlowId': flow_id,
                            'FlowName': flow_name,
                            'FlowType': flow_type,
                            'FlowArn': flow_summary.get('Arn', ''),
                            'Status': flow_summary.get('ContactFlowStatus', ''),
                            'State': flow_summary.get('ContactFlowState', '')
                        })
                        logger.debug(f"❌ Logging is not enabled for flow: {flow_name} (ID: {flow_id})")
                    else :
                        logger.debug(f"✅ Logging is enabled for flow: {flow_name} (ID: {flow_id})")
                        
                except Exception as e:
                    logger.error(f"Error analyzing flow {flow_name}: {str(e)}")
                    continue
                    
    except Exception as e:
        logger.error(f"Error listing contact flows: {str(e)}")
        return []
    
    return flows_without_logging

"""Check if the flow contains a 'Set logging behavior' block with logging enabled"""
def check_logging_behavior_in_flow(flow_content):

    state = False

    # Look for actions in the flow content
    actions = flow_content.get('Actions', [])
    
    for action in actions:
        # Check if this is a Set logging behavior block
        action_type = action.get('Type', '')
        if action_type == 'UpdateFlowLoggingBehavior':

            # Check the parameters to see if logging is enabled
            parameters = action.get('Parameters', {})
            logging_behavior = parameters.get('FlowLoggingBehavior', '')
            logger.debug(f"parameters: {parameters}")
            logger.debug(f"logging_behavior: {logging_behavior}")

            # If LoggingBehavior is set to 'Enable', then logging is enabled
            if logging_behavior == 'Enabled':
                state = True
                logger.debug(f"action_type: {action_type}")
                break  # Stop searching once we find a logging block that is enabled

    # If no SetLoggingBehavior block found or none are enabled
    return state

"""Main Handler"""
def lambda_handler(event, context):
    try:
        mystring = ""
        combined_string = ""
        cfs_limit=""
        rps_limit = ""
        queues_limit = ""
        sec_profiles_limit = ""
        users_limit = ""
        bots_limit = ""
        days_back = 14
        metric_name = ""
        html_content = ""

        logger.info(f"Execute AWS Automated Connect Operations Review: {datetime_string}")
        lambda_exec_start_time = time.time()

        # Far back to evaluate logs
        days_back = 14
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days_back)

        # Parse Amazon connect instance info from environment variables
        parsed = parse_connect_instance_arn(os.environ.get('CONNECT_INSTANCE_ARN'))
        instance_id = str(parsed['instance_id'])
        aws_region = str(parsed['aws_region'])
        account_id = str(parsed['account_id'])

        logger.info (f"Instance Details parsed from env variables: {instance_id}, AWS Region: {aws_region}, Account ID: {account_id}")

        # Get Amazon Connect logs
        log_group = hf.get_connect_log_group(instance_id)
        log_group = os.environ.get('CONNECT_INSTANCE_LOG_GROUP')

        if log_group:
            logger.info(f"Found log group for Connect instance {instance_id}: {log_group}")
        else:
            logger.info(f"No log group found for Connect instance {instance_id}.")


        # Current Quota Limits
        quotas = get_connect_service_quotas()
        logger.debug(f"Found {len(quotas)} Amazon Connect service quotas:\n")

        for quota in quotas:
           
            if quota['QuotaName'] == "Contact flows per instance":
                cfs_string = "Contact flows per instance - Current Limit : " + str(quota['Value'])  + ". "
                cfs_limit = str(quota['Value'])
                logger.debug(f"{cfs_string}")

            elif quota['QuotaName'] == "Routing profiles per instance":
                rps_limit = str(quota['Value'])

            elif quota['QuotaName'] == "Queues per instance":
                queues_limit = str(quota['Value'])
            
            elif quota['QuotaName'] == "Security profiles per instance":
                sec_profiles_limit = str(quota['Value'])
            
            elif quota['QuotaName'] == "Users per instance":
                users_limit = str(quota['Value'])
            
            elif quota['QuotaName'] == "Amazon Lex bots per instance":
                botsv1_limit = str(quota['Value'])
            
            elif quota['QuotaName'] == "Phone numbers per instance":
                phone_limit = str(quota['Value'])

            elif quota['QuotaName'] == "Amazon Lex V2 bot aliases per instance":
                botsv2_limit = str(quota['Value'])

            elif quota['QuotaName'] == "Quick connects per instance":
                qc_limit = str(quota['Value'])

            elif quota['QuotaName'] == "Hours of operation per instance":
                hrs_operation_limit = str(quota['Value'])

            elif quota['QuotaName'] == "Users per instance":
                users_limit = str(quota['Value'])

            elif quota['QuotaName'] == "Amazon Lex bots per instance":
                bots_limit = str(quota['Value'])

            else:
                quota_name = quota['QuotaName']
                quota_value = quota['Value']
                
        if not instance_id:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Connect Instance ID is required'})
            }

        #Describe Instance and create the intial html output
        html_output = describe_connect_to_html(instance_id)
        
        #Instance Attributes
        #get_instance_attributes(instance_id)
        
        #HTML Output - Connect Usage Vs Limits
        html_output += f"""
            <html>
            <body>
            <div class="section">
                <br><h2>Capacity Analysis</h2>
                <h3>Current Instance Usage Vs Limit</h3>
                <table style="width: 50%">
                    <tr><th></th><th>Current Use</th><th>Quota Limit</th></tr>
                    <tr><th>Contact Flows per instance</th><td>{escape(str(hf.current_utilization(instance_id, "ContactFlows")))}</td><td>{escape(cfs_limit)}</td></tr>
                    <tr><th>Queues per instance</th><td>{escape(str(hf.current_utilization(instance_id, "Queues")))}</td><td>{escape(queues_limit)}</td></tr>
                    <tr><th>Routing Profiles per instance</th><td>{escape(str(hf.current_utilization(instance_id, "RoutingProfiles")))}</td><td>{escape(rps_limit)}</td></tr>
                    <tr><th>Security Profiles per instance</th><td>{escape(str(hf.current_utilization(instance_id, "SecurityProfiles")))}</td><td>{escape(sec_profiles_limit)}</td></tr>
                    <tr><th>Users per instance</th><td>{escape(str(hf.current_utilization(instance_id, "Users")))}</td><td>{escape(users_limit)}</td></tr>
                    <tr><th>Lex Bots V1 per instance</th><td>{escape(str(hf.current_utilization(instance_id, "LexBotsV1")))}</td><td>{escape(botsv1_limit)}</td></tr>
                    <tr><th>Lex Bots V2 per instance</th><td>{escape(str(hf.current_utilization(instance_id, "LexBotsV2")))}</td><td>{escape(botsv2_limit)}</td></tr>
                    <tr><th>PhoneNumbers per instance</th><td>{escape(str(hf.current_utilization(instance_id, "PhoneNumbers")))}</td><td>{escape(phone_limit)}</td></tr>
                    <tr><th>QuickConnects per instance</th><td>{escape(str(hf.current_utilization(instance_id, "QuickConnects")))}</td><td>{escape(qc_limit)}</td></tr>
                    <tr><th>HoursOfOperation per instance</th><td>{escape(str(hf.current_utilization(instance_id, "HoursOfOperation")))}</td><td>{escape(hrs_operation_limit)}</td></tr>

                </table>
            </div>
            </html>
            </body>
            """
        
        html_output += f"""
            <html>
            <body>
            <div class="section">
            <br><h2>Operational Analysis</h2>
            <h3>Contact Flows missing logging</h3>
            Analyzed {escape(str(hf.current_utilization(instance_id, "ContactFlows")))} contact flows....<br>
            """

        flows_without_logging = find_flows_without_logging_enabled(instance_id)
        
        if flows_without_logging.__len__() == 0:
            html_output += f"""<br> No contact flows without logging enabled found."""
        else:
            html_output += f"""
                   <br>{flows_without_logging.__len__()} contact flows without logging enabled found.<br><br>
                    <table style="width: 80%">
                            <tr><th>Flow Name</th><th>Flow ID</th><th>Flow Type</th><th>Status</th><th>State</th><th>ARN</th></tr>"""
            
            for flow in flows_without_logging:
                html_output += f"""
                            <tr><td>{flow['FlowName']}</td><td>{flow['FlowId']}</td><td>{flow['FlowType']}</td><td>{flow['Status']}</td><td>{flow['State']}</td><td>{flow['FlowArn']}</td></tr>
                    """
            html_output += f"""</table>
            <h4>Recommendations</h4>
            <ul>
                <li>Use a Set logging behavior block to enable or disable logging for segments of the flow where sensitive information is collected and can't be stored in CloudWatch.</li>
                <li>Learn more about contact flow <a href="https://docs.aws.amazon.com/connect/latest/adminguide/about-contact-flow-logs.html" target="_blank">logging</a>.</li>
            </ul>
            """

        #Phone Number Analysis
        phone_type_counts = count_phone_numbers_by_type(connect_client, instance_id)
        logger.debug(f"Phone type counts: {phone_type_counts}")

        metadata = phone_type_counts.get('_metadata', {})
        total_numbers = metadata.get('total_numbers', 0)

        html_output += f"""
            <br><h3>Phone Number Analysis</h3>
            Analyzed {escape(str(total_numbers))} phone numbers....<br>
            """

        if total_numbers == 0:
             html_output += "No phone numbers analyzed."

        else :    # Check for toll-free dominance
            toll_free_count = phone_type_counts.get('TOLL_FREE', 0)
            if toll_free_count > 0:
                toll_free_percentage = (toll_free_count / total_numbers) * 100
                if toll_free_percentage > 70:
                    html_output += (f"High toll-free usage: {toll_free_percentage:.1f}% of numbers are toll-free (potential cost optimization opportunity)")
                elif toll_free_percentage < 20:
                    html_output += (f"<br>Low toll-free usage: Only {toll_free_percentage:.1f}% are toll-free (consider customer accessibility)")
            
            # Check for DID usage
            did_count = phone_type_counts.get('DID', 0)
            if did_count > 0:
                did_percentage = (did_count / total_numbers) * 100
                html_output += (f"<br>DID numbers provide local presence: {did_percentage:.1f}% of total numbers")
            
            # Check for international presence
            metadata = phone_type_counts.get('_metadata', {})
            countries_count = metadata.get('countries_count', 0)
            if countries_count > 1:
                html_output += (f"<br>International presence: Numbers in {countries_count} countries")
            
            # Check for special types
            uifn_count = phone_type_counts.get('UIFN', 0)
            short_code_count = phone_type_counts.get('SHORT_CODE', 0)
            
            if uifn_count > 0:
                html_output += (f"<br>Global accessibility: {uifn_count} UIFN numbers for international toll-free access")
            
            if short_code_count > 0:
                html_output += (f"<br>SMS capability: {short_code_count} short codes for messaging services")    


            if phone_type_counts.get('TOLL_FREE', 0) == 0:
                html_output += f"""
                <h4>Recommendations</h4>
                <ul>
                    <li>Consider using toll-free numbers for international toll-free access.</li>
                    <li>Learn more about <a href="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" target="_blank">phone number types</a>.</li>
                </ul>
                """
            if phone_type_counts.get('TOLL_FREE', 0) < phone_type_counts.get('DID', 0):
                html_output += f"""
                <h4>Recommendations</h4>
                <ul>
                    <li>In the US, use toll-free phone numbers wherever possible to load balance across multiple carriers for additional route and carrier redundancy.</li>
                    <li>In situations where you use DIDs, load balance across numbers from multiple carriers, when possible, to increase reliability.</li>
                    <li>This level of service does come at an additional cost.</li>
                </ul>
                """

            else :
                html_output += f"""
                <h4>Recommendations</h4>
                <ul>
                Though Toll free numbers provide additional resiliency, it comes with additional cost when compared with DIDs. Apply your workload's
                availability and resiliency requirements in choosing right telephony numbers. Refer <a href="https://docs.aws.amazon.com/connect/latest/adminguide/ag-overview-numbers.html" target="_blank">documentation</a> for additional details on DIDs and TFNs in
                Amazon Connect. 
                </ul>
                """

        html_output += f"""</div>
            <div class="section">
            <h3>Carrier diversity</h3>
            <table style="width: 80%">
            <tr><th>Country Code | Phone Carrier</th><th>Count</th><th>Phone Number List</th></tr>"""
        # Get all phone numbers for the instance
        phone_numbers = get_phone_numbers_with_basic_details(connect_client, instance_id)
        logger.debug(f"Phone numbers: {phone_numbers}")

        multi_groups = hf.segregate_by_multiple_criteria(phone_numbers, ["phone_number_country_code", "phone_number_carrier"])
        logger.debug("By country code and carrier:")
        for group_key, ph_nos in multi_groups.items():
            logger.debug(f"{group_key}:  Count - {len(ph_nos)}, List - {[ph['phone_number'] for ph in ph_nos]}")
            html_output += f"""
                <tr><th>{escape(group_key)}</th><td>{escape(str(len(ph_nos)))}</td><td>{[ph['phone_number'] for ph in ph_nos]}</td></tr>
                """                    
                             
            #if len(ph_nos) > 1:
            # html_output += f"""<br>Recommendation: Consider using a different carrier for each phone number in this group to increase carrier diversity."""
        
        html_output += f"""
            </table>
            </div><div class="section">
            <br><h2>CloudWatch Analysis</h2>
            <h3>Concurrent Calls</h3>
            """
        html_output += hf.summarize_concurrent_calls(instance_id, days_back)

        html_output += f"""</div>
            <div class="section">
            <h3>Missed Calls</h3>
            """
        html_output += hf.summarize_missed_calls(instance_id, days_back)

        html_output += f"""</div>
            <div class="section">
            <h3>Throttled Calls</h3>
            """
        html_output += hf.summarize_throttled_calls(instance_id, days_back)

        html_output += f"""</div>
            <div class="section">
            <h3>Concurrent Chat Analysis</h3>
            """
        html_output += "Work In Progress..."

        html_output += f"""</div>
            <div class="section">
            <h3>Contact Flow Errors</h3>
            """
        html_output += "Work In Progress..."

        html_output += f"""</div>
            <div class="section">
            <h3>Fatal Errors</h3>
            """
        html_output += "Work In Progress..."

        html_output += f"""</div>
            <div class="section">
            <h3>Amazon Connect API Throttling</h3>
            """
        html_output += hf.summarize_amazon_api_throttles(instance_id, account_id, days_back, aws_region)

        html_output += f"""</div>
            </html>
            </body>
            """

         # Get key metrics
        get_connect_metric_simple(instance_id, 'CallsPerInterval', days_back)
        get_connect_metric_simple(instance_id, 'ConcurrentCalls', days_back)
        get_connect_metric_simple(instance_id, 'MissedCalls', days_back)
        get_connect_metric_simple(instance_id, 'QueueSize', days_back)

        # Upload to S3
        upload_string_to_s3(html_output, 'amazonconnectoperationalreview-10252025', 'my-connect.html','text/html') 
        
        # Get contact flow information
        contact_flows = get_contact_flows(instance_id)

         # Analyze contact flow errors
        error_analysis = analyze_contact_flow_errors(
            logs_client, instance_id, start_time, end_time, contact_flows
        )
        
        logger.debug(f"Error analysis: {error_analysis}")

        # Analyze fatal errors specifically
        fatal_analysis = analyze_fatal_errors(
            logs_client, instance_id, start_time, end_time, contact_flows
        )
        logger.debug(f"Fatal analysis: {fatal_analysis}")

        lambda_exec_end_time = time.time()
        duration = lambda_exec_end_time - lambda_exec_start_time
        print(f"Lambda execution time: {duration}")

        return {
                'statusCode': 200,
                'body': json.dumps({'success': f'Amazon Connect Ops Review document succesfully generated. Execution duration: {duration} seconds")'})
            }
        
    except Exception as e:
        logger.error(f"AWS Client Error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'AWS API Error',
                'message': str(e)
            })
        }
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }
