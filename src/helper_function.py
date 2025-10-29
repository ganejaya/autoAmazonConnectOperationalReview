
import boto3
import json
import logging
import os
from botocore.exceptions import ClientError
import json
from collections import defaultdict
from datetime import datetime
from datetime import datetime, timedelta
from typing import List, Dict, Any, Union

# Initialize Connect client
connect_client = boto3.client('connect')

# Initialize S3 client
s3_client = boto3.client('s3')  

# Initialize CloudWatch client
cloudwatch_client = boto3.client('cloudwatch')

# Initialize CloudWatch client
quota_client = boto3.client('service-quotas')

# Initialize CloudTrail client
cloudtrail_client = boto3.client('cloudtrail')    


# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

#Get Current utilization for Amazon Connect
def current_utilization (instance_id, metric_name):
   
    try:
        matched_value = metric_name
        if matched_value == "ContactFlows":
            # List all contact flows
                response = connect_client.list_contact_flows(InstanceId=instance_id)
                metric_usage = len(response['ContactFlowSummaryList'])
        
        # Get the current number of Users
        elif matched_value == "Users":
            # List all users
                response = connect_client.list_users(InstanceId=instance_id)
                metric_usage = len(response['UserSummaryList'])
        
        # Get the current number of Queues
        elif matched_value == "Queues":
            # List all queues
                response = connect_client.list_queues(InstanceId=instance_id)
                metric_usage = len(response['QueueSummaryList'])

        elif matched_value == "RoutingProfiles":
            # List all routing profiles
                response = connect_client.list_routing_profiles(InstanceId=instance_id)
                metric_usage = len(response['RoutingProfileSummaryList'])
        
        elif matched_value == "SecurityProfiles":
            # List all security profiles
                response = connect_client.list_security_profiles(InstanceId=instance_id)
                metric_usage = len(response['SecurityProfileSummaryList'])

        elif matched_value == "HoursOfOperation":
            # List all hours of operation
                response = connect_client.list_hours_of_operations(InstanceId=instance_id)
                metric_usage = len(response['HoursOfOperationSummaryList'])
        
        elif matched_value == "Prompts":
            # List all prompts
                response = connect_client.list_prompts(InstanceId=instance_id)
                metric_usage = len(response['PromptSummaryList'])

        elif matched_value == "LexBotsV1":
            # List all lex bots
                response = connect_client.list_bots(InstanceId=instance_id, LexVersion='V1')
                metric_usage = len(response['LexBots'])
        
        elif matched_value == "LexBotsV2":
            # List all lex bots
                response = connect_client.list_bots(InstanceId=instance_id, LexVersion='V2')
                metric_usage = len(response['LexBots'])
        
        elif matched_value == "PhoneNumbers":
            # List all phone numbers
                response = connect_client.list_phone_numbers(InstanceId=instance_id)
                metric_usage = len(response['PhoneNumberSummaryList'])

        elif matched_value == "AgentStatuses":
            # List all agent statuses
                response = connect_client.list_agent_statuses(InstanceId=instance_id)
                metric_usage = len(response['AgentStatusSummaryList'])

        elif matched_value == "ContactFlowModules":
            # List all contact flow modules
                response = connect_client.list_contact_flow_modules(InstanceId=instance_id)
                metric_usage = len(response['ContactFlowModulesSummaryList'])
        
        elif matched_value == "QuickConnects":
            # List all quick connects
                response = connect_client.list_quick_connects(InstanceId=instance_id)
                metric_usage = len(response['QuickConnectSummaryList'])
        
        else:
        # Handle unexpected metric_name values
            error = f"Unknown metric name: {metric_name}"
            logger.warning(error)
            return error

        logger.debug(f"Metric {matched_value} usage : {metric_usage}")

        return metric_usage

    except Exception as e:
        logger.error(f"AWS Client Error: {e}")
        #print(traceback.format_exc())
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

#Service Quota value for those service quota
def get_connect_service_quota(instance_id_arn, quota_code):
    """Retrieve all Amazon Connect service quotas"""
    try:
       
        response = quota_client.get_service_quota(
        ServiceCode='connect',
        QuotaCode=quota_code,
        ContextId=instance_id_arn # Optional, for resource-level quotas
        )
        
        quota_value = response['Quota']['Value']
        quota_unit = response['Quota']['Unit']

        logger.debug(f"For Amazon Connect quota_code {quota_code} value is {quota_value} with unit {quota_unit}")

        return quota_value
    
    except ClientError as e:
        logger.error(f"Error retrieving service quotas: {e}")
        return []

#Instance Attribute
def get_instance_attributes(instance_id):
    """
    Get instance attributes (requires additional API calls)
    """
    try:
        logger.debug(f"\n{'='*60}")
        logger.debug(f"INSTANCE ATTRIBUTES AND CONFIGURATION")
        logger.debug(f"{'='*60}")
            
        # Get instance storage configuration
        try:
            storage_response = connect_client.describe_instance_storage_config(
                InstanceId=instance_id,
                ResourceType='CONTACT_TRACE_RECORDS'
            )
            logger.debug(f"\n💾 STORAGE CONFIGURATION (Contact Trace Records):")
            for config in storage_response.get('StorageConfigs', []):
                storage_type = config['StorageType']
                logger.debug(f"   Storage Type: {storage_type}")
                    
                if storage_type == 'S3':
                    s3_config = config.get('S3Config', {})
                    logger.debug(f"   S3 Bucket: {s3_config.get('BucketName', 'N/A')}")
                    logger.debug(f"   S3 Prefix: {s3_config.get('BucketPrefix', 'N/A')}")
                    logger.debug(f"   Encryption Type: {s3_config.get('EncryptionConfig', {}).get('EncryptionType', 'N/A')}")
                elif storage_type == 'KINESIS_DATA_STREAM':
                    kinesis_config = config.get('KinesisStreamConfig', {})
                    logger.debug(f"   Stream ARN: {kinesis_config.get('StreamArn', 'N/A')}")
                elif storage_type == 'KINESIS_DATA_FIREHOSE':
                    firehose_config = config.get('KinesisFirehoseConfig', {})
                    logger.debug(f"   Delivery Stream ARN: {firehose_config.get('DeliveryStreamArn', 'N/A')}")
                        
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                logger.error(f"   ⚠️  Could not retrieve storage config: {e.response['Error']['Message']}")
            
        # Get instance attribute - Auto resolve best effort
        try:
            attribute_response = connect_client.describe_instance_attribute(
                InstanceId=instance_id,
                AttributeType='AUTO_RESOLVE_BEST_EFFORT'
            )
            logger.debug(f"\n⚙️  INSTANCE ATTRIBUTES:")
            attribute = attribute_response.get('Attribute', {})
            logger.debug(f"   Auto Resolve Best Effort: {attribute.get('Value', 'N/A')}")
        except ClientError:
            pass  # Attribute might not be available
            
        # Try to get other common attributes
        attribute_types = [
            'INBOUND_CALLS',
            'OUTBOUND_CALLS', 
            'CONTACTFLOW_LOGS',
            'CONTACT_LENS',
            'USE_CUSTOM_TTS_VOICES'
        ]
            
        for attr_type in attribute_types:
            try:
                attr_response = self.connect_client.describe_instance_attribute(
                    InstanceId=instance_id,
                    AttributeType=attr_type
                )
                attribute = attr_response.get('Attribute', {})
                logger.debug(f"   {attr_type.replace('_', ' ').title()}: {attribute.get('Value', 'N/A')}")
            except ClientError:
                continue  # Skip if attribute is not available
                    
    except Exception as e:
        print(f"❌ Error retrieving instance attributes: {str(e)}")

#Get Amazon Connect log group
def get_connect_log_group(connect_instance_id):
    """
    Finds the Amazon Connect log group for a specific Connect instance.

    Args:
        connect_instance_id (str): The ID of the Amazon Connect instance.
        region_name (str): The AWS region where the Connect instance resides.

    Returns:
        str: The name of the Amazon Connect log group, or None if not found.
    """
    client = boto3.client('logs')

    paginator = client.get_paginator('describe_log_groups')
    response_iterator = paginator.paginate()

    for page in response_iterator:
        for log_group in page['logGroups']:
            log_group_name = log_group['logGroupName']
            # Look for log groups that contain the Connect instance ID in their name
            # This is a common pattern, but might need adjustment based on your specific setup.
            if f'/aws/connect/{connect_instance_id}' in log_group_name or \
               f'connect-{connect_instance_id}' in log_group_name: # Another possible pattern
                return log_group_name
    return None

class JSONSegregator:
    """A comprehensive class for segregating JSON data."""
    
    def __init__(self, data: List[Dict[str, Any]]):
        self.data = data
    
    def by_key(self, key: str, include_missing: bool = True) -> Dict[str, List[Dict]]:
        """Segregate by a single key."""
        result = defaultdict(list)
        
        for item in self.data:
            if key in item:
                value = str(item[key])  # Convert to string for consistent keys
                result[value].append(item)
            elif include_missing:
                result['_missing'].append(item)
        
        return dict(result)
    
    def by_value_range(self, key: str, ranges: List[tuple]) -> Dict[str, List[Dict]]:
        """Segregate by value ranges."""
        result = defaultdict(list)
        
        for item in self.data:
            if key in item:
                value = item[key]
                assigned = False
                
                for range_name, min_val, max_val in ranges:
                    if min_val <= value < max_val:
                        result[range_name].append(item)
                        assigned = True
                        break
                
                if not assigned:
                    result['_out_of_range'].append(item)
            else:
                result['_missing_key'].append(item)
        
        return dict(result)
    
    def by_custom_function(self, func) -> Dict[str, List[Dict]]:
        """Segregate using custom function."""
        result = defaultdict(list)
        
        for item in self.data:
            try:
                group_key = func(item)
                result[str(group_key)].append(item)
            except Exception as e:
                result[f'_error_{type(e).__name__}'].append(item)
        
        return dict(result)

def segregate_by_json_element(data, key):
    """
    Segregate data based on a specific JSON element/key.
    
    Args:
        data (list): List of dictionaries (JSON objects)
        key (str): The key to segregate by
    
    Returns:
        dict: Dictionary with segregated data
    """
    segregated = defaultdict(list)
    
    for item in data:
        if key in item:
            value = item[key]
            segregated[value].append(item)
        else:
            # Handle items without the key
            segregated['_missing_key'].append(item)
    
    return dict(segregated)

def segregate_by_multiple_criteria(data, criteria):
    """
    Segregate data based on multiple JSON elements.
    
    Args:
        data (list): List of dictionaries
        criteria (list): List of keys to create composite grouping
    
    Returns:
        dict: Dictionary with segregated data using composite keys
    """
    segregated = defaultdict(list)
    
    for item in data:
        # Create composite key from multiple criteria
        key_parts = []
        for criterion in criteria:
            if criterion in item:
                key_parts.append(str(item[criterion]))
            else:
                key_parts.append('_missing')
        
        composite_key = ' | '.join(key_parts)
        segregated[composite_key].append(item)
    
    return dict(segregated)

#Analyze CloudWatch Metrics - Concurrent Calls
def summarize_concurrent_calls(instance_id, days_back):
    """
    Summarize concurrent calls for Amazon Connect over the last 2 weeks
    """
    html_content = f"<b>Summarize concurrent calls for Amazon Connect over the last {days_back} days</b><br>"
    
    # Calculate time range for last 2 weeks
    end_time = datetime.utcnow() +  timedelta(days=1)
    start_time = end_time - timedelta(days=1)
    
    logger.debug(f"\n Retrieving concurrent calls data from {start_time.date()} to {end_time.date()}")
    
    try:
        # Get concurrent calls metrics
        response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/Connect',
            MetricName='ConcurrentCalls',
            Dimensions=[
                {'Name': 'InstanceId', 'Value': instance_id}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,  # 1-hour periods for detailed analysis
            Statistics=['Average', 'Maximum', 'Minimum']
        )
        
        # Process data by day
        daily_stats = defaultdict(lambda: {'hourly_avg': [], 'hourly_max': [], 'hourly_min': []})
        
        for datapoint in response['Datapoints']:
            date = datapoint['Timestamp'].date()
            daily_stats[date]['hourly_avg'].append(datapoint['Average'])
            daily_stats[date]['hourly_max'].append(datapoint['Maximum'])
            daily_stats[date]['hourly_min'].append(datapoint['Minimum'])
        
        # Calculate overall statistics
        all_averages = []
        all_maximums = []
        all_minimums = []
        
        logger.debug(f"\n{'='*60}")
        logger.debug(f"CONCURRENT CALLS SUMMARY - LAST 2 WEEKS")
        logger.debug(f"Instance ID: {instance_id}")
        logger.debug(f"{'='*60}")
        
        # Daily breakdown
        for date in sorted(daily_stats.keys()):
            stats = daily_stats[date]
            
            daily_avg = sum(stats['hourly_avg']) / len(stats['hourly_avg'])
            daily_max = max(stats['hourly_max'])
            daily_min = min(stats['hourly_min'])
            
            all_averages.extend(stats['hourly_avg'])
            all_maximums.extend(stats['hourly_max'])
            all_minimums.extend(stats['hourly_min'])
            
            logger.debug(f"\n{date.strftime('%A, %B %d, %Y')}:")
            logger.debug(f"  Daily Average: {daily_avg:.2f} calls")
            logger.debug(f"  Peak (Maximum): {daily_max:.0f} calls")
            logger.debug(f"  Lowest (Minimum): {daily_min:.0f} calls")
            logger.debug(f"  Data points: {len(stats['hourly_avg'])} hours")
        
        # Overall 2-week summary
        if all_averages:
            overall_avg = sum(all_averages) / len(all_averages)
            overall_max = max(all_maximums)
            overall_min = min(all_minimums)
            
            logger.debug(f"\n{'='*60}")
            logger.debug(f"OVERALL 2-WEEK SUMMARY")
            logger.debug(f"{'='*60}")
            html_content += f"<br>Period Average: {overall_avg:.2f} concurrent calls"
            html_content += f"<br>Absolute Peak: {overall_max:.0f} concurrent calls"
            html_content += f"<br>Absolute Minimum: {overall_min:.0f} concurrent calls"
            html_content += f"<br>Total data points: {len(all_averages)} hours"
            
            # Additional insights
            html_content += f"<br><br>INSIGHTS:"
            html_content += f"<br>- Average daily variation: {(overall_max - overall_min):.0f} calls"
            html_content += f"<br>- Peak utilization was {(overall_max / overall_avg - 1) * 100:.1f}% above average"
            
        else:
            html_content += f"<br>No data available for the specified time period."
            logger.debug("\nNo data available for the specified time period.")
            
    except Exception as e:
        logger.error(f"Error retrieving metrics: {str(e)}")
        html_content = f"\nError retrieving metrics: {str(e)}"

    return html_content

#Analyze CloudWatch Metrics - Missed Calls
def summarize_missed_calls(instance_id, days_back):
    """
    Comprehensive missed calls summary for Amazon Connect
    """
    html_content = f"<b>Summarize missed calls for Amazon Connect over the last {days_back} days</b><br>"

    # Calculate time range for last 2 weeks
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days_back)
    
    logger.debug(f"Retrieving missed calls data from {start_time.date()} to {end_time.date()}")
    logger.debug(f"Instance ID: {instance_id}")
    
    try:
        # Get missed calls metrics with daily granularity
        response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/Connect',
            MetricName='MissedCalls',
            Dimensions=[
                {'Name': 'InstanceId', 'Value': instance_id},
                {'Name': 'MetricGroup', 'Value': 'VoiceCalls'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,  # Daily statistics (24 hours)
            Statistics=['Sum']
        )
        
        # Process daily data
        daily_data = []
        total_missed_calls = 0
        
        for datapoint in sorted(response['Datapoints'], key=lambda x: x['Timestamp']):
            date = datapoint['Timestamp'].date()
            missed_calls = int(datapoint['Sum'])
            total_missed_calls += missed_calls
            daily_data.append((date, missed_calls))
        
        logger.debug(f"\n{'='*60}")
        logger.debug(f"MISSED CALLS SUMMARY - LAST 2 WEEKS")
        logger.debug(f"{'='*60}")
        
        # Daily breakdown
        logger.debug(f"\nDAILY BREAKDOWN:")
        logger.debug(f"{'-'*40}")
        for date, count in daily_data:
            day_name = date.strftime('%A')
            logger.debug(f"{date} ({day_name}): {count:,} missed calls")
        
        # Calculate statistics
        if daily_data:
            missed_calls_counts = [count for _, count in daily_data]
            daily_average = statistics.mean(missed_calls_counts)
            daily_median = statistics.median(missed_calls_counts)
            max_missed = max(missed_calls_counts)
            min_missed = min(missed_calls_counts)
            
            # Find peak day
            peak_day = max(daily_data, key=lambda x: x[1])
            
            logger.debug(f"\n{'='*60}")
            logger.debug(f"SUMMARY STATISTICS")
            logger.debug(f"{'='*60}")
            html_content+=f"<br>Total missed calls ({days_back}): {total_missed_calls:,}"
            html_content+=f"<br>Daily average: {daily_average:.1f} missed calls"
            html_content+=f"<br>Daily median: {daily_median:.1f} missed calls"
            html_content+=f"<br>Highest single day: {max_missed:,} missed calls"
            html_content+=f"<br>Lowest single day: {min_missed:,} missed calls"
            html_content+=f"<br>Peak day: {peak_day[0]} ({peak_day[0].strftime('%A')}) with {peak_day[1]:,} missed calls"
            
            # Weekly comparison
            week1_data = [count for date, count in daily_data if date < start_time.date() + timedelta(days=7)]
            week2_data = [count for date, count in daily_data if date >= start_time.date() + timedelta(days=7)]
            
            if week1_data and week2_data:
                week1_total = sum(week1_data)
                week2_total = sum(week2_data)
                week1_avg = statistics.mean(week1_data)
                week2_avg = statistics.mean(week2_data)
                
                change_percent = ((week2_total - week1_total) / week1_total) * 100 if week1_total > 0 else 0
                
                logger.debug(f"\n{'='*60}")
                logger.debug(f"WEEKLY COMPARISON")
                logger.debug(f"{'='*60}")
                logger.debug(f"Week 1 total: {week1_total:,} missed calls (avg: {week1_avg:.1f}/day)")
                logger.debug(f"Week 2 total: {week2_total:,} missed calls (avg: {week2_avg:.1f}/day)")
                logger.debug(f"Week-over-week change: {change_percent:+.1f}%")
                
                if change_percent > 10:
                    logger.debug("⚠️  Significant increase in missed calls detected!")
                elif change_percent < -10:
                    logger.debug("✅ Significant improvement in missed calls!")
        
        else:
            logger.debug("No missed calls data available for the specified time period.")
            html_content+=f"<br>No missed calls data available for the specified time period."
        return html_content
            
    except Exception as e:
        logger.error(f"Error retrieving metrics: {str(e)}")
        html_content+=f"<br>Error retrieving metrics: {str(e)}"

#Analyze CloudWatch Metrics - Throttled Calls
def summarize_throttled_calls(instance_id, days_back):
    """
    Comprehensive analysis of ThrottledCalls for Amazon Connect
    """
    html_content = f"<b>Summarize throttled calls for Amazon Connect over the last {days_back} days</b><br>"

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days_back)
    
    logger.debug(f"Analyzing ThrottledCalls from {start_time.date()} to {end_time.date()}")
    logger.debug(f"Instance ID: {instance_id}")
    
    try:
        # Get ThrottledCalls metrics
        response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/Connect',
            MetricName='ThrottledCalls',
            Dimensions=[
                {'Name': 'InstanceId', 'Value': instance_id},
                {'Name': 'MetricGroup', 'Value': 'VoiceCalls'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,  # 1-hour intervals
            Statistics=['Sum', 'Maximum']
        )
        
        datapoints = response['Datapoints']
        
        if not datapoints:
            logger.debug("✅ No throttled calls found in the specified time period!")
            logger.debug("This indicates your instance is operating within capacity limits.")
            html_content+=f"<br>No throttled calls found in the specified time period!"
            html_content+=f"<br>Your instance is operating well within capacity limits"
            return html_content
        
        # Sort datapoints by timestamp
        sorted_data = sorted(datapoints, key=lambda x: x['Timestamp'])
        
        logger.debug(f"\n{'='*70}")
        logger.debug(f"THROTTLED CALLS ANALYSIS - LAST {days_back} DAYS")
        logger.debug(f"{'='*70}")
        
        # Calculate overall statistics
        total_throttled = sum(int(dp['Sum']) for dp in sorted_data)
        hourly_counts = [int(dp['Sum']) for dp in sorted_data]
        max_hourly = max(hourly_counts)
        avg_hourly = statistics.mean(hourly_counts) if hourly_counts else 0
        
        logger.debug(f"\nOVERALL STATISTICS:")
        logger.debug(f"  Total throttled calls: {total_throttled:,}")
        logger.debug(f"  Average per hour: {avg_hourly:.2f}")
        logger.debug(f"  Maximum in single hour: {max_hourly:,}")
        logger.debug(f"  Hours with throttling: {len([c for c in hourly_counts if c > 0])}")
        logger.debug(f"  Total hours analyzed: {len(hourly_counts)}")
        
        # Severity assessment
        logger.debug(f"\nSEVERITY ASSESSMENT:")
        if total_throttled == 0:
            logger.debug("  ✅ EXCELLENT - No throttling detected")
        elif total_throttled < 10:
            logger.debug("  ⚠️  LOW - Minimal throttling (< 10 calls)")
        elif total_throttled < 100:
            logger.debug("  ⚠️  MODERATE - Some throttling detected (< 100 calls)")
        elif total_throttled < 1000:
            logger.debug("  ❌ HIGH - Significant throttling (< 1000 calls)")
        else:
            logger.debug("  🚨 CRITICAL - Severe throttling (> 1000 calls)")
            logger.debug("     IMMEDIATE ACTION REQUIRED!")
        
        # Daily breakdown
        daily_stats = defaultdict(int)
        for dp in sorted_data:
            date = dp['Timestamp'].date()
            daily_stats[date] += int(dp['Sum'])
        
        logger.debug(f"\nDAILY BREAKDOWN:")
        logger.debug(f"{'-'*50}")
        for date in sorted(daily_stats.keys()):
            count = daily_stats[date]
            day_name = date.strftime('%A')
            status = "🚨" if count > 100 else "⚠️" if count > 10 else "✅" if count == 0 else "⚠️"
            logger.debug(f"  {date} ({day_name}): {count:,} throttled calls {status}")
        
        # Peak hours analysis
        peak_hours = sorted(sorted_data, key=lambda x: x['Sum'], reverse=True)[:5]
        if peak_hours and peak_hours[0]['Sum'] > 0:
            logger.debug(f"\nTOP 5 PEAK THROTTLING HOURS:")
            logger.debug(f"{'-'*50}")
            for i, dp in enumerate(peak_hours, 1):
                if dp['Sum'] > 0:
                    timestamp = dp['Timestamp'].strftime('%Y-%m-%d %H:%M UTC')
                    print(f"  {i}. {timestamp}: {int(dp['Sum']):,} throttled calls")
        
        # Recommendations
        print(f"\n{'='*70}")
        print(f"RECOMMENDATIONS")
        print(f"{'='*70}")
        
        if total_throttled > 0:
            logger.debug("🔧 IMMEDIATE ACTIONS:")
            logger.debug("  1. Review current service quotas for your Connect instance")
            logger.debug("  2. Consider requesting quota increases via AWS Support")
            logger.debug("  3. Analyze call patterns during peak throttling periods")
            logger.debug("  4. Implement call queuing or retry mechanisms")
            
            logger.debug("\n📊 MONITORING IMPROVEMENTS:")
            logger.debug("  1. Set up CloudWatch alarms for ThrottledCalls metric")
            logger.debug("  2. Monitor ConcurrentCalls to predict throttling")
            logger.debug("  3. Track CallsPerInterval for capacity planning")
            
            logger.debug("\n⚡ CAPACITY OPTIMIZATION:")
            logger.debug("  1. Distribute call load across multiple instances if possible")
            logger.debug("  2. Implement intelligent call routing")
            logger.debug("  3. Consider auto-scaling strategies for peak periods")
        else:
            logger.debug("✅ Your instance is operating well within capacity limits!")
            logger.debug("   Continue monitoring to ensure consistent performance.")
            html_content+=f"Your instance is operating well within capacity limits"
            html_content+=f"Continue monitoring to ensure consistent performance."
        return html_content

    except Exception as e:
        logger.error(f"❌ Error retrieving ThrottledCalls metrics: {str(e)}")
        html_content+=f"<br>Error retrieving metrics: {str(e)}"

#Analyze CloudTrail Events for API Throttling
def lookup_connect_cloudtrail_events(account_id, days_back, aws_region):
    """
    Lookup CloudTrail events for Amazon Connect
    
    Args:
        instance_id (str): Connect instance ID (optional)
        days_back : days back for event lookup
        region (str): AWS region
    
    Returns:
        list: Connect CloudTrail events
    """
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24*days_back)
    
    logger.debug(f"📅 Start Time for lookup_connect_cloudtrail_events: {start_time}")
    logger.debug(f"📅 End Time for lookup_connect_cloudtrail_events: {end_time}")

    connect_events = []
    
    try:
        # Lookup attributes for Connect events
        lookup_attributes = [
            {
                'AttributeKey': 'EventSource',
                'AttributeValue': 'connect.amazonaws.com'
            }
        ]
        
        # Add instance-specific filter if provided
       # if instance_id:
       #     lookup_attributes.append({
       #         'AttributeKey': 'ResourceName',
       #         'AttributeValue': instance_id
       #     })
        
        # Lookup events
        paginator = cloudtrail_client.get_paginator('lookup_events')
        
        for page in paginator.paginate(
            LookupAttributes=lookup_attributes,
            StartTime=start_time,
            EndTime=end_time
        ):
            for event in page['Events']:
                # Parse and enrich event data
                event_data = parse_connect_event(event)
                if event_data:
                    connect_events.append(event_data)
        
        return connect_events
        
    except ClientError as e:
        logger.debug(f"Error looking up CloudTrail events: {e}")
        return []

#Parse CloudTrail events to extract key information
def parse_connect_event(event):
    """Parse and enrich Connect CloudTrail event"""
    
    try:
        cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
        
        # Extract key information
        event_data = {
            'eventId': event.get('EventId'),
            'eventName': event.get('EventName'),
            'eventTime': event.get('EventTime'),
            'username': event.get('Username'),
            'eventSource': cloud_trail_event.get('eventSource'),
            'awsRegion': cloud_trail_event.get('awsRegion'),
            'sourceIPAddress': cloud_trail_event.get('sourceIPAddress'),
            'userAgent': cloud_trail_event.get('userAgent'),
            'requestId': cloud_trail_event.get('requestID'),
            'userIdentity': cloud_trail_event.get('userIdentity', {}),
           # 'requestParameters': cloud_trail_event.get('requestParameters', {}),
           # 'response_elements': cloud_trail_event.get('responseElements', {}),
            'errorCode': cloud_trail_event.get('errorCode'),
            'errorMessage': cloud_trail_event.get('errorMessage')
        }

        return event_data
        
    except Exception as e:
        print(f"Error parsing event: {e}")
        return None

def summarize_amazon_api_throttles(instance_id, account_id, days_back, aws_region):

    html_content = f"<b>Summarize throttled calls for Amazon Connect over the last {days_back} days</b><br>"

    try:
        # Get events from last days_back days
        events = lookup_connect_cloudtrail_events(account_id, days_back, aws_region)

        html_content += f"""Found {len(events)} Amazon Connect events to be compared during that time-period."""

        # Use a defaultdict to store counts for each category
        category_counts = defaultdict(int)
        category = ""
        total_throttled_count = 0

        # Iterate through the data and count by category
        for item in events:
            category = item.get("eventName")

            if item.get("errorCode") == 'TooManyRequestsException' and item.get("awsRegion") == aws_region:
                category_counts[category] += 1
                logger.debug(f"Found {category} and add to this seggregated counts")
                total_throttled_count += 1

        ## Summary of the output
        html_content += f"""<br>Found {total_throttled_count} Amazon Connect events which are being throttled over last {days_back} days.."""

        html_content += f"""<br><br>List of events which were throttled in for account - {account_id} in region - {aws_region}<br>"""

        # Print the segregated counts
        html_content += f"""
                    <table style="width: 50%">
                    <tr><th>Event Name</th><th>Throttle Count</th></tr>"""

        for category, count in category_counts.items():
            html_content += f"""<tr><td>{category}</td><td>{count}</td></tr>"""
            
        html_content += f"""
            </table>
            """
        return html_content

    except Exception as e:
        logger.error(f"❌ Error retrieving Amazon Connect API throttling metrics: {str(e)}")
        html_content+=f"<br>Error retrieving Amazon Connect API throttling summary.Check the logs"