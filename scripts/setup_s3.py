#!/usr/bin/env python3
"""
S3 setup script for SentrySearch
Creates bucket and tests connectivity
"""
import os
import sys
from pathlib import Path
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import logging

# Add src to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_aws_credentials():
    """Get AWS credentials from environment or prompt user"""
    access_key = os.getenv('AWS_ACCESS_KEY_ID')
    secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    region = os.getenv('AWS_REGION', 'us-east-1')
    bucket_name = os.getenv('S3_BUCKET_NAME', 'sentrysearch-reports')
    
    if not access_key or not secret_key:
        logger.info("AWS credentials not found in environment variables")
        logger.info("You have several options:")
        logger.info("1. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env file")
        logger.info("2. Configure AWS CLI: aws configure")
        logger.info("3. Use IAM roles (for EC2/ECS deployment)")
        logger.info("4. Use LocalStack for local development")
        
        choice = input("\nWould you like to:\n1. Enter credentials manually\n2. Use LocalStack (local S3)\n3. Skip S3 setup for now\nChoose (1/2/3): ")
        
        if choice == "1":
            access_key = input("Enter AWS Access Key ID: ").strip()
            secret_key = input("Enter AWS Secret Access Key: ").strip()
            region = input(f"Enter AWS Region (default: {region}): ").strip() or region
            bucket_name = input(f"Enter S3 Bucket Name (default: {bucket_name}): ").strip() or bucket_name
        elif choice == "2":
            access_key = "test"
            secret_key = "test"
            region = "us-east-1"
            bucket_name = "sentrysearch-reports"
            return access_key, secret_key, region, bucket_name, True  # LocalStack flag
        else:
            logger.info("Skipping S3 setup. You can configure it later.")
            return None, None, None, None, False
    
    return access_key, secret_key, region, bucket_name, False

def create_s3_client(access_key, secret_key, region, use_localstack=False):
    """Create S3 client with given credentials"""
    try:
        if use_localstack:
            # LocalStack configuration
            s3_client = boto3.client(
                's3',
                endpoint_url='http://localhost:4566',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            logger.info("Created LocalStack S3 client")
        else:
            # AWS S3 configuration
            s3_client = boto3.client(
                's3',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            logger.info("Created AWS S3 client")
        
        return s3_client
    except Exception as e:
        logger.error(f"Failed to create S3 client: {e}")
        return None

def create_bucket(s3_client, bucket_name, region):
    """Create S3 bucket if it doesn't exist"""
    try:
        # Check if bucket exists
        s3_client.head_bucket(Bucket=bucket_name)
        logger.info(f"Bucket '{bucket_name}' already exists")
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            # Bucket doesn't exist, create it
            try:
                if region == 'us-east-1':
                    # us-east-1 doesn't need LocationConstraint
                    s3_client.create_bucket(Bucket=bucket_name)
                else:
                    s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={'LocationConstraint': region}
                    )
                logger.info(f"Created bucket '{bucket_name}' in region '{region}'")
                return True
            except ClientError as create_error:
                logger.error(f"Failed to create bucket: {create_error}")
                return False
        else:
            logger.error(f"Error checking bucket: {e}")
            return False

def test_s3_operations(s3_client, bucket_name):
    """Test basic S3 operations"""
    try:
        # Test upload
        test_content = "SentrySearch S3 Test File"
        test_key = "test/connectivity-test.txt"
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key=test_key,
            Body=test_content,
            ContentType='text/plain'
        )
        logger.info("✓ S3 upload test successful")
        
        # Test download
        response = s3_client.get_object(Bucket=bucket_name, Key=test_key)
        downloaded_content = response['Body'].read().decode('utf-8')
        
        if downloaded_content == test_content:
            logger.info("✓ S3 download test successful")
        else:
            logger.error("✗ S3 download test failed - content mismatch")
            return False
        
        # Test delete
        s3_client.delete_object(Bucket=bucket_name, Key=test_key)
        logger.info("✓ S3 delete test successful")
        
        # Test presigned URL generation
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': 'test/sample.txt'},
            ExpiresIn=3600
        )
        if url:
            logger.info("✓ S3 presigned URL generation successful")
        
        return True
        
    except Exception as e:
        logger.error(f"S3 operations test failed: {e}")
        return False

def update_env_file(access_key, secret_key, region, bucket_name, use_localstack=False):
    """Update .env file with S3 configuration"""
    env_path = project_root / ".env"
    
    try:
        # Read current .env content
        if env_path.exists():
            with open(env_path, 'r') as f:
                lines = f.readlines()
        else:
            lines = []
        
        # Update S3 configuration
        s3_config = {
            'AWS_ACCESS_KEY_ID': access_key,
            'AWS_SECRET_ACCESS_KEY': secret_key,
            'AWS_REGION': region,
            'S3_BUCKET_NAME': bucket_name,
        }
        
        if use_localstack:
            s3_config['AWS_ENDPOINT_URL'] = 'http://localhost:4566'
        
        # Update or add configuration lines
        updated_lines = []
        config_keys = set(s3_config.keys())
        
        for line in lines:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key = line.split('=')[0].strip()
                if key in config_keys:
                    updated_lines.append(f"{key}={s3_config[key]}\n")
                    config_keys.remove(key)
                else:
                    updated_lines.append(line + '\n')
            else:
                updated_lines.append(line + '\n')
        
        # Add new configuration keys
        if config_keys:
            updated_lines.append('\n# S3 Configuration\n')
            for key in config_keys:
                updated_lines.append(f"{key}={s3_config[key]}\n")
        
        # Write updated .env file
        with open(env_path, 'w') as f:
            f.writelines(updated_lines)
        
        logger.info(f"Updated .env file with S3 configuration")
        
    except Exception as e:
        logger.error(f"Failed to update .env file: {e}")

def main():
    """Main S3 setup function"""
    logger.info("Setting up S3 for SentrySearch...")
    
    # Get AWS credentials
    access_key, secret_key, region, bucket_name, use_localstack = get_aws_credentials()
    
    if not access_key:
        logger.info("S3 setup skipped")
        return True
    
    # Create S3 client
    s3_client = create_s3_client(access_key, secret_key, region, use_localstack)
    if not s3_client:
        return False
    
    # Create bucket
    if not create_bucket(s3_client, bucket_name, region):
        return False
    
    # Test S3 operations
    if not test_s3_operations(s3_client, bucket_name):
        return False
    
    # Update .env file
    update_env_file(access_key, secret_key, region, bucket_name, use_localstack)
    
    logger.info("✅ S3 setup completed successfully!")
    logger.info(f"Bucket: {bucket_name}")
    logger.info(f"Region: {region}")
    
    if use_localstack:
        logger.info("Note: Using LocalStack for local development")
        logger.info("Start LocalStack with: docker run --rm -it -p 4566:4566 localstack/localstack")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)