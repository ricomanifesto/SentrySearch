"""
S3 storage manager for SentrySearch report content
"""
import os
import boto3
from botocore.exceptions import ClientError
import logging
from typing import Optional, Dict, Any
import json
from datetime import datetime

logger = logging.getLogger(__name__)

# Try to load environment variables if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class S3StorageManager:
    def __init__(self):
        self.bucket_name = os.getenv('AWS_S3_BUCKET', 'sentrysearch-reports')
        self.region = os.getenv('AWS_REGION', 'us-east-1')
        self.s3_client = None
        self._initialized = False
    
    def _ensure_initialized(self):
        """Ensure S3 client is initialized (lazy initialization)"""
        if not self._initialized:
            self._initialize_client()
            self._initialized = True
    
    def _initialize_client(self):
        """Initialize S3 client with credentials from environment"""
        try:
            access_key = os.getenv('AWS_ACCESS_KEY_ID')
            secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            
            if not access_key or not secret_key:
                logger.warning(f"AWS credentials not found. ACCESS_KEY: {'set' if access_key else 'not set'}, SECRET_KEY: {'set' if secret_key else 'not set'}")
                logger.warning("S3 storage will be disabled")
                self.s3_client = None
                return
            
            # AWS credentials from environment variables or IAM role
            self.s3_client = boto3.client(
                's3',
                region_name=self.region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            logger.info(f"S3 client initialized for bucket: {self.bucket_name} in region: {self.region}")
        except Exception as e:
            logger.warning(f"Error initializing S3 client: {e}")
            logger.warning("S3 storage will be disabled")
            self.s3_client = None
    
    def create_bucket_if_not_exists(self):
        """Create S3 bucket if it doesn't exist"""
        try:
            # Check if bucket exists
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            logger.info(f"Bucket {self.bucket_name} already exists")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                # Bucket doesn't exist, create it
                try:
                    if self.region == 'us-east-1':
                        self.s3_client.create_bucket(Bucket=self.bucket_name)
                    else:
                        self.s3_client.create_bucket(
                            Bucket=self.bucket_name,
                            CreateBucketConfiguration={'LocationConstraint': self.region}
                        )
                    
                    # Set bucket versioning
                    self.s3_client.put_bucket_versioning(
                        Bucket=self.bucket_name,
                        VersioningConfiguration={'Status': 'Enabled'}
                    )
                    
                    logger.info(f"Created S3 bucket: {self.bucket_name}")
                except ClientError as create_error:
                    logger.error(f"Error creating bucket: {create_error}")
                    raise
            else:
                logger.error(f"Error checking bucket: {e}")
                raise
    
    def upload_markdown_report(self, report_id: str, markdown_content: str) -> str:
        """Upload markdown report content to S3"""
        self._ensure_initialized()
        if not self.s3_client:
            logger.warning("S3 client not available, skipping upload")
            return None
            
        key = f"reports/{report_id}/report.md"
        
        try:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=markdown_content.encode('utf-8'),
                ContentType='text/markdown',
                Metadata={
                    'report_id': report_id,
                    'uploaded_at': datetime.utcnow().isoformat(),
                    'content_type': 'markdown_report'
                }
            )
            logger.info(f"Uploaded markdown report: {key}")
            return key
        except ClientError as e:
            logger.error(f"Error uploading markdown report: {e}")
            raise
    
    def upload_trace_data(self, report_id: str, trace_data: Dict[Any, Any]) -> str:
        """Upload trace data to S3"""
        self._ensure_initialized()
        if not self.s3_client:
            logger.warning("S3 client not available, skipping upload")
            return None
            
        key = f"reports/{report_id}/trace.json"
        
        try:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=json.dumps(trace_data, indent=2).encode('utf-8'),
                ContentType='application/json',
                Metadata={
                    'report_id': report_id,
                    'uploaded_at': datetime.utcnow().isoformat(),
                    'content_type': 'trace_data'
                }
            )
            logger.info(f"Uploaded trace data: {key}")
            return key
        except ClientError as e:
            logger.error(f"Error uploading trace data: {e}")
            raise
    
    def download_content(self, s3_key: str) -> str:
        """Download content from S3"""
        self._ensure_initialized()
        if not self.s3_client:
            logger.warning("S3 client not available, cannot download")
            return ""
            
        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            content = response['Body'].read().decode('utf-8')
            logger.info(f"Downloaded content: {s3_key}")
            return content
        except ClientError as e:
            logger.error(f"Error downloading content: {e}")
            raise
    
    def get_presigned_url(self, s3_key: str, expiration: int = 3600) -> str:
        """Generate presigned URL for temporary access"""
        self._ensure_initialized()
        if not self.s3_client:
            logger.warning("S3 client not available, cannot generate presigned URL")
            return ""
            
        try:
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket_name, 'Key': s3_key},
                ExpiresIn=expiration
            )
            return url
        except ClientError as e:
            logger.error(f"Error generating presigned URL: {e}")
            raise
    
    def delete_report_files(self, report_id: str):
        """Delete all files for a report"""
        self._ensure_initialized()
        if not self.s3_client:
            logger.warning("S3 client not available, cannot delete files")
            return
            
        try:
            # List all objects with the report prefix
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=f"reports/{report_id}/"
            )
            
            if 'Contents' in response:
                # Delete all objects
                objects_to_delete = [{'Key': obj['Key']} for obj in response['Contents']]
                self.s3_client.delete_objects(
                    Bucket=self.bucket_name,
                    Delete={'Objects': objects_to_delete}
                )
                logger.info(f"Deleted {len(objects_to_delete)} files for report: {report_id}")
            else:
                logger.info(f"No files found for report: {report_id}")
        except ClientError as e:
            logger.error(f"Error deleting report files: {e}")
            raise
    
    def list_report_files(self, report_id: str) -> list:
        """List all files for a report"""
        self._ensure_initialized()
        if not self.s3_client:
            logger.warning("S3 client not available, cannot list files")
            return []
            
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=f"reports/{report_id}/"
            )
            
            if 'Contents' in response:
                return [obj['Key'] for obj in response['Contents']]
            else:
                return []
        except ClientError as e:
            logger.error(f"Error listing report files: {e}")
            raise

# Global S3 storage manager instance
s3_manager = S3StorageManager()