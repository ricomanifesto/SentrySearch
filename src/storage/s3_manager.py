"""
S3 storage manager for SentrySearch report content
"""

import os
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
from .config import is_deployed
import logging
from typing import Dict, Any
import json
import hashlib
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Try to load environment variables if available
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


class S3StorageManager:
    def __init__(self):
        self.bucket_name = os.getenv("AWS_S3_BUCKET", "sentrysearch-reports")
        self.region = os.getenv("AWS_REGION", "us-east-1")
        self.s3_client = None
        self._initialized = False

    def _ensure_initialized(self):
        """Ensure S3 client is initialized (lazy initialization)"""
        if not self._initialized:
            self._initialize_client()
            self._initialized = True
        if self.s3_client is None:
            raise RuntimeError("Artifact storage unavailable; verify bucket and SDK credentials")

    def require_available(self) -> None:
        """Resolve SDK credentials, not bucket permissions or live object access."""
        self._ensure_initialized()

    def _initialize_client(self):
        """Keep credential resolution and refresh owned by the SDK session."""
        try:
            if not self.bucket_name or (is_deployed() and not os.getenv("AWS_S3_BUCKET")):
                raise ValueError("Explicit artifact bucket required")
            session = boto3.Session()
            credentials = session.get_credentials()
            if credentials is None:
                raise ValueError("No SDK credentials available")
            # Resolve deferred role credentials once before admitting work. Do
            # not pass this snapshot to the client: the session retains refresh.
            resolved = credentials.get_frozen_credentials()
            if not resolved.access_key or not resolved.secret_key:
                raise ValueError("Incomplete SDK credentials")
            self.s3_client = session.client(
                "s3",
                region_name=self.region,
                config=Config(
                    connect_timeout=5,
                    read_timeout=30,
                    retries={"mode": "standard", "total_max_attempts": 3},
                ),
            )
            logger.info("Artifact client initialized using SDK credential provider chain")
        except Exception:
            self.s3_client = None
            logger.warning("Artifact storage initialization failed")
            raise RuntimeError(
                "Artifact storage unavailable; verify bucket and SDK credentials"
            ) from None

    def upload_markdown_report(self, report_id: str, markdown_content: str) -> str:
        """Upload markdown report content to S3"""
        self._ensure_initialized()
        assert self.s3_client is not None

        content = markdown_content.encode("utf-8")
        key = f"reports/{report_id}/artifacts/{hashlib.sha256(content).hexdigest()}.md"

        try:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=content,
                ContentType="text/markdown",
                Metadata={
                    "report_id": report_id,
                    "uploaded_at": datetime.now(timezone.utc).isoformat(),
                    "content_type": "markdown_report",
                },
            )
            logger.info(f"Uploaded markdown report: {key}")
            return key
        except ClientError as e:
            logger.error(f"Error uploading markdown report: {e}")
            raise

    def upload_trace_data(self, report_id: str, trace_data: Dict[Any, Any]) -> str:
        """Upload trace data to S3"""
        self._ensure_initialized()
        assert self.s3_client is not None

        content = json.dumps(trace_data, indent=2, sort_keys=True).encode("utf-8")
        key = f"reports/{report_id}/artifacts/{hashlib.sha256(content).hexdigest()}.json"

        try:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=content,
                ContentType="application/json",
                Metadata={
                    "report_id": report_id,
                    "uploaded_at": datetime.now(timezone.utc).isoformat(),
                    "content_type": "trace_data",
                },
            )
            logger.info(f"Uploaded trace data: {key}")
            return key
        except ClientError as e:
            logger.error(f"Error uploading trace data: {e}")
            raise

    def download_content(self, s3_key: str) -> str:
        """Download content from S3"""
        self._ensure_initialized()
        assert self.s3_client is not None

        try:
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=s3_key)
            content = response["Body"].read().decode("utf-8")
            logger.info(f"Downloaded content: {s3_key}")
            return content
        except ClientError as e:
            logger.error(f"Error downloading content: {e}")
            raise

    def get_presigned_url(self, s3_key: str, expiration: int = 3600) -> str:
        """Generate presigned URL for temporary access"""
        self._ensure_initialized()
        assert self.s3_client is not None

        try:
            url = self.s3_client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket_name, "Key": s3_key},
                ExpiresIn=expiration,
            )
            return url
        except ClientError as e:
            logger.error(f"Error generating presigned URL: {e}")
            raise

    def delete_report_files(self, report_id: str):
        """Delete all files for a report"""
        self._ensure_initialized()
        assert self.s3_client is not None

        try:
            # List all objects with the report prefix
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name, Prefix=f"reports/{report_id}/"
            )

            if "Contents" in response:
                # Delete all objects
                objects_to_delete = [{"Key": obj["Key"]} for obj in response["Contents"]]
                self.s3_client.delete_objects(
                    Bucket=self.bucket_name, Delete={"Objects": objects_to_delete}
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
        assert self.s3_client is not None

        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name, Prefix=f"reports/{report_id}/"
            )

            if "Contents" in response:
                return [obj["Key"] for obj in response["Contents"]]
            else:
                return []
        except ClientError as e:
            logger.error(f"Error listing report files: {e}")
            raise


# Global S3 storage manager instance
s3_manager = S3StorageManager()
