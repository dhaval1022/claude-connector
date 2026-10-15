"""AWS S3 storage for uploaded files and databases."""
import asyncio
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from app.config import get_settings


def is_s3_configured() -> bool:
    s = get_settings()
    return bool(s.aws_bucket_name and s.aws_bucket_name.strip())


def get_s3_client():
    s = get_settings()
    kwargs = {}
    if s.aws_access_key_id and s.aws_secret_access_key:
        kwargs["aws_access_key_id"] = s.aws_access_key_id
        kwargs["aws_secret_access_key"] = s.aws_secret_access_key
    if s.aws_region:
        kwargs["region_name"] = s.aws_region
    return boto3.client("s3", **kwargs)


def upload_file_to_s3_sync(local_path: Path, s3_key: str) -> None:
    s = get_settings()
    client = get_s3_client()
    client.upload_file(str(local_path), s.aws_bucket_name, s3_key)


async def upload_file_to_s3(local_path: Path, s3_key: str) -> None:
    await asyncio.to_thread(upload_file_to_s3_sync, local_path, s3_key)


def download_file_from_s3_sync(s3_key: str, local_path: Path) -> bool:
    s = get_settings()
    client = get_s3_client()
    local_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        client.download_file(s.aws_bucket_name, s3_key, str(local_path))
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey"):
            return False
        raise


async def download_file_from_s3(s3_key: str, local_path: Path) -> bool:
    return await asyncio.to_thread(download_file_from_s3_sync, s3_key, local_path)


def delete_s3_prefix_sync(s3_prefix: str) -> None:
    s = get_settings()
    client = get_s3_client()
    paginator = client.get_paginator("list_objects_v2")
    to_delete = []
    for page in paginator.paginate(Bucket=s.aws_bucket_name, Prefix=s3_prefix):
        for obj in page.get("Contents", []):
            to_delete.append({"Key": obj["Key"]})
    if to_delete:
        client.delete_objects(Bucket=s.aws_bucket_name, Delete={"Objects": to_delete})


async def delete_s3_prefix(s3_prefix: str) -> None:
    await asyncio.to_thread(delete_s3_prefix_sync, s3_prefix)
