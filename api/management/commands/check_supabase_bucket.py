import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Connect to the Supabase S3 bucket from env/settings and verify access."

    def add_arguments(self, parser):
        parser.add_argument(
            "--bucket",
            default=None,
            help="Override the bucket name. Defaults to SUPABASE_S3_BUCKET/AWS_STORAGE_BUCKET_NAME.",
        )
        parser.add_argument(
            "--prefix",
            default="",
            help="Optional key prefix to inspect.",
        )
        parser.add_argument(
            "--max-keys",
            type=int,
            default=5,
            help="How many keys to list when testing access.",
        )
        parser.add_argument(
            "--folders-only",
            action="store_true",
            help="List folder prefixes under the given prefix instead of object keys.",
        )

    def handle(self, *args, **options):
        endpoint = os.getenv("SUPABASE_S3_ENDPOINT") or getattr(settings, "AWS_S3_ENDPOINT_URL", None)
        access_key = os.getenv("SUPABASE_S3_ACCESS_KEY") or getattr(settings, "AWS_ACCESS_KEY_ID", None)
        secret_key = os.getenv("SUPABASE_S3_SECRET_KEY") or getattr(settings, "AWS_SECRET_ACCESS_KEY", None)
        region = os.getenv("SUPABASE_S3_REGION", getattr(settings, "AWS_S3_REGION_NAME", "us-east-1"))
        bucket = options["bucket"] or os.getenv("SUPABASE_S3_BUCKET") or getattr(settings, "AWS_STORAGE_BUCKET_NAME", None)

        missing = [
            name
            for name, value in (
                ("SUPABASE_S3_ENDPOINT", endpoint),
                ("SUPABASE_S3_ACCESS_KEY", access_key),
                ("SUPABASE_S3_SECRET_KEY", secret_key),
                ("SUPABASE_S3_BUCKET", bucket),
            )
            if not value
        ]
        if missing:
            raise CommandError(f"Missing Supabase S3 configuration: {', '.join(missing)}")

        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )

        self.stdout.write(self.style.WARNING(f"Endpoint: {endpoint}"))
        self.stdout.write(self.style.WARNING(f"Bucket: {bucket}"))
        self.stdout.write(self.style.WARNING(f"Region: {region}"))

        try:
            request = {
                "Bucket": bucket,
                "Prefix": options["prefix"],
                "MaxKeys": max(options["max_keys"], 1),
            }
            if options["folders_only"]:
                request["Delimiter"] = "/"

            response = client.list_objects_v2(**request)
        except (ClientError, BotoCoreError) as exc:
            raise CommandError(f"Supabase bucket connection failed: {exc}") from exc

        if options["folders_only"]:
            folders = [item["Prefix"] for item in response.get("CommonPrefixes", [])]
            self.stdout.write(
                self.style.SUCCESS(
                    f"Connected to bucket '{bucket}'. Folder count returned: {len(folders)}"
                )
            )
            if not folders:
                self.stdout.write("No folders returned for the requested prefix.")
                return

            for folder in folders:
                self.stdout.write(f" - {folder}")
            return

        contents = response.get("Contents", [])
        self.stdout.write(
            self.style.SUCCESS(
                f"Connected to bucket '{bucket}'. Key count returned: {len(contents)}"
            )
        )
        if not contents:
            self.stdout.write("No objects returned for the requested prefix.")
            return

        for obj in contents:
            self.stdout.write(f" - {obj['Key']}")
