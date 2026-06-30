from __future__ import annotations

from datetime import UTC, datetime

import boto3

from .base import IssuedCredential


class AwsStsProvider:
    name = "aws_sts"

    def issue(self, grant: dict, secrets: dict[str, str], ttl_seconds: int) -> IssuedCredential:
        session = boto3.Session(
            aws_access_key_id=secrets["aws_access_key_id"],
            aws_secret_access_key=secrets["aws_secret_access_key"],
        )
        tags = [{"Key": k, "Value": str(v)} for k, v in grant.get("session_tags", {}).items()]
        kwargs = {
            "RoleArn": grant["role_arn"],
            "RoleSessionName": f"keyholder-{grant.get('name', 'grant')}",
            "DurationSeconds": ttl_seconds,
        }
        if grant.get("external_id"):
            kwargs["ExternalId"] = grant["external_id"]
        if tags:
            kwargs["Tags"] = tags
        resp = session.client("sts").assume_role(**kwargs)
        creds = resp["Credentials"]
        expiration = creds["Expiration"]
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=UTC)
        return IssuedCredential(
            provider=self.name,
            token_type="aws_sts",
            env={
                "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
                "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
                "AWS_SESSION_TOKEN": creds["SessionToken"],
            },
            display_token=None,
            expires_at=expiration,
            scope_summary=grant["role_arn"],
        )
