from datetime import UTC, datetime
from keyholderd.providers.aws_sts import AwsStsProvider


def test_aws_sts_assume_role_receives_policy_values(monkeypatch):
    calls = []
    class STS:
        def assume_role(self, **kwargs):
            calls.append(kwargs)
            return {"Credentials": {"AccessKeyId":"AKIA", "SecretAccessKey":"SECRET", "SessionToken":"SESSION", "Expiration": datetime(2030,1,1,tzinfo=UTC)}}
    class Session:
        def __init__(self, **kwargs): self.kwargs = kwargs
        def client(self, service): assert service == "sts"; return STS()
    monkeypatch.setattr("keyholderd.providers.aws_sts.boto3.Session", Session)
    grant = {"name":"aws", "role_arn":"arn:aws:iam::1:role/demo", "external_id":"ext", "session_tags":{"app":"hermes"}}
    cred = AwsStsProvider().issue(grant, {"aws_access_key_id":"SRC", "aws_secret_access_key":"SRCSECRET"}, 900)
    assert calls[0]["RoleArn"] == grant["role_arn"]
    assert calls[0]["ExternalId"] == "ext"
    assert calls[0]["Tags"] == [{"Key":"app", "Value":"hermes"}]
    assert calls[0]["DurationSeconds"] == 900
    assert cred.env["AWS_ACCESS_KEY_ID"] == "AKIA"
    assert cred.env["AWS_SECRET_ACCESS_KEY"] == "SECRET"
    assert cred.display_token is None
