"""Providers: per-service knowledge, one declarative table (ADR-0011).

A Provider is a storage service carryon knows how to set a Remote up for -
which handful of fields that service needs, and nothing else about it. The
table holds that knowledge the way `adapters/` holds per-agent knowledge, so
the engine keeps no Provider branches: knowing a Provider is not speaking
its protocol, rclone does that.

Two kinds of entry in `fields`, told apart by which attribute is set. A
field with a `question` is asked, and its answer normally becomes one
`key=value` for `rclone config create`; a field with `derive` is computed
from the other answers instead - R2's endpoint is its account ID wearing a
URL, and AWS's location constraint is its region except for the one region
AWS spells by leaving it out. An asked field whose key starts with '_' only
feeds derivations and never reaches rclone.

rclone's own full Provider list, for anything this table does not name, is
a later addition rather than part of this (ADR-0011).

One knowledge item here took reading rclone's backends to learn, and the
table is shaped around it: rclone's UPLOAD path creates a missing bucket
(s3's prepareUpload and gcs's Update both reach makeBucket), which would
have had the reachability probe create the very bucket the user had just
declined to create. So the S3-family and GCS entries pin
`no_check_bucket=true` in the Remote's config - an upload to a missing
bucket then fails, which the probe reports as the refusal it is - and their
`mkdir_flags` switch the check back on for the one call that IS the offered
creation. Backblaze B2's upload creates the bucket unconditionally and has
no such option, so B2 is not in this table: it would ship with "never
create a billable resource silently" quietly false.
"""

from __future__ import annotations

from typing import Callable, NamedTuple, Optional, Tuple


class Field(NamedTuple):
    """One thing a Provider needs: asked of the user, or derived."""

    key: str                                # the rclone config key, or _fed
    question: Optional[str] = None          # asked when set
    secret: bool = False                    # asked without echo, never shown
    default: Optional[str] = None
    derive: Optional[Callable] = None       # answers dict -> value


class Provider(NamedTuple):
    key: str            # short name in the menu and in tests
    name: str           # the line the user picks
    rclone_type: str    # rclone's TYPE argument
    fixed: Tuple        # ((key, value), ...) - true of every account
    fields: Tuple       # (Field, ...)
    place: str          # what the path half of the spec is called
    place_question: str
    place_costs: bool   # True when creating one is a billable resource
    mkdir_flags: Tuple = ()  # what `rclone mkdir` needs on top of the config


def _r2_endpoint(answers: dict) -> str:
    return f"https://{answers['_account_id']}.r2.cloudflarestorage.com"


def _aws_location(answers: dict) -> str:
    # Used when creating buckets only, and us-east-1 is spelled by leaving
    # it out - rclone's own config flow says "Empty for US Region".
    region = answers.get("region", "")
    return "" if region == "us-east-1" else region


PROVIDERS = (
    Provider(
        key="r2",
        name="Cloudflare R2 (S3-compatible; no egress fees)",
        rclone_type="s3",
        # no_check_bucket also happens to be what R2's own docs recommend
        # for tokens scoped to one bucket.
        fixed=(("provider", "Cloudflare"), ("region", "auto"),
               ("acl", "private"), ("no_check_bucket", "true")),
        fields=(
            Field("_account_id", "Cloudflare account ID"),
            Field("access_key_id", "R2 access key ID"),
            Field("secret_access_key", "R2 secret access key", secret=True),
            Field("endpoint", derive=_r2_endpoint),
        ),
        place="bucket",
        place_question="R2 bucket for the Archive",
        place_costs=True,
        mkdir_flags=("--s3-no-check-bucket=false",),
    ),
    Provider(
        key="s3",
        name="Amazon S3",
        rclone_type="s3",
        fixed=(("provider", "AWS"), ("no_check_bucket", "true")),
        fields=(
            Field("access_key_id", "AWS access key ID"),
            Field("secret_access_key", "AWS secret access key", secret=True),
            Field("region", "Region", default="us-east-1"),
            Field("location_constraint", derive=_aws_location),
        ),
        place="bucket",
        place_question="S3 bucket for the Archive",
        place_costs=True,
        mkdir_flags=("--s3-no-check-bucket=false",),
    ),
    Provider(
        key="gcs",
        name="Google Cloud Storage",
        rclone_type="google cloud storage",
        fixed=(("no_check_bucket", "true"),),
        fields=(
            Field("service_account_file",
                  "Path to a service account JSON file"),
            Field("project_number",
                  "Project number (rclone needs it to create a bucket)"),
        ),
        place="bucket",
        place_question="GCS bucket for the Archive",
        place_costs=True,
        mkdir_flags=("--gcs-no-check-bucket=false",),
    ),
    Provider(
        key="sftp",
        name="SFTP (any machine you can ssh to)",
        rclone_type="sftp",
        fixed=(),
        # No credential fields on purpose: ssh-agent is the ordinary way in,
        # and rclone falls back to it when pass and key_file are unset.
        fields=(
            Field("host", "SSH host"),
            Field("user", "SSH user"),
        ),
        place="directory",
        place_question="Directory on that machine for the Archive",
        place_costs=False,
    ),
)


def config_pairs(provider: Provider, answers: dict) -> list:
    """The (key, value) pairs `rclone config create` gets for this account.

    Fixed pairs first, then every answered or derived field - minus the
    '_'-prefixed ones that only feed derivations, and minus empty values,
    because an empty `location_constraint=` is not the same argv as leaving
    the key out and the difference is AWS's, not carryon's.
    """
    values = dict(answers)
    for field in provider.fields:
        if field.derive is not None:
            values[field.key] = field.derive(values)
    pairs = list(provider.fixed)
    for field in provider.fields:
        value = values.get(field.key)
        if field.key.startswith("_") or value in (None, ""):
            continue
        pairs.append((field.key, value))
    return pairs
