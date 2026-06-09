#!/usr/bin/env python3
# Copyright 2026 The Sismo Authors. All rights reserved.
# Licensed under the MIT License.
"""Builds the sismo UI once and deploys it to Cloudflare R2.

Mirrors third_party/src/perfetto/ui/release/build_channel.py but targets
R2 via the S3 API instead of GCS via gsutil. Same channel/version-archive
model: each release writes /v<version>/ (immutable, kept forever) and
CAS-updates the /index.html version map.

--channel takes a comma-separated list; a single build is uploaded and
every listed channel's slot in the version map is pointed at it. CI
deploys every push to main with --channel=stable,canary,autopush, so all
three slots track main together; the per-channel granularity remains for
manual surgery (e.g. pinning canary to an experiment build).

Channels:
  autopush -- updates only the autopush slot
  canary   -- updates only the canary slot
  stable   -- swaps the HTML body AND updates the stable slot
              (preserves unlisted channels' map entries)
  release  -- uploads /v<version>/ only, no shared-state mutation;
              cannot be combined with other channels

Required env vars (from GitHub Actions secrets):
  R2_ACCOUNT_ID         -- Cloudflare account ID
  R2_ACCESS_KEY_ID      -- R2 API token access key
  R2_SECRET_ACCESS_KEY  -- R2 API token secret
  R2_BUCKET             -- bucket name (e.g. sismo-ui)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

from os.path import dirname

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

pjoin = os.path.join

INDEX_CHANNELS = ('autopush', 'canary', 'stable')
CHANNELS = INDEX_CHANNELS + ('release',)

CUR_DIR = dirname(os.path.abspath(__file__))
SISMO_ROOT = dirname(dirname(CUR_DIR))
PERFETTO_ROOT = pjoin(SISMO_ROOT, 'third_party/src/perfetto')

CAS_MAX_RETRIES = 10
NO_CACHE = 'no-cache, no-transform'
IMMUTABLE = 'public, max-age=31536000, immutable'

VERSION_ATTR_RE = re.compile(r"data-perfetto_version='([^']*)'")

# Content types we rely on R2 returning correctly. Most are inferred from
# extension by R2 itself; a couple need explicit hints.
CONTENT_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.wasm': 'application/wasm',
    '.json': 'application/json; charset=utf-8',
    '.map': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.woff2': 'font/woff2',
}


def content_type(path):
  for ext, ctype in CONTENT_TYPES.items():
    if path.endswith(ext):
      return ctype
  return 'application/octet-stream'


def check_call_and_log(args, cwd=None):
  print(' '.join(args))
  subprocess.check_call(args, cwd=cwd)


def check_output_str(args, cwd=None):
  return subprocess.check_output(args, cwd=cwd).decode().strip()


def make_s3_client():
  account_id = os.environ['R2_ACCOUNT_ID']
  return boto3.client(
      's3',
      endpoint_url=f'https://{account_id}.r2.cloudflarestorage.com',
      aws_access_key_id=os.environ['R2_ACCESS_KEY_ID'],
      aws_secret_access_key=os.environ['R2_SECRET_ACCESS_KEY'],
      config=Config(signature_version='s3v4', region_name='auto'),
  )


def head(s3, bucket, key):
  """Return (etag, body_bytes) or (None, None) if the object is absent."""
  try:
    obj = s3.get_object(Bucket=bucket, Key=key)
  except ClientError as e:
    code = e.response.get('Error', {}).get('Code')
    if code in ('NoSuchKey', '404'):
      return None, None
    raise
  return obj['ETag'], obj['Body'].read()


def cas_write(s3, bucket, key, body, etag, content_type_str, cache_control):
  """Conditionally write `body` to `key`, requiring the current ETag to
  match `etag`. Pass `etag=None` for must-not-exist semantics."""
  kwargs = dict(
      Bucket=bucket,
      Key=key,
      Body=body,
      ContentType=content_type_str,
      CacheControl=cache_control,
  )
  if etag is None:
    kwargs['IfNoneMatch'] = '*'
  else:
    kwargs['IfMatch'] = etag
  s3.put_object(**kwargs)


def cas_write_html(s3, bucket, key, update_fn):
  """Read bucket/key, apply update_fn(text)->text, write back under
  If-Match. Retry on precondition failure. If the object does not exist,
  update_fn is called with '' and the write uses If-None-Match:*."""
  for attempt in range(CAS_MAX_RETRIES):
    etag, body = head(s3, bucket, key)
    current = body.decode() if body is not None else ''
    new = update_fn(current)
    if new == current and etag is not None:
      print(f'No change needed for {key}; skipping write')
      return
    try:
      cas_write(
          s3, bucket, key, new.encode(), etag,
          'text/html; charset=utf-8', NO_CACHE)
      print(f'CAS write of {key} succeeded on attempt {attempt + 1}')
      return
    except ClientError as e:
      code = e.response.get('Error', {}).get('Code')
      if code not in ('PreconditionFailed', '412'):
        raise
      print(f'CAS write of {key} failed (precondition); retrying')
      time.sleep(1 + attempt)
  raise Exception(f'CAS retries exhausted for {key}')


def parse_version_map(html):
  m = VERSION_ATTR_RE.search(html)
  if not m:
    return None
  return json.loads(m.group(1))


def replace_version_map(html, version_map):
  return VERSION_ATTR_RE.sub(
      "data-perfetto_version='%s'" % json.dumps(version_map), html, count=1)


def patch_channels(html, channels, new_version):
  """Update only these channels' slots in the remote HTML's version map."""
  version_map = parse_version_map(html)
  if version_map is None:
    raise Exception(
        'data-perfetto_version attribute not found in remote HTML; '
        'refusing to write. The stable channel must seed the root HTML '
        'before canary/autopush can update their entries.')
  if all(version_map.get(c) == new_version for c in channels):
    return html
  for channel in channels:
    version_map[channel] = new_version
  return replace_version_map(html, version_map)


def make_stable_updater(local_html_path, channels, new_version):
  """For stable: swap in the freshly-built HTML body, splice in the
  remaining channels' entries from the current remote map, and point every
  requested channel at the new version."""
  with open(local_html_path) as f:
    new_body = f.read()
  if VERSION_ATTR_RE.search(new_body) is None:
    raise Exception(
        'Locally-built HTML has no data-perfetto_version attribute; '
        'ui/build did not bake it in correctly.')

  def update(remote_html):
    merged = parse_version_map(remote_html) or {}
    for channel in channels:
      merged[channel] = new_version
    return replace_version_map(new_body, merged)

  return update


def make_other_channel_updater(channels, new_version):
  def update(remote_html):
    return patch_channels(remote_html, channels, new_version)
  return update


def build(channels):
  # Compute the sismo-side SHA *before* chdir to PERFETTO_ROOT so it's the
  # sismo repo's HEAD, not perfetto's. Pass it through as a build-time env
  # var so write_version_header.py bakes it into perfetto_version{.gen.h,.ts}
  # — the version footer in the deployed UI then identifies the sismo
  # commit that was deployed. See google/perfetto#5717.
  sismo_sha = check_output_str(['git', 'rev-parse', 'HEAD'], cwd=SISMO_ROOT)
  os.environ['PERFETTO_VERSION_HEADER_OVERRIDE_SCM_REVISION'] = sismo_sha

  os.chdir(PERFETTO_ROOT)
  print('=' * 70)
  print(f'Building UI for channels {",".join(channels)} @ sismo {sismo_sha}')
  print('=' * 70)
  version = check_output_str(['tools/write_version_header.py', '--stdout'])
  check_call_and_log(['tools/install-build-deps', '--ui'])
  check_call_and_log(['ui/build', '--minify-js=all', '--no-source-maps'])
  return version, pjoin(PERFETTO_ROOT, 'ui/out/dist')


def version_exists(s3, bucket, version):
  try:
    s3.head_object(Bucket=bucket, Key=f'{version}/manifest.json')
    return True
  except ClientError as e:
    code = e.response.get('Error', {}).get('Code')
    if code in ('NoSuchKey', '404'):
      return False
    raise


def upload_versioned_dir(s3, bucket, version, dist_dir):
  """Upload everything under dist_dir/<version>/ to bucket/<version>/.
  Skipped entirely if the version already exists -- /v<version>/ is
  immutable and must never be overwritten."""
  if version_exists(s3, bucket, version):
    print(f'Skipping upload of {version} -- already in R2')
    return
  src_dir = pjoin(dist_dir, version)
  for root, _, files in os.walk(src_dir):
    for fname in files:
      abs_path = pjoin(root, fname)
      rel_path = os.path.relpath(abs_path, dist_dir)
      key = rel_path.replace(os.sep, '/')
      with open(abs_path, 'rb') as f:
        body = f.read()
      print(f'put {key} ({len(body)} bytes)')
      s3.put_object(
          Bucket=bucket,
          Key=key,
          Body=body,
          ContentType=content_type(fname),
          CacheControl=IMMUTABLE,
      )


def upload_loose_files(s3, bucket, channels, version, dist_dir):
  """Iterate the loose files at the root of dist_dir.

  HTML files: CAS-updated by every index channel (stable swaps the body,
  others patch only their slots in the version map).

  Non-HTML files (service_worker.*, etc.): uploaded plain only when stable
  is among the channels -- canary/autopush must not touch shared loose
  files.

  release: skipped entirely. /v<version>/ alone is published, no shared
  state mutated."""
  if channels == ['release']:
    print('Skipping loose-file upload for release mode')
    return
  for fname in sorted(os.listdir(dist_dir)):
    fpath = pjoin(dist_dir, fname)
    if not os.path.isfile(fpath):
      continue
    if fname.endswith('.html'):
      if 'stable' in channels:
        update = make_stable_updater(fpath, channels, version)
      else:
        update = make_other_channel_updater(channels, version)
      cas_write_html(s3, bucket, fname, update)
    elif 'stable' in channels:
      with open(fpath, 'rb') as f:
        body = f.read()
      print(f'put {fname} ({len(body)} bytes)')
      s3.put_object(
          Bucket=bucket,
          Key=fname,
          Body=body,
          ContentType=content_type(fname),
          CacheControl=NO_CACHE,
      )


def check_env():
  """Fail fast with a clear message if any required secret is missing
  or empty. Avoids burning a 15-minute build before the upload step
  discovers a missing credential."""
  required = (
      'R2_ACCOUNT_ID', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2_BUCKET')
  missing = [k for k in required if not os.environ.get(k)]
  if missing:
    raise SystemExit(
        'Missing or empty environment variables: ' + ', '.join(missing) +
        '. Set them as GitHub Actions secrets with these exact names.')


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--channel',
      required=True,
      help='comma-separated list of channels to update: ' +
      ', '.join(CHANNELS))
  parser.add_argument('--upload', action='store_true')
  args = parser.parse_args()

  channels = args.channel.split(',')
  bad = sorted(set(channels) - set(CHANNELS))
  if bad:
    parser.error(f'unknown channel(s): {", ".join(bad)}')
  if 'release' in channels and len(channels) > 1:
    parser.error("'release' cannot be combined with other channels")

  if args.upload:
    check_env()

  version, dist_dir = build(channels)

  if not args.upload:
    return

  bucket = os.environ['R2_BUCKET']
  s3 = make_s3_client()

  print('=' * 70)
  print(f'Uploading channels {args.channel} @ {version} to r2://{bucket}')
  print('=' * 70)
  upload_versioned_dir(s3, bucket, version, dist_dir)
  upload_loose_files(s3, bucket, channels, version, dist_dir)


if __name__ == '__main__':
  sys.exit(main())
