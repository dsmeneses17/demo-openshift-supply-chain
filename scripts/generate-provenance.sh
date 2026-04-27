#!/usr/bin/env bash

set -e

IMAGE=$1

if [ -z "$IMAGE" ]; then
  echo "Usage: $0 <image>"
  exit 1
fi

FULL_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE")

SHA=$(echo "$FULL_DIGEST" | cut -d'@' -f2 | cut -d':' -f2)

echo "Generating provenance.json"

cat <<EOF > provenance.json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "$IMAGE",
      "digest": {
        "sha256": "$SHA"
      }
    }
  ],
  "predicate": {
    "buildType": "github-actions",
    "builder": {
      "id": "${GITHUB_ACTOR:-local}"
    }
  }
}
EOF

echo "Done"
echo "FULL_DIGEST=$FULL_DIGEST"
echo "SHA=$SHA"