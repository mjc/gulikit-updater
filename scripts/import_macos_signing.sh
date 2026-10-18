#!/bin/bash
# Called only by the manual signing workflow, after the build has finished.
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?}" "${GITHUB_ENV:?}"
: "${MACOS_CERTIFICATE_P12_BASE64:?Missing Developer ID certificate}"
: "${MACOS_CERTIFICATE_PASSWORD:?Missing certificate password}"
: "${MACOS_SIGNING_IDENTITY:?Missing Developer ID Application identity}"
: "${APPLE_ID:?}" "${APPLE_TEAM_ID:?}" "${APPLE_APP_PASSWORD:?}"
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
keychain="$RUNNER_TEMP/gulikit-signing.keychain-db"
certificate="$RUNNER_TEMP/gulikit-signing.p12"
password="$(/usr/bin/openssl rand -hex 32)"
echo "::add-mask::$password"
trap 'rm -f "$certificate"' EXIT
printf '%s' "$MACOS_CERTIFICATE_P12_BASE64" | /usr/bin/base64 --decode > "$certificate"
/usr/bin/security create-keychain -p "$password" "$keychain"
# Record the path immediately so the workflow's always() cleanup handles failures.
printf 'MACOS_SIGNING_KEYCHAIN=%s\n' "$keychain" >> "$GITHUB_ENV"
/usr/bin/security set-keychain-settings -lut 21600 "$keychain"
/usr/bin/security unlock-keychain -p "$password" "$keychain"
/usr/bin/security import "$certificate" -P "$MACOS_CERTIFICATE_PASSWORD" \
    -k "$keychain" -T /usr/bin/codesign
/usr/bin/security set-key-partition-list -S apple-tool:,apple:,codesign: \
    -k "$password" "$keychain" > /dev/null
/usr/bin/xcrun notarytool store-credentials gulikit-release \
    --keychain "$keychain" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD"
