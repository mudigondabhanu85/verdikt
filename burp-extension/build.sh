#!/usr/bin/env bash
# Compiles the Verdikt Montoya extension and packages it as a jar Burp
# can load directly (Extensions tab -> Add -> Java -> this jar).
#
# The Montoya API itself is Burp's own interface layer, fetched here from
# Maven Central as a compile-time-only dependency (never bundled into the
# output jar — Burp provides those classes on its own classpath at
# runtime, same as any Montoya extension).
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA_VERSION="2026.7"
mkdir -p lib out

if [ ! -f "lib/montoya-api.jar" ]; then
  curl -sL -o lib/montoya-api.jar \
    "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA_VERSION}/montoya-api-${MONTOYA_VERSION}.jar"
fi

rm -rf out && mkdir out
javac -Xlint:all -d out -cp lib/montoya-api.jar src/com/verdikt/burp/*.java

jar --create --file verdikt-burp-extension.jar -C out .
echo "Built verdikt-burp-extension.jar"
