#!/bin/sh
# Test and build the plugin ZIP inside the Flutter image, which carries a JDK and the Android SDK.
set -e
cd /src
export ANDROID_HOME=${ANDROID_HOME:-$ANDROID_SDK_ROOT}
command -v python3 >/dev/null || (apt-get update -qq && apt-get install -y -qq python3 >/dev/null)
python3 tools/test.py
python3 tools/build.py
