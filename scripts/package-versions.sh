#!/usr/bin/env bash
set -euo pipefail

version="${1:?version is required}"

if [[ "${version}" == v* ]]; then
    version="${version#v}"
fi

base="${version%%-*}"

if [[ "${base}" == "${version}" ]]; then
    deb_version="${version}-1"
    rpm_version="${version}"
    rpm_release="1"
else
    prerelease="${version#*-}"
    rpm_prerelease="${prerelease//-/.}"
    deb_version="${base}~${prerelease}-1"
    rpm_version="${base}"
    rpm_release="0.${rpm_prerelease}"
fi

cat <<EOF
deb_version=${deb_version}
rpm_version=${rpm_version}
rpm_release=${rpm_release}
EOF
