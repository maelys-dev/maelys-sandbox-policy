#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

case "$(uname -s)" in Linux) host_os=linux ;; Darwin) host_os=macos ;; *) exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) host_arch=x86_64 ;; arm64|aarch64) host_arch=arm64 ;; *) exit 1 ;; esac
target="${1:-${host_os}-${host_arch}}"
case "$target" in linux-x86_64|linux-arm64|macos-arm64) ;; *) echo "unsupported target: $target" >&2; exit 1 ;; esac
test "$target" = "${host_os}-${host_arch}" || { echo "target does not match native host" >&2; exit 1; }

version="${PACKAGE_VERSION_OVERRIDE:-$(cat VERSION)}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid VERSION: $version" >&2; exit 1; }

dist="$root/dist"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$dist"
rm -f "$dist"/*"$version"*"$target"* 2>/dev/null || true

make clean check
stage="$tmp/stage"
make install DESTDIR="$stage" PREFIX=/usr/local
test "$("$stage/usr/local/bin/maelys-policy" --version)" = "$version"
grep -Fq "Version: $version" "$stage/usr/local/lib/pkgconfig/maelys-sandbox-policy.pc"

tar_name="maelys-sandbox-policy-${version}-${target}.tar.gz"
tar -czf "$dist/$tar_name" -C "$stage" .
(cd "$dist" && sha256 "$tar_name" >"${tar_name}.sha256")

if [ "$host_os" = macos ]; then
  test "$(lipo -archs "$stage/usr/local/lib/libmaelys-mir.a")" = arm64
  test "$(lipo -archs "$stage/usr/local/lib/libmaelys-sandbox-policy.a")" = arm64
  ls -1 "$dist"/*"$version"*
  exit 0
fi

command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; exit 1; }
command -v rpmbuild >/dev/null || { echo "rpmbuild is required" >&2; exit 1; }
case "$host_arch" in x86_64) deb_arch=amd64; rpm_arch=x86_64 ;; arm64) deb_arch=arm64; rpm_arch=aarch64 ;; esac

linux_stage="$tmp/linux-stage"
make install DESTDIR="$linux_stage" PREFIX=/usr

dev_root="$tmp/dev-deb"
cp -a "$linux_stage" "$dev_root"
rm -rf "$dev_root/usr/bin"
mkdir -p "$dev_root/DEBIAN"
cat >"$dev_root/DEBIAN/control" <<EOF
Package: libmaelys-sandbox-policy-dev
Version: ${version}
Section: libdevel
Priority: optional
Architecture: ${deb_arch}
Maintainer: Maelys Developers <noreply@maelys.dev>
Depends: libc6-dev
Description: C SDK for canonical Maelys sandbox policies and host plans
 Includes static libraries, public headers, MIR schema and pkg-config metadata.
EOF
dev_deb="libmaelys-sandbox-policy-dev_${version}_${deb_arch}.deb"
dpkg-deb --root-owner-group --build "$dev_root" "$dist/$dev_deb" >/dev/null
(cd "$dist" && sha256 "$dev_deb" >"${dev_deb}.sha256")

runtime_root="$tmp/runtime-deb"
mkdir -p "$runtime_root/usr/bin" "$runtime_root/usr/share/doc/maelys-sandbox-policy" "$runtime_root/DEBIAN"
install -m 0755 "$linux_stage/usr/bin/maelys-policy" "$runtime_root/usr/bin/maelys-policy"
install -m 0644 LICENSE SECURITY.md "$runtime_root/usr/share/doc/maelys-sandbox-policy/"
cat >"$runtime_root/DEBIAN/control" <<EOF
Package: maelys-sandbox-policy
Version: ${version}
Section: utils
Priority: optional
Architecture: ${deb_arch}
Maintainer: Maelys Developers <noreply@maelys.dev>
Description: Compile and inspect portable Maelys sandbox policies
 Provides the maelys-policy command for strict JSON, canonical MIR and digests.
EOF
runtime_deb="maelys-sandbox-policy_${version}_${deb_arch}.deb"
dpkg-deb --root-owner-group --build "$runtime_root" "$dist/$runtime_deb" >/dev/null
(cd "$dist" && sha256 "$runtime_deb" >"${runtime_deb}.sha256")

rpm_top="$tmp/rpmbuild"
mkdir -p "$rpm_top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cat >"$rpm_top/SPECS/maelys-sandbox-policy.spec" <<EOF
Name: maelys-sandbox-policy
Version: ${version}
Release: 1
Summary: Compile and inspect portable Maelys sandbox policies
License: MPL-2.0
URL: https://policy.maelys.dev
BuildArch: ${rpm_arch}

%description
Strict JSON source compiler and canonical MIR inspection command.

%package devel
Summary: C SDK for canonical Maelys sandbox policies and host plans
Requires: %{name} = %{version}-%{release}

%description devel
Static libraries, public headers, MIR schema and pkg-config metadata.

%prep
%build
%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a ${linux_stage}/. %{buildroot}/

%files
/usr/bin/maelys-policy
/usr/share/doc/maelys-sandbox-policy/

%files devel
/usr/include/maelys/
/usr/lib/*.a
/usr/lib/pkgconfig/*.pc
/usr/share/maelys-sandbox-policy/
EOF
rpmbuild --define "_topdir $rpm_top" -bb "$rpm_top/SPECS/maelys-sandbox-policy.spec" >/dev/null
find "$rpm_top/RPMS" -type f -name '*.rpm' -exec cp {} "$dist/" \;
for rpm_file in "$dist"/*"${version}"*.rpm; do (cd "$dist" && sha256 "$(basename "$rpm_file")" >"$(basename "$rpm_file").sha256"); done
ls -1 "$dist"/*"$version"*
