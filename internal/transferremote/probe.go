package transferremote

import (
	"context"
	"fmt"
)

const (
	hashSha256sum = "sha256sum"
	hashShasum    = "shasum"
	hashSha256q   = "sha256q"
)

// remoteCaps is the functional probe verdict for one remote host.
type remoteCaps struct {
	hash   string // "sha256sum", "shasum" or "sha256q"
	mvT    bool   // mv -T is functional; false selects Perl rename/link
	tarGNU bool   // tar -x --no-same-owner --no-same-permissions is functional
	// wcNames is functional; false selects the stdin-based portable size listing.
	wcNames bool
	// chunk is the chunked-mode verdict; the zero value means unavailable.
	chunk ChunkCaps
}

// probeTemplate verifies POSIX sh and the fixed tools cat find xargs tar rm
// mv wc mkdir chmod ln, then functionally selects a SHA-256 output format and
// publication primitives. The report is one machine-readable line on stdout;
// the scratch directory is removed on every path.
const probeTemplate = `set -eu
for tool in cat find xargs tar rm mv wc mkdir chmod ln; do
	command -v "$tool" >/dev/null || exit 20
done
if ! (: | xargs -0 cat >/dev/null); then
	exit 20
fi
d="${TMPDIR:-/tmp}"%s
if ! mkdir -m 700 "$d"; then
	exit 20
fi
trap 'rm -rf "$d"' 0
trap 'exit 20' 1 2 3 15
mode="$(find "$d" -type d -perm 0700 -print)" || exit 20
[ "$mode" = "$d" ] || exit 20
actual="$(umask 0022 && mask=$(umask) && printf '%%o' "$((0777 & ~mask))")" || exit 20
[ "$actual" = 755 ] || exit 20
actual="$(umask 0077 && mask=$(umask) && printf '%%o' "$((0777 & ~mask))")" || exit 20
[ "$actual" = 700 ] || exit 20
printf '\000' > "$d/nul" || exit 20
bytes="$(wc -c < "$d/nul")" || exit 20
[ "$bytes" -eq 1 ] || exit 20
wc_path="$d/wc name ' $(printf '\303\274 \303\261')"
printf 'abc' > "$wc_path" || exit 20
count="$(wc -c < "$wc_path")" || exit 20
while [ "${count# }" != "$count" ]; do count=${count# }; done
case "$count" in ''|*[!0-9]*) exit 20 ;; esac
[ "$count" = 3 ] || exit 20
out="$(wc -c "$wc_path")" || exit 20
while [ "${out# }" != "$out" ]; do out=${out# }; done
wc='stdin'
if [ "$out" = "3 $wc_path" ]; then wc='names'; fi
: > "$d/name with ' quote" || exit 20
if ! printf '%%s\000' "$d/name with ' quote" | xargs -0 sh -c 'test "$#" -eq 1 && test "$1" = "$0"' "$d/name with ' quote"; then
	exit 20
fi
if ! find "$d" -type f -name "name with ' quote" -print0 | xargs -0 sh -c 'test "$#" -eq 2 && test "$2" = "$1"' sh "$d/name with ' quote"; then
	exit 20
fi
printf 'abc' > "$d/h" || exit 20
hash=''
if out="$(sha256sum "$d/h" 2>/dev/null)" && [ "$out" = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  $d/h" ]; then
	hash='sha256sum'
elif out="$(shasum -a 256 < "$d/h" 2>/dev/null)" && [ "$out" = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -" ]; then
	hash='shasum'
elif sha256q="$(sha256 -q "$d/h" 2>/dev/null)"; then
	out="$(printf '%%s  %%s\n' "$sha256q" "$d/h")" || exit 20
	if [ "$out" = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  $d/h" ]; then
		hash='sha256q'
	fi
fi
[ -n "$hash" ] || exit 20

# Select GNU mv only after a successful mv -T file rename. Otherwise the
# fallback requires Perl on PATH; stock macOS supplies /usr/bin/perl on its
# harness PATH (/usr/bin:/bin:/usr/sbin:/sbin).
printf 'mv probe' > "$d/mv-cap-source" || exit 20
rename='t'
if ! mv -T "$d/mv-cap-source" "$d/mv-cap-dest"; then
	rename='p'
else
	if [ -e "$d/mv-cap-source" ] || [ -L "$d/mv-cap-source" ] || [ ! -f "$d/mv-cap-dest" ]; then
		rename='p'
	else
		content="$(cat "$d/mv-cap-dest")" || exit 20
		[ "$content" = 'mv probe' ] || rename='p'
	fi
fi
if [ "$rename" = t ]; then
	mkdir "$d/mv-cap-existing-dir" || exit 20
	printf 'no nesting source' > "$d/mv-cap-nest-source" || exit 20
	if mv -T "$d/mv-cap-nest-source" "$d/mv-cap-existing-dir"; then
		rename='p'
	fi
	[ -f "$d/mv-cap-nest-source" ] && [ -d "$d/mv-cap-existing-dir" ] && [ ! -e "$d/mv-cap-existing-dir/mv-cap-nest-source" ] || rename='p'
	if [ -f "$d/mv-cap-nest-source" ]; then
		content="$(cat "$d/mv-cap-nest-source")" || exit 20
		[ "$content" = 'no nesting source' ] || rename='p'
	fi
fi
if [ "$rename" = p ]; then
	command -v perl >/dev/null || exit 20
	printf 'perl probe' > "$d/perl-cap-source" || exit 20
	if ! perl -e 'exit(rename($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$d/perl-cap-source" "$d/perl-cap-dest"; then
		exit 20
	fi
	[ ! -f "$d/perl-cap-source" ] && [ -f "$d/perl-cap-dest" ] || exit 20
	content="$(cat "$d/perl-cap-dest")" || exit 20
	[ "$content" = 'perl probe' ] || exit 20
fi
rename_entry() {
	if [ "$rename" = t ]; then
		mv -T "$1" "$2"
	else
		perl -e 'exit(rename($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$1" "$2"
	fi
}
link_entry() {
	perl -e 'exit(link($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$1" "$2"
}

# Exercise the selected primitive with a path containing whitespace and an
# apostrophe; all path text travels as argv, never in the fixed Perl program.
printf 'rename source' > "$d/rename source ' quote" || exit 20
if ! rename_entry "$d/rename source ' quote" "$d/renamed source ' quote"; then
	exit 20
fi
[ ! -e "$d/rename source ' quote" ] && [ -f "$d/renamed source ' quote" ] || exit 20
content="$(cat "$d/renamed source ' quote")" || exit 20
[ "$content" = 'rename source' ] || exit 20

# Directory rename to an absent path succeeds.
mkdir "$d/mv-dir-absent-source" || exit 20
printf 'directory source' > "$d/mv-dir-absent-source/source" || exit 20
if ! rename_entry "$d/mv-dir-absent-source" "$d/mv-dir-absent-dest"; then
	exit 20
fi
[ ! -e "$d/mv-dir-absent-source" ] && [ -f "$d/mv-dir-absent-dest/source" ] || exit 20

# POSIX rename replaces an existing empty directory, without nesting.
mkdir "$d/mv-dir-empty-source" "$d/mv-dir-empty-dest" || exit 20
printf 'empty target source' > "$d/mv-dir-empty-source/source" || exit 20
if ! rename_entry "$d/mv-dir-empty-source" "$d/mv-dir-empty-dest"; then
	exit 20
fi
[ ! -e "$d/mv-dir-empty-source" ] && [ -f "$d/mv-dir-empty-dest/source" ] && [ ! -e "$d/mv-dir-empty-dest/mv-dir-empty-source" ] || exit 20
content="$(cat "$d/mv-dir-empty-dest/source")" || exit 20
[ "$content" = 'empty target source' ] || exit 20

# A file may not be moved into an existing directory as a nested entry.
printf 'file source' > "$d/mv-file" || exit 20
mkdir "$d/mv-file-dest" || exit 20
if [ "$rename" = t ]; then
	if mv -T "$d/mv-file" "$d/mv-file-dest"; then
		exit 20
	fi
else
	if perl -e 'exit(rename($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$d/mv-file" "$d/mv-file-dest"; then
		exit 20
	fi
fi
[ -f "$d/mv-file" ] && [ -d "$d/mv-file-dest" ] && [ ! -e "$d/mv-file-dest/mv-file" ] || exit 20
content="$(cat "$d/mv-file")" || exit 20
[ "$content" = 'file source' ] || exit 20

# A non-empty destination directory is refused unchanged.
mkdir "$d/mv-dir-source" "$d/mv-dir-dest" || exit 20
printf 'directory source' > "$d/mv-dir-source/source" || exit 20
printf 'destination sentinel' > "$d/mv-dir-dest/sentinel" || exit 20
if [ "$rename" = t ]; then
	if mv -T "$d/mv-dir-source" "$d/mv-dir-dest"; then
		exit 20
	fi
else
	if perl -e 'exit(rename($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$d/mv-dir-source" "$d/mv-dir-dest"; then
		exit 20
	fi
fi
[ -d "$d/mv-dir-source" ] && [ -f "$d/mv-dir-source/source" ] && [ -f "$d/mv-dir-dest/sentinel" ] || exit 20
content="$(cat "$d/mv-dir-source/source")" || exit 20
[ "$content" = 'directory source' ] || exit 20
content="$(cat "$d/mv-dir-dest/sentinel")" || exit 20
[ "$content" = 'destination sentinel' ] || exit 20

# Rename over a symlink replaces the link itself, not its referent.
printf 'symlink source' > "$d/symlink-source" || exit 20
printf 'symlink sentinel' > "$d/symlink-sentinel" || exit 20
ln -s "$d/symlink-sentinel" "$d/symlink-dest" || exit 20
if ! rename_entry "$d/symlink-source" "$d/symlink-dest"; then
	exit 20
fi
[ ! -e "$d/symlink-source" ] && [ ! -L "$d/symlink-dest" ] || exit 20
content="$(cat "$d/symlink-dest")" || exit 20
[ "$content" = 'symlink source' ] || exit 20
content="$(cat "$d/symlink-sentinel")" || exit 20
[ "$content" = 'symlink sentinel' ] || exit 20

# Rename over a regular file succeeds and replaces its bytes.
printf 'regular source' > "$d/regular-source" || exit 20
printf 'regular target' > "$d/regular-dest" || exit 20
if ! rename_entry "$d/regular-source" "$d/regular-dest"; then
	exit 20
fi
[ ! -e "$d/regular-source" ] && [ -f "$d/regular-dest" ] || exit 20
content="$(cat "$d/regular-dest")" || exit 20
[ "$content" = 'regular source' ] || exit 20

# Perl link() is deliberately tested only for the fallback: unlike ln, it
# cannot interpret an existing directory as a request to create a nested link.
if [ "$rename" = p ]; then
	printf 'link source' > "$d/link-source" || exit 20
	mkdir "$d/link-dir" || exit 20
	if link_entry "$d/link-source" "$d/link-dir"; then
		exit 20
	fi
	[ -f "$d/link-source" ] && [ ! -e "$d/link-dir/link-source" ] || exit 20
	if ! link_entry "$d/link-source" "$d/link-absent"; then
		exit 20
	fi
	[ -f "$d/link-source" ] && [ -f "$d/link-absent" ] || exit 20
	content="$(cat "$d/link-absent")" || exit 20
	[ "$content" = 'link source' ] || exit 20
	printf 'link symlink sentinel' > "$d/link-sentinel" || exit 20
	printf 'link symlink source' > "$d/link-symlink-source" || exit 20
	ln -s "$d/link-sentinel" "$d/link-symlink-dest" || exit 20
	if link_entry "$d/link-symlink-source" "$d/link-symlink-dest"; then
		exit 20
	fi
	[ -f "$d/link-symlink-source" ] && [ -L "$d/link-symlink-dest" ] || exit 20
	content="$(cat "$d/link-sentinel")" || exit 20
	[ "$content" = 'link symlink sentinel' ] || exit 20
fi

mkdir "$d/x" "$d/y" || exit 20
printf 'tar fixture' > "$d/x/f" || exit 20
chmod 0777 "$d/x/f" || exit 20
if ! (cd "$d/x" && tar -c -f "$d/archive.tar" .); then
	exit 20
fi
if ! (umask 0077 && cd "$d/y" && tar -x --no-same-owner --no-same-permissions -f "$d/archive.tar"); then
	exit 20
fi
[ -f "$d/y/f" ] || exit 20
content="$(cat "$d/y/f")" || exit 20
[ "$content" = 'tar fixture' ] || exit 20
mode="$(find "$d/y/f" -type f -perm 0700 -print)" || exit 20
[ "$mode" = "$d/y/f" ] || exit 20
` + probeChunkSection + `rm -rf "$d" || exit 20
trap - 0
printf 'SSJACK-CAPS %%s %%s gnu %%s\n' "$hash" "$rename" "$wc"
printf '%%s\n' "$chunk_line"
`

// probeChunkSection reports the chunked-mode capabilities on a second line,
// from the same scratch directory. The checks run in a command substitution
// with errexit off and stderr dropped: a failing tool only turns its own
// field off, and a missing or broken line means "chunking unavailable"; it
// can never make the probe fail. Every command either writes to a variable or
// is redirected, so the substitution carries exactly the report line.
const probeChunkSection = `chunk_caps() {
	set +e
	cown=no
	if [ -O "$d" ] && [ ! -O "$d/absent-owner-probe" ]; then
		mkdir "$d/own755" && chmod 755 "$d/own755"
		cfound=$(find "$d" -prune -type d -perm 0700 -print 2>/dev/null)
		cother=$(find "$d/own755" -prune -type d -perm 0700 -print 2>/dev/null)
		if [ "$cfound" = "$d" ] && [ -d "$d/own755" ] && [ -z "$cother" ]; then
			cown=yes
		fi
	fi
	crd=none
	printf '0123456789' > "$d/rd"
	cra=$(dd if="$d/rd" bs=4 skip=1 count=1 2>/dev/null)
	crb=$(dd if="$d/rd" bs=4 skip=2 count=1 2>/dev/null)
	crc=$(dd if="$d/rd" bs=10 skip=0 count=1 2>/dev/null)
	if [ "$cra" = 4567 ] && [ "$crb" = 89 ] && [ "$crc" = 0123456789 ]; then
		crd=dd
	else
		cra=$(tail -c +4 "$d/rd" 2>/dev/null | head -c 3)
		crb=$(tail -c +9 "$d/rd" 2>/dev/null | head -c 5)
		crc=$(tail -c +1 "$d/rd" 2>/dev/null | head -c 10)
		if [ "$cra" = 345 ] && [ "$crb" = 89 ] && [ "$crc" = 0123456789 ]; then
			crd=tail
		fi
	fi
	cmt=none
	cst=$(stat -c '%%s %%Y' "$d/rd" 2>/dev/null)
	cval=${cst#10 }
	if [ "$cval" != "$cst" ]; then
		case "$cval" in
			''|*[!0123456789]*) ;;
			*) cmt=c ;;
		esac
	fi
	if [ "$cmt" = none ]; then
		cst=$(stat -f '%%z %%m' "$d/rd" 2>/dev/null)
		cval=${cst#10 }
		if [ "$cval" != "$cst" ]; then
			case "$cval" in
				''|*[!0123456789]*) ;;
				*) cmt=f ;;
			esac
		fi
	fi
	cdf=no
	cout=$(df -P -k "$d" 2>/dev/null)
	cnl='
'
	cdata=${cout#*"$cnl"}
	if [ "$cdata" != "$cout" ]; then
		case "$cdata" in
			*"$cnl"*) ;;
			*)
				set -f
				set -- $cdata
				set +f
				if [ "$#" -ge 6 ]; then
					case "$2$3$4" in
						*[!0123456789]*) ;;
						*)
							case "$5" in
								*%%|-) cdf=yes ;;
							esac
							;;
					esac
				fi
				;;
		esac
	fi
	printf 'SSJACK-CHUNK %%s %%s %%s %%s\n' "$cown" "$crd" "$cmt" "$cdf"
}
chunk_line=$(chunk_caps 2>/dev/null) || chunk_line=
case "$chunk_line" in
	'SSJACK-CHUNK '*) ;;
	*) chunk_line='SSJACK-CHUNK no none none no' ;;
esac
`

// Probe checks that the remote target has every tool the transfer needs.
func (r *remoteRunner) Probe(ctx context.Context) error {
	if err := r.ready(); err != nil {
		return err
	}
	suffix, err := newRandomSuffix()
	if err != nil {
		return err
	}
	command := fmt.Sprintf(probeTemplate, shellQuote("/"+probePrefix+suffix))
	report, err := r.runListed(ctx, command, 1024)
	if err != nil {
		return err
	}
	caps, ok := parseProbeReport(string(report))
	if !ok {
		return classedUnsupportedProbe()
	}
	r.caps.Store(&caps)
	return nil
}

func classedUnsupportedProbe() error {
	return classError(exitUnsupported)
}
