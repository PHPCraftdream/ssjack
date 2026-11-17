package transferremote

// Shell text of the chunked-mode command templates. Every command is built as
// a Go-formatted prologue (caller values, each single-quoted) followed by one
// of the fixed bodies below; the bodies are never passed through fmt, so the
// `%` of printf formats is literal. All variables a body relies on are named
// here: parent, name, key, stage, magic.

// Remote exit codes of the chunked templates, besides the shared ones in
// remote.go. They are not drops: the session ended with a remote status.
const (
	// ExitStageForeign: the staging path exists but failed an adoption check
	// (not a real directory, not owned by the principal, mode other than
	// 0700, no marker or another key). It was neither used nor modified.
	ExitStageForeign = 26
	// ExitStageMissing: the staging directory does not exist.
	ExitStageMissing = 27
	// ExitPartMissing: a part named for assembly is absent or not a regular
	// file.
	ExitPartMissing = 28
)

// stageMarkerName is the marker file inside a chunked staging directory; its
// first line is the magic and the full key, its modification time is the
// idleness clock for garbage collection.
const stageMarkerName = "marker"

// stageMagic prefixes the key in the marker's first line.
const stageMagic = "SSJACK-STAGING 1 "

// stageFuncs are POSIX sh functions shared by the chunked templates. They use
// only builtins, `find -perm`/`-mmin`/`-mtime` and `wc`, nothing GNU-only.
//
// check_stage returns 0 when $stage is a real, owned, 0700 directory with the
// marker for $magic, 2 when nothing exists at $stage and 1 for anything else
// (a foreign object). stage_gate exits 27 (missing) or 26 (foreign).
// stage_idle is true when the marker is older than a day: `-mmin +1440` where
// supported, else `-mtime +1` (never younger than a day on any find; BSD find
// rounds ages up, so `-mtime +0` would match a fresh file there).
// wc_count sets wc_n to the byte count of a file read from stdin (padding
// trimmed, digits checked). safe_name accepts `part-` followed by digits and
// dashes only; valid_part is the strict part-<offset>-<len> pattern.
const stageFuncs = `check_stage() {
	if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then
		return 2
	fi
	if [ -L "$stage" ] || [ ! -d "$stage" ] || [ ! -O "$stage" ]; then
		return 1
	fi
	if [ "$(find "$stage" -prune -type d -perm 0700 -print 2>/dev/null)" != "$stage" ]; then
		return 1
	fi
	if [ -L "$stage/marker" ] || [ ! -f "$stage/marker" ]; then
		return 1
	fi
	line=
	IFS= read -r line < "$stage/marker" || :
	if [ "$line" != "$magic" ]; then
		return 1
	fi
	return 0
}
stage_gate() {
	gate_rc=0
	check_stage || gate_rc=$?
	case "$gate_rc" in
		0) ;;
		2) exit 27 ;;
		*) exit 26 ;;
	esac
}
stage_idle() {
	if idle_out=$(find "$stage/marker" -mmin +1440 -print 2>/dev/null); then
		[ -n "$idle_out" ]
	elif idle_out=$(find "$stage/marker" -mtime +1 -print 2>/dev/null); then
		[ -n "$idle_out" ]
	else
		return 1
	fi
}
wc_count() {
	wc_n=$(wc -c < "$1") || return 1
	while [ "${wc_n# }" != "$wc_n" ]; do
		wc_n=${wc_n# }
	done
	case "$wc_n" in
		''|*[!0123456789]*) return 1 ;;
	esac
	return 0
}
safe_name() {
	case "$1" in
		part-*) ;;
		*) return 1 ;;
	esac
	sn_rest=${1#part-}
	case "$sn_rest" in
		''|*[!0123456789-]*) return 1 ;;
	esac
	[ "${#sn_rest}" -le 45 ]
}
valid_part() {
	case "$1" in
		part-*-*) ;;
		*) return 1 ;;
	esac
	vp_rest=${1#part-}
	vp_off=${vp_rest%%-*}
	vp_len=${vp_rest#*-}
	for vp_v in "$vp_off" "$vp_len"; do
		case "$vp_v" in
			''|*[!0123456789]*|0?*) return 1 ;;
		esac
		if [ "${#vp_v}" -gt 18 ]; then
			return 1
		fi
	done
	if [ "$vp_len" = 0 ]; then
		return 1
	fi
	return 0
}
`

// stageHeader re-validates the key and name given by the caller and derives
// $stage and $magic. A malformed key or name, or a missing or symlinked
// parent, is refused (exit 21) before anything is touched.
const stageHeader = `case "$key" in
	''|*[!0123456789abcdef]*) exit 21 ;;
esac
if [ "${#key}" -ne 32 ] || [ "$name" != ".ssjack-transfer-$key" ]; then
	exit 21
fi
if [ ! -d "$parent" ] || [ -L "$parent" ]; then
	exit 21
fi
stage="$parent/$name"
magic="SSJACK-STAGING 1 $key"
`

// stageEnsureBody creates the staging directory (mode 0700, no clobber) with
// its marker, or verifies an existing one. The verdict is the single stdout
// line `SSJACK-STAGE created|reused|foreign`; a foreign object is never
// reused, written to or removed.
const stageEnsureBody = `if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then
	if ! mkdir -m 700 "$stage" 2>/dev/null; then
		if [ -e "$stage" ] || [ -L "$stage" ]; then
			printf 'SSJACK-STAGE foreign\n'
			exit 0
		fi
		exit 24
	fi
	if ! printf '%s\n' "$magic" > "$stage/marker" 2>/dev/null; then
		rm -rf "$stage" || :
		exit 24
	fi
	printf 'SSJACK-STAGE created\n'
	exit 0
fi
rc=0
check_stage || rc=$?
if [ "$rc" -eq 0 ]; then
	printf 'SSJACK-STAGE reused\n'
else
	printf 'SSJACK-STAGE foreign\n'
fi
`

// partUploadBody stores stdin as one part. The bytes land in a temporary
// name with a per-attempt random suffix; only an exact count equal to $len
// renames them to the final name (the selected publication primitive) and
// refreshes the marker time. The session prints `SSJACK-PART <count>
// stored|short`; a short temporary is removed.
const partUploadBody = `stage_gate
final="$stage/part-$off-$len"
tmp="$stage/part-$off-$len.$rnd.tmp"
if [ -e "$tmp" ] || [ -L "$tmp" ]; then
	exit 22
fi
trap 'rm -f "$tmp"' 0
trap 'exit 24' 1 2 3 15
if ! (umask 077 && cat > "$tmp"); then
	exit 24
fi
if ! wc_count "$tmp"; then
	exit 24
fi
if [ "$wc_n" != "$len" ]; then
	printf 'SSJACK-PART %s short\n' "$wc_n"
	exit 0
fi
if ! mv -T -f "$tmp" "$final"; then
	exit 24
fi
trap - 0
touch "$stage/marker" 2>/dev/null || :
printf 'SSJACK-PART %s stored\n' "$wc_n"
`

// listBody validates the marker, removes stale temporary files and prints
// every part-* regular file with its size (`wc -c` on stdin, so names never
// pass through wc). Entries are counted before filtering and bounded by $max.
// Output: `SSJACK-LIST 1`, `<size> <name>` lines, then `SSJACK-END <n>` or
// `SSJACK-OVERFLOW`.
const listBody = `stage_gate
for f in "$stage"/part-*.tmp; do
	if [ -e "$f" ] || [ -L "$f" ]; then
		rm -f "$f" 2>/dev/null || :
	fi
done
count=0
listed=0
printf 'SSJACK-LIST 1\n'
for f in "$stage"/part-*; do
	if [ ! -e "$f" ] && [ ! -L "$f" ]; then
		continue
	fi
	count=$((count + 1))
	if [ "$count" -gt "$max" ]; then
		printf 'SSJACK-OVERFLOW\n'
		exit 0
	fi
	if [ -L "$f" ] || [ ! -f "$f" ]; then
		continue
	fi
	base=${f##*/}
	if ! safe_name "$base"; then
		continue
	fi
	if ! wc_count "$f"; then
		continue
	fi
	printf '%s %s\n' "$wc_n" "$base"
	listed=$((listed + 1))
done
printf 'SSJACK-END %s\n' "$listed"
`

// removeEntriesBody removes the named entries of the staging directory. The
// names arrive on stdin, one per line, and are re-validated here.
const removeEntriesBody = `stage_gate
p=
while IFS= read -r p || [ -n "$p" ]; do
	if ! safe_name "$p"; then
		exit 21
	fi
	rm -f "$stage/$p" || exit 24
done
`

// assembleBody concatenates the parts named on stdin (one per line, in
// order, each re-validated against the strict pattern) into a random-named
// file inside the staging directory, checks its size and prints the size and
// the SHA-256 line of the selected hash command. Any failure removes the
// half-written file; the parts are never touched.
const assembleBody = `stage_gate
asm="$stage/assembled.$rnd.tmp"
if [ -e "$asm" ] || [ -L "$asm" ]; then
	exit 22
fi
ok=0
trap 'if [ "$ok" != 1 ]; then rm -f "$asm"; fi' 0
trap 'exit 24' 1 2 3 15
: > "$asm" || exit 24
p=
while IFS= read -r p || [ -n "$p" ]; do
	if ! valid_part "$p"; then
		exit 21
	fi
	f="$stage/$p"
	if [ -L "$f" ] || [ ! -f "$f" ]; then
		exit 28
	fi
	cat "$f" >> "$asm" || exit 24
done
`

// assembleExecSuffix adds the execute bits like writeFileExecSuffix.
const assembleExecSuffix = "chmod +x \"$asm\" || exit 24\n"

// assembleCheckBody verifies the size, then hashes the assembled file.
// statHashCommand is appended after `path="$asm"`.
const assembleCheckBody = `if ! wc_count "$asm"; then
	exit 24
fi
if [ "$wc_n" != "$size" ]; then
	exit 23
fi
printf '%s\n' "$wc_n"
path="$asm"
`

// assembleDoneBody marks success so the exit trap keeps the file.
const assembleDoneBody = "\nok=1\n"

// removeStagingBody removes the staging directory only after the full
// adoption check; an absent directory is success.
const removeStagingBody = `rc=0
check_stage || rc=$?
case "$rc" in
	0) ;;
	2) exit 0 ;;
	*) exit 26 ;;
esac
rm -rf "$stage" || exit 24
`

// gcBody removes at most 16 stale staging directories of the parent: name
// pattern (32 lowercase hex), real directory, owned, mode 0700, marker with
// the matching key, marker idle for over a day, and not the excluded current
// directory. Every check is repeated immediately before rm -rf. The scan is
// bounded and nothing in it can fail the session. Output: `SSJACK-GC <n>`.
const gcBody = `removed=0
checked=0
if [ -d "$parent" ] && [ ! -L "$parent" ]; then
	for stage in "$parent"/.ssjack-transfer-????????????????????????????????; do
		if [ "$removed" -ge 16 ] || [ "$checked" -ge 256 ]; then
			break
		fi
		if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then
			continue
		fi
		checked=$((checked + 1))
		name=${stage##*/}
		if [ "$name" = "$excl" ]; then
			continue
		fi
		key=${name#.ssjack-transfer-}
		case "$key" in
			*[!0123456789abcdef]*) continue ;;
		esac
		magic="SSJACK-STAGING 1 $key"
		rc=0
		check_stage || rc=$?
		if [ "$rc" -ne 0 ]; then
			continue
		fi
		if ! stage_idle; then
			continue
		fi
		rc=0
		check_stage || rc=$?
		if [ "$rc" -ne 0 ]; then
			continue
		fi
		if ! stage_idle; then
			continue
		fi
		if rm -rf "$stage" 2>/dev/null; then
			removed=$((removed + 1))
		fi
	done
fi
printf 'SSJACK-GC %s\n' "$removed"
`

// diskBody prints the POSIX df report for the parent; any df failure prints
// nothing, which the caller reads as "skip the check".
const diskBody = `if [ ! -d "$parent" ] || [ -L "$parent" ]; then
	exit 21
fi
df -P -k "$parent" 2>/dev/null || :
`

// statSourceBody prints "<size> <mtime>" of a regular file; the stat
// invocation is appended per flavour.
const statSourceBody = `if [ -L "$path" ] || [ ! -f "$path" ]; then
	exit 21
fi
`

const (
	statSourceGNU = "stat -c '%s %Y' \"$path\"\n"
	statSourceBSD = "stat -f '%z %m' \"$path\"\n"
)

// readRangeBody guards the source the same way readFileTemplate does.
const readRangeBody = `if [ -L "$path" ] || [ ! -f "$path" ]; then
	exit 21
fi
`

const (
	// readRangeDD reads one block of bs bytes at block index skip.
	readRangeDD = "dd if=\"$path\" bs=\"$bs\" skip=\"$skip\" count=1 2>/dev/null\n"
	// readRangeTail reads len bytes from the 1-based byte start.
	readRangeTail = "tail -c \"+$start\" \"$path\" 2>/dev/null | head -c \"$len\"\n"
)
