package ownerrotationtest

// rotationRetireScript is the fixed retire-key command the production client sends.
const rotationRetireScript = `set -eu
umask 077
IFS= read -r old
IFS= read -r new
oldtype=${old%% *}
oldblob=${old#* }
newtype=${new%% *}
newblob=${new#* }
directory=$HOME/.ssh
file=$directory/authorized_keys
[ -d "$directory" ] && [ ! -L "$directory" ]
[ -f "$file" ] && [ ! -L "$file" ]
lock=$directory/.ssjack-rotate.lock
mkdir "$lock"
temporary=
trap 'rmdir "$lock"; if [ -n "$temporary" ]; then rm -f "$temporary"; fi' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
awk -v ot="$oldtype" -v ob="$oldblob" -v nt="$newtype" -v nb="$newblob" '
    index($0, ob) { if ($1 != ot || $2 != ob) bad=1 }
    index($0, nb) { if ($1 == nt && $2 == nb) found=1; else bad=1 }
    END { if (!found || bad) exit 1 }
' "$file"
if ! awk -v ot="$oldtype" -v ob="$oldblob" '$1 == ot && $2 == ob { found=1 } END { exit !found }' "$file"; then
    exit 0
fi
temporary=$(mktemp "$directory/.ssjack-retire.XXXXXX")
awk -v ot="$oldtype" -v ob="$oldblob" '!($1 == ot && $2 == ob)' "$file" > "$temporary"
awk -v nt="$newtype" -v nb="$newblob" '$1 == nt && $2 == nb { found=1 } END { exit !found }' "$temporary"
cp -p "$file" "$file.ssjack-retired"
chmod 600 "$temporary"
mv -f "$temporary" "$file"
temporary=
`
