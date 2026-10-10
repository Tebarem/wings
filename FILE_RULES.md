# File rules

Wings can keep some of a server's files out of reach of users. Eggs define two lists of
patterns, `file_hidden` and `file_denylist` (protected). Wings applies them to every user-facing
channel it serves. They do not restrict the server process, which runs inside the container and
can read everything in the volume. Read the limitations before relying on them.

## Pattern syntax

Each list holds one pattern per line, written like `.gitignore` lines, and matched against paths
relative to the server root (`/plugins/Licensed.jar`).

- Blank lines and lines starting with `#` are ignored. Start a line with `\#` or `\!` to match a
  literal `#` or `!`.
- `!pattern` negates. A later negated line re-allows what an earlier line matched.
- A trailing `/` limits a pattern to directories. A directory pattern also covers everything
  beneath it, so `secrets/` protects `/secrets/a/b.txt`.
- A pattern without a `/` (other than a trailing one) matches a name at any depth: `*.key`
  matches `/a/b/token.key`. A pattern containing a `/` is anchored to the root, and a leading `/`
  is optional: `/plugins/*.jar` and `plugins/*.jar` both match only `/plugins/*.jar` files.
- `*` matches anything except `/`, `?` matches one character except `/`, `**` matches across
  directories (`plugins/**` matches everything under `plugins/`), and `[abc]` / `[!abc]` match a
  character class.
- Every other character is literal. A line that cannot be compiled is matched literally and a
  warning is logged, so it can never silently stop protecting anything.
- Names may contain newlines and other unusual characters; rules match them as written.

## Hidden and protected

| | Hidden (`file_hidden`) | Protected (`file_denylist`) |
|---|---|---|
| Listed | No | Yes, flagged `"protected": true` |
| Stat | Not found | Returned |
| Read, download | Not found | Refused (403) |
| Write, create, upload, pull, copy | Not found | Refused (403) |
| Delete, rename, chmod, chtimes | Not found | Refused (403) |
| Directory containing one | n/a | Refused (403, see below) |
| Archives and backups | Left out | Left out |
| Restore | Entry skipped | Entry skipped |

Hidden takes precedence over protected. A hidden path answers exactly as a path that does not
exist, so its existence is not revealed. A directory that contains any restricted entry, hidden
or protected, is refused with the same message, so the two cannot be told apart by that either.
Protected entries are visible on purpose: users can see that a file is there and that it is
locked.

A symbolic link is restricted if its own name is restricted, or if the location it points to is.
Directories are checked as a whole: renaming a directory is refused if its contents would be
restricted under their new names too, which stops files being planted under a restricted name.

## Hard links

When any rule is configured on a server, a regular file that has more than one name cannot be read,
written, copied, or have its mode or times changed through Wings (403, "Hardlinked files cannot be
accessed on servers with protected files."). This stops a file being reached through a second name
that the rules do not cover. Deleting one of the names is allowed. Archives and backups leave such
files out. Servers with no rules are unaffected.

## Which channels are enforced

Enforced (through the restricted view of the filesystem):

- HTTP file API: contents, list-directory, write, rename, copy, delete, create-directory,
  compress, decompress, chmod, and file upload.
- Downloads: `/download/file`, and the destination of remote pulls.
- SFTP: every read, write, list, stat, rename, delete, chmod, symlink, and mkdir.
- Backups created by Wings, and restores (restricted entries are skipped, never overwritten; a
  truncating restore keeps them).

Not enforced: the server process itself, installation scripts, the egg config-file parser, server
transfers and disk usage. These are internal to Wings or to the container and use the unrestricted
filesystem, as they always have.

Restricted paths are checked by descriptor, not by path string. Each directory on the way is opened
without following symbolic links, the location the descriptor really refers to is read back from
`/proc/self/fd`, and the operation is performed through that same descriptor.

## Limitations

These are inherent to rules that are based on names. Read them before relying on the rules.

1. **Anything inside the container can bypass the rules.** The rules gate Wings' channels only.
   A process in the container can read every file in the volume, and boot-time permission checks
   (`check_permissions_on_boot`, on by default) make the whole volume owned by the server user. A
   process there can therefore rename or copy a protected file to an unprotected name and then reach
   the copy through Wings, or read the file directly. Hard links are refused, but a copy is not.
   The rules keep a file out of Wings' channels, not out of the server.
2. **Protect whole directories where they must stay locked.** A file pattern only covers the names it
   matches. `/plugins/*.jar` does not cover `/plugins/sub/x.jar` or `/plugins/x.zip`, and new files with
   those names can be created by a process inside the container. Protecting the directory itself
   (`/plugins/`) covers everything beneath it. Wings checks the real location of every path, so writes
   through symbolic links into a protected directory are refused either way.
3. **The egg config-file parser is internal** and follows symbolic links in parent directories, as
   it always has. Its writes are not restricted.
4. **Directory refusals reveal that a restricted entry exists** somewhere beneath the directory. The
   response does not say whether the entry is hidden or protected, but it does say that one is there.
5. **Races with directory renames are narrowed, not removed.** A directory that is verified and then
   renamed by a process in the container before the operation completes will still be acted on. Swaps
   of a directory for a symbolic link are refused.
6. **Protected files are visible.** Their names, sizes and modification times are listed and returned
   by Stat. Their content is not, and it is not sniffed for a MIME type either.
7. **Changes apply on sync.** Rules are replaced when the server configuration is synced with the
   Panel. A check that is running at the moment of the change may complete with the old rules.
