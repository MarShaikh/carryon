# The README's demo: two machines, five commands.
#
# Re-record from the repo root with `vhs docs/demo/demo.tape`. It writes
# docs/demo/demo.gif and nothing outside /tmp/carryon-demo.
#
# It never touches your own agent, keychain or folders. Both "machines" are
# throwaway homes under /tmp/carryon-demo, built by seed.py. Each home's ~/Dropbox links
# to one folder, which stands in for a synced folder. PATH holds only what the
# demo needs, plus a stand-in for macOS security(1) that keeps each home's key
# in a file inside that home. carryon runs from this checkout through the
# `carryon` shim beside this file, which refuses any path outside
# /tmp/carryon-demo. The shell is zsh because Homebrew's bash 5.3 expands ~
# against the real home whatever HOME says.

Output docs/demo/demo.gif

Set Shell "zsh"
Set FontSize 15
Set Width 1200
Set Height 640
Set Padding 24
Set TypingSpeed 45ms
Set Theme "Builtin Dark"

Hide
Type `setopt interactive_comments` Enter
Type `export DEMO_SRC="$PWD" DEMO_PYTHON="$(command -v python3)" DEMO_ROOT=/tmp/carryon-demo` Enter
Type `rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/bin" "$DEMO_ROOT/dropbox"` Enter
Type `"$DEMO_PYTHON" docs/demo/seed.py "$DEMO_ROOT"` Enter
Type `cp docs/demo/carryon docs/demo/security "$DEMO_ROOT/bin/"` Enter
Type `for t in openssl basename tee cat clear; do ln -s "$(command -v $t)" "$DEMO_ROOT/bin/$t"; done` Enter
Type `for m in laptop desktop; do ln -s "$DEMO_ROOT/dropbox" "$DEMO_ROOT/$m/Dropbox"; done` Enter
Type `export PATH="$DEMO_ROOT/bin" HOME="$DEMO_ROOT/laptop" PROMPT='%F{cyan}laptop%f $ '` Enter
Type `cd ~ && clear` Enter
Show

Type "# On the first machine" Enter
Sleep 600ms
Type "carryon init --dest ~/Dropbox/carryon" Enter
Sleep 2.5s
Type "carryon push --apply" Enter
Sleep 2.5s
Type "carryon pair" Enter
Sleep 3.5s

Hide
Type `export CODE=$(/usr/bin/grep -oE '[A-Z0-9]{4}(-[A-Z0-9]{4}){3}' "$DEMO_ROOT/pair.out")` Enter
Type `export HOME="$DEMO_ROOT/desktop" PROMPT='%F{magenta}desktop%f $ '` Enter
Type `cd ~ && clear` Enter
Show

Type "# On the second machine, with the code pair printed" Enter
Sleep 600ms
Type "carryon init --join $CODE --dest ~/Dropbox/carryon" Enter
Sleep 2.5s
Type "carryon pull --apply" Enter
Sleep 5s
