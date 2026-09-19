# docs/assets/demo.tape - charmbracelet/vhs script for dezhan's intro demo.
# Render with:  vhs docs/assets/demo.tape   (produces docs/assets/demo.gif)
# Output is reproduced by the shims in docs/assets/demo.sh and the captured
# dashboard frame in docs/assets/dashboard.frame; see those files.

Output demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1120
Set Height 760
Set Padding 24
Set Margin 12
Set BorderRadius 10
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Hide
Type "source ./demo.sh; export DEZHAN_ENDPOINT=http://127.0.0.1:8080; clear" Enter
Show

Type "#  dezhanctl - control CLI and live dashboard for an immutable dezhan vault"
Sleep 900ms
Enter
Sleep 400ms

Type "dezhanctl health"
Sleep 300ms
Enter
Sleep 900ms

Type "dezhanctl put q3-close.tar --file ./q3-close.tar --mode compliance --retain 86400"
Sleep 300ms
Enter
Sleep 1300ms

Type "dezhanctl stat q3-close.tar"
Sleep 300ms
Enter
Sleep 1500ms

# every path that would destroy a retained object is refused
Type "dezhanctl del q3-close.tar"
Sleep 300ms
Enter
Sleep 2000ms

# the live dashboard: health, seal state, objects, audit chain, scrub
Hide
Type "clear" Enter
Show
Type "dezhanctl dashboard"
Sleep 300ms
Enter
Sleep 3600ms
