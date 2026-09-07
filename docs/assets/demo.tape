# docs/assets/demo.tape - charmbracelet/vhs script for dezhan's intro demo.
# Render with:  vhs docs/assets/demo.tape   (produces docs/assets/demo.gif)
# The shims in docs/assets/demo.sh reproduce real dezhan_server / dezhan_cli /
# aws-s3 output; see that file for the sources.

Output demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 800
Set Padding 24
Set Margin 12
Set BorderRadius 10
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0

Hide
Type "source ./demo.sh; clear" Enter
Show

Type "#  dezhan - an S3 vault where deleting before expiry is proved impossible, not just blocked."
Sleep 1000ms
Enter
Sleep 500ms

Type "dezhan_cli health"
Sleep 300ms
Enter
Sleep 1300ms

# drop-in S3 data plane: any size, multipart, parallel per-chunk encoding
Type "aws s3 mb s3://backups"
Sleep 300ms
Enter
Sleep 1200ms
Type "aws s3 cp ./q3-close.tar s3://backups/"
Sleep 300ms
Enter
Sleep 1900ms
Type "aws s3 ls s3://backups"
Sleep 300ms
Enter
Sleep 1600ms

# lock it under a one-day compliance retention
Type "dezhan_cli put q3-close.tar report compliance 86400"
Sleep 300ms
Enter
Sleep 1800ms

# every destroying path is refused while it is retained
Type "aws s3 rm s3://backups/q3-close.tar"
Sleep 300ms
Enter
Sleep 1700ms
Type "dezhan_cli del report"
Sleep 300ms
Enter
Sleep 2000ms

# restores keep working - immutability is not read-only
Type "dezhan_cli get report"
Sleep 300ms
Enter
Sleep 1800ms

# what dezhan DOES delete: an object whose retention has elapsed
Type "dezhan_cli put scratch tmp.bin compliance 0"
Sleep 300ms
Enter
Sleep 900ms
Type "dezhan_cli del scratch"
Sleep 300ms
Enter
Sleep 2000ms

Type "dezhan_cli metrics"
Sleep 300ms
Enter
Sleep 2200ms

Type "#  integrity core: 325 SPARK proof checks, 0 unproved - re-checked by gnatprove on every commit"
Sleep 700ms
Enter
Sleep 1400ms
Type "#  the delete-before-expiry path is machine-checked unreachable. immutability is a theorem, not a setting."
Sleep 700ms
Enter
Sleep 2600ms
