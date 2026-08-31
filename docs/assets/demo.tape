# docs/assets/demo.tape - charmbracelet/vhs script for dezhan's intro demo.
# Render with:  vhs docs/assets/demo.tape   (produces docs/assets/demo.gif)
# The shims in docs/assets/demo.sh reproduce real dezhan_server / dezhan_cli
# output; see that file for the sources.

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

# --- setup (hidden): load the scripted shims ---------------------------------
Hide
Type "source ./demo.sh; clear" Enter
Show

# --- title -------------------------------------------------------------------
Type "#  dezhan - an air-gapped, immutable backup vault. Deleting before expiry is proved impossible, not just blocked."
Sleep 1100ms
Enter
Sleep 500ms

# --- 1) the vault is up ------------------------------------------------------
Type "dezhan_cli health"
Sleep 300ms
Enter
Sleep 1400ms

# --- 2) store an object under a retention lock -------------------------------
Type "#  store a compliance-mode object under a one-day retention"
Enter
Sleep 500ms
Type "dezhan_cli put report q3-close.tar compliance 86400"
Sleep 300ms
Enter
Sleep 1800ms

# --- 3) reads / restores keep working ----------------------------------------
Type "#  restores keep working - immutability is not read-only"
Enter
Sleep 500ms
Type "dezhan_cli get report"
Sleep 300ms
Enter
Sleep 1800ms

# --- 4) every destroying path is refused -------------------------------------
Type "#  now it is under retention. every path that would destroy it is refused."
Enter
Sleep 700ms
Type "dezhan_cli del report"
Sleep 300ms
Enter
Sleep 2200ms

Type "#  a governance-mode object is protected the same way"
Enter
Sleep 500ms
Type "dezhan_cli del audit-2024"
Sleep 300ms
Enter
Sleep 2200ms

Type "#  and a moved clock cannot expire it early - the vault seals instead of releasing"
Enter
Sleep 2000ms

# --- 5) what dezhan does delete: expired retention ---------------------------
Type "#  what dezhan DOES delete: an object whose retention has elapsed"
Enter
Sleep 500ms
Type "dezhan_cli put scratch tmp.bin compliance 0"
Sleep 300ms
Enter
Sleep 900ms
Type "dezhan_cli del scratch"
Sleep 300ms
Enter
Sleep 2000ms

# --- 6) the payoff: measured integrity, proved core --------------------------
Type "#  integrity is measured, and the core is proved"
Enter
Sleep 500ms
Type "dezhan_cli metrics"
Sleep 300ms
Enter
Sleep 2400ms

Type "#  integrity core: 325 SPARK proof checks, 0 unproved - re-checked by gnatprove on every commit"
Sleep 800ms
Enter
Sleep 1400ms
Type "#  the delete-before-expiry path is machine-checked unreachable. immutability is a theorem, not a setting."
Sleep 800ms
Enter
Sleep 2800ms
