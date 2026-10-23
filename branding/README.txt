BRANDING RULES - CELLARDOOR

1. Plain 7-bit ASCII only. No box-drawing, emoji or Unicode art.
2. 72 columns maximum, so it fits any terminal, email and issue tracker.
3. Color is optional decoration. Every screen must read correctly
   without it.
   Respect NO_COLOR. Never use color as the only signal.
4. No runtime dependency for art. Art is plain text the program prints.
   (No figlet, curses or TUI library. Line-based prompts work over SSH,
   serial, Windows, macOS and Linux alike.)
5. Door states are fixed: [ ] open, [/] ajar, [#] closed.
6. Messages say what happened and what to do next. Never print secrets,
   tokens, hashes or full invite links after the first display.
7. Every example uses made-up data: example.com addresses and zero or
   repeating ids. Nothing real goes in the repo.
8. Write cellardoor in running text and CellarDoor in titles.

Files
  logo.txt     large and small logo
  cli-mockups.txt   install, configure, users, invite, audit, errors
