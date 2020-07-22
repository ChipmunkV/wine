---
name: EAC Load Failure Bug Report.
about: Include this information if EAC fails to launch your game, or your game doesn't   accept
  EAC's presence.
title: ''
labels: ''
assignees: ''

---

First, make sure you're not running into a known issue.  Are you using a windows 7 prefix, is your build directory readable?  Do you have esync disabled?  Have you hidden wine exports?  Is your prefix updated?  If you answered no to any of these questions, resolve this first, then try again.

Secondly, the two most important things I need to help troubleshoot your issue are a wine log, with the `+thread,+process,warn+int,+pid,+winedevice,+fltmgr,+timestamp,+loaddll,+ntoskrnl` debug channels set, and your gamelauncher.log from your wine prefix's 'drive_c/users/*/Application Data/EasyAntiCheat' folder.

Also, please provide information on your setup, particularly:  where you got your wine build, how you are launching the game, and your CPU.
