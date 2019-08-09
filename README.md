# zeek-ntp-monlist
NTP monlist detection, updated for Zeek 3.0.0+

Credit: I believe the original ntp.bro script was written by the one and only
Scott Campbell:
https://github.com/set-element/misc-scripts/commits/master/ntp.bro

However, I honestly have no idea who made the first monlist detection version.

Zeek 3.0.0 started providing a script-land NTP module and logging which
conflicted with the older ntp-monlist.bro policy that built those structures
as well.

This package very simply just ripped out all that other code.

