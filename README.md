# zeek-ntp-monlist
NTP monlist detection, updated for Zeek 3.0.0+

Zeek 3.0.0 started providing a script-land NTP module and logging which
conflicted with the older ntp-monlist.bro policy that built those structures
as well.

This package very simply just ripped out all that other code.

