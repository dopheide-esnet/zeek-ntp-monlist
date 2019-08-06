# @TEST-EXEC: bro -C -r $TRACES/ntp-monlist.pcap %INPUT
# @TEST-EXEC: bro-cut msg note < notice.log > notice.tmp && mv notice.tmp notice.log
# @TEST-EXEC: btest-diff notice.log
