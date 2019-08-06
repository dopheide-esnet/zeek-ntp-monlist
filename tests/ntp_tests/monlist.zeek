# @TEST-EXEC: zeek -C -r $TRACES/ntp-monlist.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut msg note < notice.log > notice.tmp && mv notice.tmp notice.log
# @TEST-EXEC: btest-diff notice.log
