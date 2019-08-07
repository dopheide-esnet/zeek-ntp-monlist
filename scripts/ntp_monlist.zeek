module NTP;

export {
	redef enum Notice::Type += {
		NTP_Monlist_Queries,
		};

	# The code value maps to the NTP mode type - for now I am mostly
	#  interested in control messages.
	#
	# Mode	Description
	# 0	reserved.
	# 1	Symmetric active.
	# 2	Symmetric passive.
	# 3	Client.
	# 4	Server.
	# 5	Broadcast.
	# 6	NTP control message.
	# 7	private use.
	const NTP_RESERVED = 0;
	const NTP_SYM_ACTIVE = 1;
	const NTP_SYM_PASSIVE = 2;
	const NTP_CLIENT = 3;
	const NTP_SERVER = 4;
	const NTP_BROADCAST = 5;
	const NTP_CONTROL = 6;
	const NTP_PRIVATE = 7;

	# So we don't warn more than one time
	global ntp_host: set[addr] &write_expire=1day &redef;

	} # end export


event ntp_message(c: connection, is_orig: bool, msg: NTP::Message)
	{

	if ((msg$mode == NTP_PRIVATE) || (msg$mode == NTP_CONTROL)) {

		if ( (c$id$orig_h !in ntp_host)  && ! Site::is_neighbor_addr(c$id$resp_h) && ! Site::is_local_addr(c$id$resp_h)) {

			add ntp_host[c$id$orig_h];
			NOTICE([$note=NTP::NTP_Monlist_Queries,
				$conn=c,
				$suppress_for=6hrs,
				$msg=fmt("NTP monlist queries"),
				$identifier=cat(c$id$orig_h)]);
			}
		}
	}

