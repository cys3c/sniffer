all: packet_parser tcp_parser email_parser cookie_parser

packet_parser:
	clang -o packet_parser packet_parser.c -lpcap

tcp_parser:
	clang -o tcp_parser tcp_parser.c -lpcap

email_parser:
	clang -o email_parser email_parser.c -lpcap

cookie_parser:
	clang -o cookie_parser cookie_parser.c -lpcap

clean:
	rm -rf packet_parser tcp_parser email_parser cookie_parser *.o
