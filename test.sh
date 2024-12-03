#!/usr/bin/env expect

set smtp_server "127.0.0.1"
set smtp_port "25"

# Start the telnet session
spawn telnet $smtp_server $smtp_port

# Interact with the SMTP server
expect "220*"               			 ;# Wait for server greeting
send "helo test.de\r"       			 ;# Send HELO command
expect "250*"                            ;# Wait for response

send "mail from: <test@test.de>\r"       ;# Send MAIL FROM command
expect "250*"                            ;# Wait for response

send "rcpt to: <test@test.de>\r"         ;# Send RCPT TO command
expect "250*"                            ;# Wait for response

send "rcpt to: <test2@test.de>\r"        ;# Send RCPT TO command
expect "250*"                            ;# Wait for response

send "data\r"                            ;# Start the message body
expect "354*"                            ;# Wait for servers continuation response

send "abcdefghijklmnopqrstuvwxyz\r"      ;# Send random message content
send "abcdefghijklmnopqrstuvwxyz\r"      ;# Send random message content
send ".\r"                               ;# End the message with a dot
expect "250*"                            ;# Wait for response

# Close the connection
send "quit\r"
expect eof
