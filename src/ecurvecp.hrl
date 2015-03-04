-define(HELLO, "QvnQ5XlH").
-define(COOKIE, "RL3aNMXK").
-define(INITIATE, "QvnQ5XlI").
-define(SERVER_M, "RL3aNMXM").
-define(CLIENT_M, "QvnQ5XlM").

-record(hello_packet, {
    server_extension,
    client_extension,
    client_short_term_public_key,
    nonce,
    box
  }).

-record(initiate_packet, {
    server_extension,
    client_extension,
    client_short_term_public_key,
    cookie,
    nonce,
    box
  }).

-record(client_msg_packet, {
    server_extension,
    client_extension,
    client_short_term_public_key,
    nonce,
    box
  }).
