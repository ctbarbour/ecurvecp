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

-record(cookie_packet, {
    server_extension,
    client_extension,
    cookie,
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

-record(server_msg_packet, {
    server_extension,
    client_extension,
    nonce,
    box
  }).

-type hello_packet()      :: #hello_packet{}.
-type cookie_packet()     :: #cookie_packet{}.
-type initiate_packet()   :: #initiate_packet{}.
-type client_msg_packet() :: #client_msg_packet{}.
-type server_msg_packet() :: #server_msg_packet{}.

-type key() :: <<_:32>>.
-type extension() :: <<_:16>>.
