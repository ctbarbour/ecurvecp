-define(HELLO_PKT_PREFIX, "QvnQ5XlH").
-define(COOKIE_PKT_PREFIX, "RL3aNMXK").
-define(INITIATE_PKT_PREFIX, "QvnQ5XlI").
-define(SERVER_MESSAGE_PKT_PREFIX, "RL3aNMXM").
-define(CLIENT_MESSAGE_PKT_PREFIX, "QvnQ5XlM").

-type message_type() :: hello | cookie | initiate
  | server_message | client_message.
-type key()               :: <<_:32>>.
-type key_pair()          :: #{public => key(), secret => key()}.
-type nonce()             :: <<_:8>> | short_term_nonce() | long_term_nonce().
-type short_term_nonce()  :: <<_:16>>.
-type long_term_nonce()   :: <<_:24>>.
-type nonce_string()      :: <<_:24>>.
-type extension()         :: <<_:16>>.
-type cookie()            :: <<_:96>>.
