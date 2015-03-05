-module(ecurvecp_codec).

-include("ecurvecp.hrl").

-export([new_client_codec/5,
         new_server_codec/3,
         encode_hello_packet/1,
         encode_cookie_packet/1,
         decode_curvecp_packet/2,
         generate_short_term_keypair/1,
         rotate_minute_keys/1,
         generate_minute_key/0]).

-ifdef(TEST).
-export([validate_codec_pair/3]).
-endif.

-record(server_codec, {
    server_long_term_public_key,
    server_long_term_secret_key,
    server_short_term_public_key,
    server_short_term_secret_key,
    client_long_term_public_key,
    client_short_term_public_key,
    minute_key,
    prev_minute_key,
    shared_key,
    cookie,
    server_extension,
    client_extension
  }).

-record(client_codec, {
    client_long_term_public_key,
    client_long_term_secret_key,
    client_short_term_public_key,
    client_short_term_secret_key,
    server_long_term_public_key,
    server_short_term_public_key,
    cookie,
    shared_key,
    client_extension,
    server_extension
  }).

-opaque client_codec()  :: #client_codec{}.
-opaque server_codec()  :: #server_codec{}.

-export_type([client_codec/0, server_codec/0]).

new_client_codec(CLTPK, CLTSK, CE, SLTPK, SE) ->
  #client_codec{server_long_term_public_key=SLTPK,
                client_long_term_public_key=CLTPK,
                client_long_term_secret_key=CLTSK,
                server_extension=SE,
                client_extension=CE}.

new_server_codec(SLTPK, SLTSK, SE) ->
  #server_codec{server_long_term_public_key=SLTPK,
                server_long_term_secret_key=SLTSK,
                server_extension=SE}.

generate_short_term_keypair(#client_codec{} = Codec) ->
  #{public := CSTPK, secret := CSTSK} = enacl:box_keypair(),
  Codec#client_codec{client_short_term_public_key=CSTPK,
                     client_short_term_secret_key=CSTSK};
generate_short_term_keypair(#server_codec{} = Codec) ->
  #{public := SSTPK, secret := SSTSK} = enacl:box_keypair(),
  Codec#server_codec{server_short_term_public_key=SSTPK,
                     server_short_term_secret_key=SSTSK}.

rotate_minute_keys(#server_codec{minute_key=undefined} = Codec) ->
  MinuteKey = generate_minute_key(),
  rotate_minute_keys(Codec#server_codec{minute_key=MinuteKey});
rotate_minute_keys(#server_codec{} = Codec) ->
  #server_codec{minute_key=PrevMinuteKey} = Codec,
  MinuteKey = generate_minute_key(),
  _Ref = erlang:send_after(60000, self(), rotate),
  Codec#server_codec{minute_key=MinuteKey, prev_minute_key=PrevMinuteKey}.

generate_minute_key() ->
  enacl:randombytes(32).

encode_hello_packet(Codec) ->
  #client_codec{server_long_term_public_key=SLTPK,
                client_short_term_public_key=CSTPK,
                client_short_term_secret_key=CSTSK,
                server_extension=SE,
                client_extension=CE} = Codec,

  Zeros = binary:copy(<<0>>, 64),
  Nonce = ecurvecp_nonces:short_term_nonce(CSTSK),
  NonceString = ecurvecp_nonces:nonce_string(hello, Nonce),
  Box = enacl:box(Zeros, NonceString, SLTPK, CSTSK),
  <<?HELLO, SE/binary, CE/binary, CSTPK/binary, Zeros/binary, Nonce/binary, Box/binary>>.

encode_cookie_packet(#server_codec{} = Codec) ->
  #server_codec{client_short_term_public_key=CSTPK,
                server_long_term_secret_key=SLTSK,
                server_short_term_public_key=SSTPK,
                minute_key=MK,
                client_extension=CE,
                server_extension=SE} = Codec,

  Nonce = ecurvecp_nonces:long_term_nonce_counter(SLTSK),
  NonceString = ecurvecp_nonces:nonce_string(cookie, Nonce),
  Cookie = encode_cookie(CSTPK, SSTPK, MK),
  PlainText = <<SSTPK/binary, Cookie/binary>>,
  Box = enacl:box(PlainText, NonceString, CSTPK, SLTSK),
  <<?COOKIE, CE/binary, SE/binary, Nonce/binary, Box/binary>>.

encode_cookie(ClientShortTermPubKey, ServerShortTermSecKey, MinuteKey) ->
  Msg = <<ClientShortTermPubKey/binary, ServerShortTermSecKey/binary>>,
  Nonce = ecurvecp_nonces:long_term_nonce_timestamp(),
  NonceString = ecurvecp_nonces:nonce_string(minute_key, Nonce),
  Box = enacl:secretbox(Msg, NonceString, MinuteKey),
  <<Nonce/binary, Box/binary>>.


decode_curvecp_packet(<<?HELLO, SE:16/binary, CE:16/binary, CSTPK:32/binary,
                        _Z:64/binary, Nonce:8/binary, Box:80/binary>>,
                      #server_codec{} = Codec) ->
  true = decode_hello_packet_box(Nonce, Box, CSTPK, Codec),
  Codec#server_codec{server_extension=SE, client_extension=CE,
                     client_short_term_public_key=CSTPK};

decode_curvecp_packet(<<?COOKIE, _CE:16/binary, _SE:16/binary,
                        Nonce:16/binary,
                        Box:144/binary>>, #client_codec{} = Codec) ->
  decode_cookie_body(Nonce, Box, Codec).

decode_hello_packet_box(Nonce, Box, CSTPK, Codec) ->
  #server_codec{server_long_term_secret_key=SLTSK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(hello, Nonce),
  {ok, Contents} = enacl:box_open(Box, NonceString, CSTPK, SLTSK),
  verify_hello_box_contents(Contents).

verify_hello_box_contents(<<First:32/binary, Second:32/binary>>) ->
  Zeros = binary:copy(<<0>>, 32),
  enacl:verify_32(First, Zeros) andalso enacl:verify_32(Second, Zeros);
verify_hello_box_contents(_Contents) ->
  false.

decode_cookie_body(Nonce, Box, Codec) ->
  #client_codec{server_long_term_public_key=SLTPK,
                client_short_term_secret_key=CSTSK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(cookie, Nonce),
  {ok, Contents} = enacl:box_open(Box, NonceString, SLTPK, CSTSK),
  decode_cookie_box_contents(Contents, Codec).

decode_cookie_box_contents(<<SSTPK:32/binary, Cookie:96/binary>>, Codec) ->
  Codec#client_codec{server_short_term_public_key=SSTPK, cookie=Cookie}.

-ifdef(TEST).

validate_codec_pair(_CC, _SC, []) ->
  false;
validate_codec_pair(CC, SC, [H]) when is_atom(H) ->
  validate_codec_pair(CC, SC, H);
validate_codec_pair(CC, SC, [H|T]) ->
  case validate_codec_pair(CC, SC, H) of
    true ->
      validate_codec_pair(CC, SC, T);
    false ->
      false
  end;
validate_codec_pair(CC, SC, client_extension) ->
  CC#client_codec.client_extension =:= SC#server_codec.client_extension;
validate_codec_pair(CC, SC, server_extension) ->
  CC#client_codec.server_extension =:= SC#server_codec.server_extension;
validate_codec_pair(CC, SC, server_long_term_public_key) ->
  CC#client_codec.server_long_term_public_key =:= SC#server_codec.server_long_term_public_key;
validate_codec_pair(CC, SC, server_short_term_public_key) ->
  CC#client_codec.server_short_term_public_key =:= SC#server_codec.server_short_term_public_key;
validate_codec_pair(CC, SC, client_long_term_public_key) ->
  CC#client_codec.client_long_term_public_key =:= SC#server_codec.client_long_term_public_key;
validate_codec_pair(CC, SC, client_short_term_public_key) ->
  CC#client_codec.client_short_term_public_key =:= SC#server_codec.client_short_term_public_key;
validate_codec_pair(CC, SC, cookie) ->
  CC#client_codec.cookie =:= SC#server_codec.cookie.

-endif.
