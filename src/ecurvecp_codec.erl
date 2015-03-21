-module(ecurvecp_codec).

-include("ecurvecp.hrl").

-export([encode_hello_packet/5,
         encode_cookie_packet/6,
         encode_cookie/3,
         encode_initiate_packet/9,
         encode_vouch/3,
         encode_domain_name/1,
         encode_client_msg_packet/5,
         encode_client_msg_packet/6,
         encode_server_msg_packet/4,
         encode_server_msg_packet/5,
         decode_hello_packet/1,
         decode_cookie_packet/1,
         decode_cookie_box/3,
         decode_cookie_box_contents/1,
         decode_initiate_packet/1,
         decode_initiate_box/3,
         decode_server_msg_packet/1,
         decode_server_msg_box/2,
         decode_server_msg_box/3,
         decode_client_msg_packet/1,
         decode_client_msg_box/2,
         decode_client_msg_box/3,
         verify_cookie/2,
         verify_initiate_box_contents/3,
         verify_hello_box/2,
         keypair/0,
         shared_key/2,
         minute_key/0]).

keypair() ->
  #{public := PK, secret := SK} = enacl:box_keypair(),
  {PK, SK}.

minute_key() ->
  enacl:randombytes(32).

shared_key(PK, SK) ->
  enacl:box_beforenm(PK, SK).

encode_hello_packet(CSTPK, CSTSK, SLTPK, SE, CE) ->
  Zeros = binary:copy(<<0>>, 64),
  Nonce = ecurvecp_nonces:short_term_nonce(CSTSK),
  NonceString = ecurvecp_nonces:nonce_string(hello, Nonce),
  Box = enacl:box(Zeros, NonceString, SLTPK, CSTSK),
  <<?HELLO, SE/binary, CE/binary, CSTPK/binary, Zeros/binary, Nonce/binary, Box/binary>>.

decode_hello_packet(<<?HELLO, SE:16/binary, CE:16/binary, CSTPK:32/binary,
                      _Z:64/binary, Nonce:8/binary, Box:80/binary>>) ->
  #hello_packet{server_extension=SE, client_extension=CE,
                client_short_term_public_key=CSTPK,
                nonce=Nonce, box=Box}.

verify_hello_box(Hello, SLTSK) ->
  #hello_packet{client_short_term_public_key=CSTPK, nonce=Nonce, box=Box} = Hello,
  NonceString = ecurvecp_nonces:nonce_string(hello, Nonce),
  {ok, Contents} = enacl:box_open(Box, NonceString, CSTPK, SLTSK),
  verify_hello_box_contents(Contents).

verify_hello_box_contents(<<First:32/binary, Second:32/binary>>) ->
  Zeros = binary:copy(<<0>>, 32),
  enacl:verify_32(First, Zeros) andalso enacl:verify_32(Second, Zeros);
verify_hello_box_contents(_Contents) ->
  false.

encode_cookie(CSTPK, SSTSK, MK) ->
  Msg = <<CSTPK/binary, SSTSK/binary>>,
  Nonce = ecurvecp_nonces:long_term_nonce_timestamp(),
  NonceString = ecurvecp_nonces:nonce_string(minute_key, Nonce),
  Box = enacl:secretbox(Msg, NonceString, MK),
  <<Nonce/binary, Box/binary>>.

encode_cookie_packet(CSTPK, SSTPK, SLTSK, Cookie, SE, CE) ->
  Nonce = ecurvecp_nonces:long_term_nonce_counter(SLTSK),
  NonceString = ecurvecp_nonces:nonce_string(cookie, Nonce),
  PlainText = <<SSTPK/binary, Cookie/binary>>,
  ok = error_logger:info_msg("[~p] CSTPK: ~p~nSLTSK: ~p~n", [self(), CSTPK, SLTSK]),
  Box = enacl:box(PlainText, NonceString, CSTPK, SLTSK),
  <<?COOKIE, CE/binary, SE/binary, Nonce/binary, Box/binary>>.

decode_cookie_packet(<<?COOKIE, CE:16/binary, SE:16/binary,
                       Nonce:16/binary, Box:144/binary>>) ->
  #cookie_packet{client_extension=CE, server_extension=SE,
                 nonce=Nonce, box=Box}.

decode_cookie_box(CookiePacket, PK, SK) ->
  #cookie_packet{nonce=Nonce, box=Box} = CookiePacket,
  NonceString = ecurvecp_nonces:nonce_string(cookie, Nonce),
  {ok, Contents} = enacl:box_open(Box, NonceString, PK, SK),
  decode_cookie_box_contents(Contents).

decode_cookie_box_contents(<<SSTPK:32/binary, Cookie:96/binary>>) ->
  #{server_short_term_public_key => SSTPK, cookie => Cookie}.

encode_vouch(CLTSK, CSTPK, SLTPK) ->
  Nonce = ecurvecp_nonces:long_term_nonce_counter(CLTSK),
  NonceString = ecurvecp_nonces:nonce_string(vouch, Nonce),
  Box = enacl:box(CSTPK, NonceString, SLTPK, CLTSK),
  <<Nonce/binary, Box/binary>>.

encode_domain_name(DomainName) ->
  Bin = list_to_binary(DomainName),
  case (256 - size(Bin) rem 256) rem 256 of
    0 ->
      Bin;
    N ->
      <<Bin/binary, 0:(N*8)>>
  end.

encode_initiate_packet(CLTPK, CSTPK, CSTSK, SSTPK, Vouch, Cookie, DomainName, SE, CE) ->
  PlainText = <<CLTPK/binary, Vouch/binary, DomainName/binary, "CurveCPI">>,
  Nonce = ecurvecp_nonces:short_term_nonce(CSTSK),
  NonceString = ecurvecp_nonces:nonce_string(initiate, Nonce),
  Box = enacl:box(PlainText, NonceString, SSTPK, CSTSK),
  <<?INITIATE, SE/binary, CE/binary, CSTPK/binary, Cookie/binary, Nonce/binary, Box/binary>>.

decode_initiate_packet(<<?INITIATE, SE:16/binary, CE:16/binary, CSTPK:32/binary,
                        Cookie:96/binary, Nonce:8/binary, Box/binary>>) ->
  #initiate_packet{server_extension=SE, client_extension=CE,
                   client_short_term_public_key=CSTPK,
                   cookie=Cookie, nonce=Nonce, box=Box}.

decode_initiate_box(Initiate, PK, SK) ->
  #initiate_packet{nonce=Nonce, box=Box} = Initiate,
  NonceString = ecurvecp_nonces:nonce_string(initiate, Nonce),
  {ok, Contents} = enacl:box_open(Box, NonceString, PK, SK),
  Contents.

verify_cookie(_, []) ->
  false;
verify_cookie(Initiate, [MK|PMK]) ->
  #initiate_packet{cookie= <<Nonce:16/binary, Box/binary>>, client_short_term_public_key=CSTPK} = Initiate,
  NonceString = ecurvecp_nonces:nonce_string(minute_key, Nonce),
  case enacl:secretbox_open(Box, NonceString, MK) of
    {ok, <<BoxedCSTPK:32/binary, _:32/binary>>} ->
      enacl:verify_32(BoxedCSTPK, CSTPK);
    _ ->
      verify_cookie(Initiate, PMK)
  end.

verify_initiate_box_contents(<<CLTPK:32/binary, Vouch:64/binary,
                               DomainName:256/binary, _Message/binary>>, CSTPK, SLTPK) ->
  verify_vouch(Vouch, CLTPK, CSTPK, SLTPK) andalso
    verify_domain_name(DomainName).

verify_vouch(<<Nonce:16/binary, Box:48/binary>>, CLTPK, CSTPK, SLTPK) ->
  NonceString = ecurvecp_nonces:nonce_string(vouch, Nonce),
  {ok, VouchedCSTPK} = enacl:box_open(Box, NonceString, CLTPK, SLTPK),
  enacl:verify_32(VouchedCSTPK, CSTPK).

verify_domain_name(_DomainName) ->
  true.

encode_client_msg_packet(Message, CSTPK, PK, SK, SE, CE) ->
  Nonce = ecurvecp_nonces:short_term_nonce(SK),
  NonceString = ecurvecp_nonces:nonce_String(client_message, Nonce),
  Box = enacl:box(Message, NonceString, PK, SK),
  <<?CLIENT_M, SE/binary, CE/binary, CSTPK/binary, Nonce/binary, Box/binary>>.

encode_client_msg_packet(Message, CSTPK, SharedKey, SE, CE) ->
  Nonce = ecurvecp_nonces:short_term_nonce(SharedKey),
  NonceString = ecurvecp_nonces:nonce_string(client_message, Nonce),
  Box = enacl:box_afternm(Message, NonceString, SharedKey),
  <<?CLIENT_M, SE/binary, CE/binary, CSTPK/binary, Nonce/binary, Box/binary>>.

decode_client_msg_packet(<<?CLIENT_M, CE:16/binary, SE:16/binary, Nonce:8/binary, Box/binary>>) ->
  #client_msg_packet{client_extension=CE, server_extension=SE,
                     nonce=Nonce, box=Box}.

decode_client_msg_box(ClientMsg, SharedKey) ->
  #client_msg_packet{nonce=Nonce, box=Box} = ClientMsg,
  NonceString = ecurvecp_nonces:nonce_string(client_message, Nonce),
  enacl:box_open_afternm(Box, NonceString, SharedKey).

decode_client_msg_box(ClientMsg, PK, SK) ->
  #client_msg_packet{nonce=Nonce, box=Box} = ClientMsg,
  NonceString = ecurvecp_nonces:nonce_string(client_message, Nonce),
  enacl:box_open(Box, NonceString, PK, SK).

encode_server_msg_packet(Message, CSTPK, SSTSK, SE, CE) ->
  Nonce = ecurvecp_nonces:short_term_nonce(SSTSK),
  NonceString = ecurvecp_nonces:nonce_string(server_message, Nonce),
  Box = enacl:box(Message, NonceString, CSTPK, SSTSK),
  <<?SERVER_M, CE/binary, SE/binary, Nonce/binary, Box/binary>>.

encode_server_msg_packet(Message, SharedKey, SE, CE) ->
  Nonce = ecurvecp_nonces:short_term_nonce(SharedKey),
  NonceString = ecurvecp_nonces:nonce_string(server_message, Nonce),
  Box = enacl:box_afternm(Message, NonceString, SharedKey),
  <<?SERVER_M, CE/binary, SE/binary, Nonce/binary, Box/binary>>.

decode_server_msg_packet(<<?SERVER_M, CE:16/binary, SE:16/binary, Nonce:8/binary,
                           Box/binary>>) ->
  #server_msg_packet{client_extension=CE,
                     server_extension=SE,
                     nonce=Nonce,
                     box=Box}.

decode_server_msg_box(ServerMsg, SharedKey) ->
  #server_msg_packet{nonce=Nonce, box=Box} = ServerMsg,
  NonceString = ecurvecp_nonces:nonce_string(server_message, Nonce),
  enacl:box_open_afternm(Box, NonceString, SharedKey).

decode_server_msg_box(ServerMsg, PK, SK) ->
  #server_msg_packet{nonce=Nonce, box=Box} = ServerMsg,
  NonceString = ecurvecp_nonces:nonce_string(server_message, Nonce),
  enacl:box_open(Box, NonceString, PK, SK).
