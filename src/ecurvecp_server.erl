-module(ecurvecp_server).
-behavior(gen_fsm).

-export([start_link/2, start_link/3, start_link/4, handle_curvecp_packet/2]).
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
         code_change/4, terminate/3]).
-export([hello/2, initiate/2, finalize/2, message/2]).

-include("ecurvecp.hrl").

-record(codec, {
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

-record(st, {
    handshake_ttl                   = 60000,
    ttl                             = 360000,
    codec
  }).

handle_curvecp_packet(From, <<?HELLO, _/binary>> = Packet) ->
  {ok, Pid} = ecurvecp_server_sup:start_server(),
  gen_fsm:send_event(Pid, {hello, From, Packet});
handle_curvecp_packet(From, <<?INITIATE, Exts:32/binary, _/binary>> = Packet) ->
  dispatch(Exts, {initiate, From, Packet});
handle_curvecp_packet(From, <<?CLIENT_M, Exts:32/binary, _/binary>> = Packet) ->
  dispatch(Exts, {client_message, From, Packet}).

dispatch(<<_SE:16/binary, CE:16/binary>>, Msg) ->
  case lookup(CE) of
    {ok, ClientPid} ->
      gen_fsm:send_event(ClientPid, Msg);
    not_found ->
      ok
  end.

lookup(ClientExt) ->
  case catch(gproc:lookup_local_name({ecurvecp_server, ClientExt})) of
    {'EXIT', {badarg, _}} ->
      not_found;
    Pid ->
      {ok, Pid}
  end.

start_link(KeyPair, Extension) ->
  start_link(KeyPair, Extension, []).

start_link(#{public := PK, secret := SK}, Extension, Opts) ->
  start_link(PK, SK, Extension, Opts).

start_link(PK, SK, Extension, Opts) ->
  Args = [PK, SK, Extension, proplists:unfold(Opts)],
  gen_fsm:start_link(?MODULE, Args, []).

box_open(Box, Nonce, PK, SK) ->
  enacl:box_open(Box, Nonce, PK, SK).

box(Box, Nonce, PK, SK) ->
  enacl:box(Box, Nonce, PK, SK).

secretbox(Box, Nonce, PK) ->
  enacl:secretbox(Box, Nonce, PK).

secretbox_open(Box, Nonce, K) ->
  enacl:secretbox_open(Box, Nonce, K).

box_beforenm(PK, SK) ->
  enacl:box_beforenm(PK, SK).

box_afternm(Msg, Nonce, K) ->
  enacl:box_afternm(Msg, Nonce, K).

box_open_afternm(Box, Nonce, K) ->
  enacl:box_open_afternm(Box, Nonce, K).

generate_shared_key(Codec) ->
  #codec{client_short_term_public_key=CSTPK,
         server_short_term_secret_key=SSTSK} = Codec,
  SharedKey = box_beforenm(CSTPK, SSTSK),
  Codec#codec{shared_key=SharedKey}.

keypair() ->
  enacl:box_keypair().

verify_32(X, Y) ->
  enacl:verify_32(X, Y).

generate_minute_key() ->
  enacl:randombytes(32).

generate_short_term_keys(Codec) ->
  #{public := SSTPK, secret := SSTSK} = keypair(),
  Codec#codec{server_short_term_public_key=SSTPK,
              server_short_term_secret_key=SSTSK}.

parse_opts([], State) ->
  State;
parse_opts([{handshake_ttl, HTTL}|Rest], State) ->
  parse_opts(Rest, State#st{handshake_ttl=HTTL});
parse_opts([{ttl, TTL}|Rest], State) ->
  parse_opts(Rest, State#st{ttl=TTL});
parse_opts([_|Rest], State) ->
  parse_opts(Rest, State).

init([PK, SK, Extension, Opts]) ->
  Codec = rotate_minute_keys(
      #codec{server_long_term_public_key=PK,
             server_long_term_secret_key=SK,
             server_extension=Extension}),

  State = parse_opts(Opts, #st{codec=Codec}),
  {ok, hello, State}.

hello({hello, From, Packet}, State) ->
  #st{handshake_ttl=Timeout, codec=Codec0} = State,
  Codec = generate_short_term_keys(decode_hello_packet(Packet, Codec0)),
  CookiePacket = encode_cookie_packet(Codec),
  true = gproc:add_local_name({?MODULE, Codec#codec.client_extension}),
  ok = ecurvecp_udp:reply(From, CookiePacket),
  {next_state, initiate, State#st{codec=Codec}, Timeout};
hello(timeout, State) ->
  {stop, timeout, State}.

initiate({initiate, From, Packet}, State) ->
  #st{handshake_ttl=Timeout, codec=Codec0} = State,
  Codec = decode_initiate_packet(Packet, Codec0),
  MessagePacket = encode_server_message_packet(<<"Welcome">>, Codec),
  ok = ecurvecp_udp:reply(From, MessagePacket),
  {next_state, message, State#st{codec=Codec}, Timeout};
initiate(timeout, State) ->
  {stop, handshake_timeout, State}.

message({client_message, From, Packet}, State) ->
  #st{codec=Codec0} = State,
  {ok, ClientMessage, Codec} = decode_client_message_packet(Packet, Codec0),
  ServerMessagePacket = encode_server_message_packet(ClientMessage, Codec),
  ok = ecurvecp_udp:reply(From, ServerMessagePacket),
  {next_state, finalize, State#st{codec=Codec}, 0};
message(timeout, State) ->
  {stop, timeout, State}.

finalize(timeout, State) ->
  #st{ttl=Timeout} = State,
  Codec = generate_shared_key(State#st.codec),
  {next_state, message, State#st{codec=Codec}, Timeout}.

handle_event(_Event, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_sync_event(_Event, _From, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_info(rotate, StateName, StateData) ->
  Codec = rotate_minute_keys(StateData#st.codec),
  {next_state, StateName, StateData#st{codec=Codec}};
handle_info(_Info, StateName, StateData) ->
  {next_state, StateName, StateData}.

code_change(_OldVsn, StateName, StateData, _Extra) ->
  {ok, StateName, StateData}.

terminate(_Reason, _StateName, _StateData) ->
  ok.

decode_hello_packet(<<?HELLO, SE:16/binary, CE:16/binary, CSTPK:32/binary,
                      _Zeros:64/binary, Nonce:8/binary, Box:80/binary>>,
                    Codec) ->
  true = decode_hello_packet_box(Nonce, Box, CSTPK, Codec),
  Codec#codec{server_extension=SE, client_extension=CE,
              client_short_term_public_key=CSTPK}.

decode_hello_packet_box(Nonce, Box, CSTPK, Codec) ->
  #codec{server_long_term_secret_key=SLTSK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(hello, Nonce),
  {ok, Contents} = box_open(Box, NonceString, CSTPK, SLTSK),
  verify_hello_box_contents(Contents).

verify_hello_box_contents(<<First:32/binary, Second:32/binary>>) ->
  Zeros = <<0:256>>,
  verify_32(First, Zeros) andalso verify_32(Second, Zeros);
verify_hello_box_contents(_Contents) ->
  false.

encode_cookie_packet(Codec) ->
  #codec{client_short_term_public_key=CSTPK,
         server_long_term_secret_key=SLTSK,
         server_short_term_public_key=SSTPK,
         minute_key=MK,
         client_extension=CE,
         server_extension=SE} = Codec,

  Nonce = ecurvecp_nonces:long_term_nonce_counter(SLTSK),
  NonceString = ecurvecp_nonces:nonce_string(cookie, Nonce),
  Cookie = encode_cookie(CSTPK, SSTPK, MK),
  PlainText = <<SSTPK/binary, Cookie/binary>>,
  Box = box(PlainText, NonceString, CSTPK, SLTSK),
  <<?COOKIE, CE/binary, SE/binary, Nonce/binary, Box/binary>>.

encode_cookie(ClientShortTermPubKey, ServerShortTermSecKey, MinuteKey) ->
  Msg = <<ClientShortTermPubKey/binary, ServerShortTermSecKey/binary>>,
  Nonce = ecurvecp_nonces:long_term_nonce_timestamp(),
  NonceString = ecurvecp_nonces:nonce_string(minute_key, Nonce),
  Box = secretbox(Msg, NonceString, MinuteKey),
  <<Nonce/binary, Box/binary>>.

decode_initiate_packet(<<?INITIATE, _SE:16/binary, _CE:16/binary,
                         CSTPK:32/binary, Cookie:96/binary, Nonce:8/binary,
                         Box/binary>>, Codec) ->
  true = verify_cookie(Cookie, CSTPK, Codec),
  decode_initiate_box(Nonce, Box, Codec).

verify_cookie(<<Nonce:16/binary, Box:80/binary>>, CSTPK, Codec) ->
  #codec{minute_key=MK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(minute_key, Nonce),
  case secretbox_open(Box, NonceString, MK) of
    {ok, <<BoxedCSTPK:32/binary, _:32/binary>>} ->
      verify_32(BoxedCSTPK, CSTPK);
    _ ->
      false
  end.

decode_initiate_box(Nonce, Box, Codec) ->
  #codec{client_short_term_public_key=CSTPK,
         server_short_term_secret_key=SSTSK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(initiate, Nonce),
  {ok, Contents} = box_open(Box, NonceString, CSTPK, SSTSK),
  verify_initiate_box_contents(Contents, Codec).

verify_initiate_box_contents(<<CLTPK:32/binary, Vouch:64/binary,
                               DomainName:256/binary, _Message/binary>>,
                             Codec) ->
  true = verify_vouch(CLTPK, Vouch, Codec) andalso
         verify_client(CLTPK, Codec) andalso
         verify_domain_name(DomainName, Codec),
  Codec#codec{client_long_term_public_key=CLTPK}.

verify_vouch(CLTPK, <<Nonce:16/binary, Box:48/binary>>, Codec) ->
  #codec{server_long_term_secret_key=SLTPK,
         client_short_term_public_key=CSTPK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(vouch, Nonce),
  {ok, VouchedCSTPK} = box_open(Box, NonceString, CLTPK, SLTPK),
  verify_32(VouchedCSTPK, CSTPK).

verify_client(_CLTPK, _Codec) ->
  true.

verify_domain_name(_DomainName, _Codec) ->
  true.

encode_server_message_packet(Message, Codec) ->
  #codec{server_short_term_secret_key=SSTSK,
         client_short_term_public_key=CSTPK,
         shared_key=SharedKey,
         client_extension=CE,
         server_extension=SE} = Codec,

  Nonce = ecurvecp_nonces:short_term_nonce(SSTSK),
  NonceString = ecurvecp_nonces:nonce_string(server_message, Nonce),
  Box = if
    SharedKey =:= undefined ->
      box(Message, NonceString, CSTPK, SSTSK);
    true ->
      box_afternm(Message, NonceString, SharedKey)
  end,
  <<?SERVER_M, CE/binary, SE/binary, Nonce/binary, Box/binary>>.

decode_client_message_packet(<<?CLIENT_M, _SE:16/binary, _CE:16/binary,
                               CSTPK:32/binary, Nonce:8/binary, Box/binary>>,
                             Codec) ->
  #codec{client_short_term_public_key=CSTPK,
         server_short_term_secret_key=SSTSK,
         shared_key=SharedKey} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(client_message, Nonce),
  {ok, Message} = if
    SharedKey =:= undefined ->
      box_open(Box, NonceString, CSTPK, SSTSK);
    true ->
      box_open_afternm(Box, NonceString, SharedKey)
  end,
  {ok, Message, Codec}.

rotate_minute_keys(#codec{minute_key=undefined} = Codec) ->
  MinuteKey = generate_minute_key(),
  rotate_minute_keys(Codec#codec{minute_key=MinuteKey});
rotate_minute_keys(Codec) ->
  #codec{minute_key=PrevMinuteKey} = Codec,
  MinuteKey = generate_minute_key(),
  _Ref = erlang:send_after(60000, self(), rotate),
  Codec#codec{minute_key=MinuteKey, prev_minute_key=PrevMinuteKey}.
