-module(ecurvecp_client).
-behavior(gen_fsm).

-export([start_link/6, start_link/7, send/2, stop/1]).
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
         code_change/4, terminate/3]).
-export([connect/2, cookie/2, ready/2, finalize/2, message/2, message/3]).

-define(SERVER_DOMAIN, "apple.com").

-include("ecurvecp.hrl").

-record(codec, {
    client_long_term_public_key,
    client_long_term_secret_key,
    client_short_term_public_key,
    client_short_term_secret_key,
    server_long_term_public_key,
    server_short_term_public_key,
    cookie,
    shared_key,
    client_extension,
    server_extension,
    message_count = 0
  }).

-record(st, {
    ip,
    port,
    socket,
    codec,
    handshake_ttl = 360000,
    ttl = 60000,
    from,
    owner
  }).

start_link(#{public := CLTPK, secret := CLTSK}, Owner, Ip, Port, ServerExt, SLTPK) ->
  start_link(CLTPK, CLTSK, Owner, Ip, Port, ServerExt, SLTPK).

start_link(CLTPK, CLTSK, Owner, Ip, Port, ServerExt, SLTPK) ->
  Args = [CLTPK, CLTSK, Owner, Ip, Port, ServerExt, SLTPK],
  gen_fsm:start_link(?MODULE, Args, []).

send(ClientPid, Message) ->
  gen_fsm:sync_send_event(ClientPid, {message, Message}, 5000).

stop(ClientPid) ->
  gen_fsm:sync_send_all_state_event(ClientPid, stop).

generate_short_term_keypair(Codec) ->
  #{public := CSTPK, secret := CSTSK} = enacl:box_keypair(),
  Codec#codec{client_short_term_public_key=CSTPK,
              client_short_term_secret_key=CSTSK}.

generate_shared_key(Codec) ->
  #codec{server_short_term_public_key=SSTPK,
         client_short_term_secret_key=CSTSK} = Codec,
  SharedKey = enacl:box_beforenm(SSTPK, CSTSK),
  Codec#codec{shared_key=SharedKey}.

init([CLTPK, CLTSK, Owner, Ip, Port, ServerExt, SLTPK]) ->
  ClientExtension = ecurvecp:extension(),
  SocketOpts = [binary, {active, once}, inet, inet6],
  {ok, Socket} = gen_udp:open(0, SocketOpts),
  Codec = generate_short_term_keypair(#codec{client_extension=ClientExtension,
                                             server_extension=ServerExt,
                                             client_long_term_public_key=CLTPK,
                                             client_long_term_secret_key=CLTSK,
                                             server_long_term_public_key=SLTPK}),
  _MRef = erlang:monitor(process, Owner),
  State = #st{ip=Ip, port=Port, socket=Socket, codec=Codec, owner=Owner},
  {ok, connect, State, 0}.

connect(timeout, State) ->
  #st{socket=Socket, codec=Codec, handshake_ttl=Timeout, ip=Ip, port=Port} = State,
  Packet = encode_hello_packet(Codec),
  ok = gen_udp:send(Socket, Ip, Port, Packet),
  {next_state, cookie, State, Timeout}.

cookie(<<?COOKIE, _/binary>> = Packet, State) ->
  #st{socket=Socket, ip=Ip, port=Port, handshake_ttl=Timeout} = State,
  Codec = decode_cookie_packet(Packet, State#st.codec),
  InitiatePacket = encode_initiate_packet(Codec),
  ok = gen_udp:send(Socket, Ip, Port, InitiatePacket),
  {next_state, ready, State#st{codec=Codec}, Timeout};
cookie(timeout, State) ->
  {stop, handshake_timeout, State}.

ready(<<?SERVER_M, _/binary>> = Packet, State) ->
  {ok, _ServerM, Codec} = decode_server_message_packet(Packet, State#st.codec),
  {next_state, finalize, State#st{codec=Codec}, 0};
ready(timeout, State) ->
  {stop, handshake_timeout, State}.

finalize(timeout, State) ->
  #st{ttl=Timeout} = State,
  Codec = generate_shared_key(State#st.codec),
  {next_state, message, State#st{codec=Codec}, Timeout}.

message(<<?SERVER_M, _/binary>> = Packet, State) ->
  #st{ttl=Timeout} = State,
  {ok, Message, Codec} = decode_server_message_packet(Packet, State#st.codec),
  _ = reply(Message, State),
  {next_state, message, State#st{codec=Codec, from=undefined}, Timeout};
message(timeout, State) ->
  {stop, timeout, State}.

message({message, PlainText}, From, State) ->
  #st{socket=Socket, ip=Ip, port=Port} = State,
  {ok, Message, Codec} = encode_client_message(PlainText, State#st.codec),
  Packet = encode_client_message_packet(Message, Codec),
  ok = gen_udp:send(Socket, Ip, Port, Packet),
  {next_state, message, State#st{codec=Codec, from=From}}.

reply(ServerMessage, State) ->
  #st{from=From} = State,
  {_Id, PlainText} = decode_server_message(ServerMessage),
  gen_fsm:reply(From, PlainText).

handle_event(_Event, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_sync_event(stop, _From, _StateName, StateData) ->
  {stop, normal, StateData};
handle_sync_event(_Event, _From, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_info({udp, _, Ip, Port, Packet}, cookie, #st{ip=Ip, port=Port} = State) ->
  cookie(Packet, active_once(State));
handle_info({udp, _, Ip, Port, Packet}, ready, #st{ip=Ip, port=Port} = State) ->
  ready(Packet, active_once(State));
handle_info({udp, _, Ip, Port, Packet}, message, #st{ip=Ip, port=Port} = State) ->
  message(Packet, active_once(State));
handle_info({'DOWN', _, process, Owner, _Reason}, _StateName, #st{owner=Owner} = State) ->
  {stop, owner_down, State};
handle_info(_Info, StateName, State) ->
  {next_state, StateName, State}.

encode_hello_packet(Codec) ->
  #codec{server_long_term_public_key=SLTPK,
                client_short_term_public_key=CSTPK,
                client_short_term_secret_key=CSTSK,
                server_extension=SE,
                client_extension=CE} = Codec,

  Zeros = <<0:512>>,
  Nonce = ecurvecp_nonces:short_term_nonce(CSTSK),
  NonceString = ecurvecp_nonces:nonce_string(hello, Nonce),
  Box = enacl:box(Zeros, NonceString, SLTPK, CSTSK),
  <<?HELLO, SE/binary, CE/binary, CSTPK/binary, Zeros/binary, Nonce/binary, Box/binary>>.

verify_extensions(<<MaybeCE:16/binary, MaybeSE:16/binary>>, Codec) ->
  #codec{client_extension=CE, server_extension=SE} = Codec,
  MaybeCE =:= CE andalso MaybeSE =:= SE.

decode_cookie_packet(<<?COOKIE, Exts:32/binary, Rest/binary>>, Codec) ->
  true = verify_extensions(Exts, Codec),
  decode_cookie_body(Rest, Codec).

decode_cookie_body(<<Nonce:16/binary, Box:144/binary>>, Codec) ->
  #codec{server_long_term_public_key=SLTPK,
         client_short_term_secret_key=CSTSK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(cookie, Nonce),
  {ok, Contents} = enacl:box_open(Box, NonceString, SLTPK, CSTSK),
  decode_cookie_box_contents(Contents, Codec).

decode_cookie_box_contents(<<SSTPK:32/binary, Cookie:96/binary>>, Codec) ->
  Codec#codec{server_short_term_public_key=SSTPK, cookie=Cookie}.

encode_initiate_packet(Codec) ->
  #codec{server_short_term_public_key=SSTPK,
                client_long_term_public_key=CLTPK,
                client_short_term_public_key=CSTPK,
                client_short_term_secret_key=CSTSK,
                server_extension=SE,
                client_extension=CE,
                cookie=Cookie} = Codec,
  Vouch = encode_vouch(Codec),
  DomainName = encode_domain_name(),
  PlainText = <<CLTPK/binary, Vouch/binary, DomainName/binary, "CurveCPI">>,
  Nonce = ecurvecp_nonces:short_term_nonce(CSTSK),
  NonceString = ecurvecp_nonces:nonce_string(initiate, Nonce),
  Box = enacl:box(PlainText, NonceString, SSTPK, CSTSK),
  <<?INITIATE, SE/binary, CE/binary, CSTPK/binary, Cookie/binary, Nonce/binary, Box/binary>>.

encode_vouch(Codec) ->
  #codec{client_short_term_public_key=CSTPK,
                server_long_term_public_key=SLTPK,
                client_long_term_secret_key=CLTSK} = Codec,
  Nonce = ecurvecp_nonces:long_term_nonce_counter(CLTSK),
  NonceString = ecurvecp_nonces:nonce_string(vouch, Nonce),
  Box = enacl:box(CSTPK, NonceString, SLTPK, CLTSK),
  <<Nonce/binary, Box/binary>>.

encode_client_message_packet(Message, Codec) ->
  #codec{server_extension=SE,
         client_extension=CE,
         server_short_term_public_key=SSTPK,
         client_short_term_secret_key=CSTSK,
         client_short_term_public_key=CSTPK,
         shared_key=SharedKey} = Codec,
  Nonce = ecurvecp_nonces:short_term_nonce(SharedKey),
  NonceString = ecurvecp_nonces:nonce_string(client_message, Nonce),
  Box = if SharedKey =:= undefined ->
      enacl:box(Message, NonceString, SSTPK, CSTSK);
    true ->
      enacl:box_afternm(Message, NonceString, SharedKey)
  end,
  <<?CLIENT_M, SE/binary, CE/binary, CSTPK/binary, Nonce/binary, Box/binary>>.

encode_client_message(PlainText, Codec) ->
  MC = Codec#codec.message_count + 1,
  Message = <<MC:32/unsigned-little-integer, PlainText/binary>>,
  {ok, Message, Codec#codec{message_count=MC}}.

decode_server_message_packet(<<?SERVER_M, Exts:32/binary, Rest/binary>>, Codec) ->
  true = verify_extensions(Exts, Codec),
  decode_server_message_body(Rest, Codec).

decode_server_message_body(<<Nonce:8/binary, Box/binary>>, Codec) ->
  #codec{server_short_term_public_key=SSTPK,
         client_short_term_secret_key=CSTSK,
         shared_key=SharedKey} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(server_message, Nonce),
  {ok, Contents} = if SharedKey =:= undefined ->
      enacl:box_open(Box, NonceString, SSTPK, CSTSK);
    true ->
      enacl:box_open_afternm(Box, NonceString, SharedKey)
  end,
  {ok, Contents, Codec}.

decode_server_message(<<Id:4/binary, PlainText/binary>>) ->
  {Id, PlainText}.

code_change(_OldVsn, StateName, StateData, _Extra) ->
  {ok, StateName, StateData}.

terminate(_Reason, _StateName, _StateData) ->
  ok.

active_once(State) ->
  #st{socket=Socket} = State,
  ok = inet:setopts(Socket, [{active, once}]),
  State.

encode_domain_name() ->
  Bin = list_to_binary(?SERVER_DOMAIN),
  case (256 - size(Bin) rem 256) rem 256 of
    0 ->
      Bin;
    N ->
      <<Bin/binary, 0:(N*8)>>
  end.
