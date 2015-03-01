-module(ecurvecp_client).
-behavior(gen_fsm).

-export([start_link/5, start_link/6, send/2, stop/1]).
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
         code_change/4, terminate/3]).
-export([connect/2, cookie/2, ready/2, message/3]).

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
    client_extension,
    server_extension
  }).

-record(st, {
    ip,
    port,
    socket,
    codec,
    handshake_ttl = 360000,
    ttl = 60000,
    from,
    message_count = 0
  }).

start_link(#{public := CLTPK, secret := CLTSK}, Ip, Port, ServerExt, SLTPK) ->
  start_link(CLTPK, CLTSK, Ip, Port, ServerExt, SLTPK).

start_link(CLTPK, CLTSK, Ip, Port, ServerExt, SLTPK) ->
  Args = [CLTPK, CLTSK, Ip, Port, ServerExt, SLTPK],
  gen_fsm:start_link(?MODULE, Args, []).

send(ClientPid, Message) ->
  gen_fsm:sync_send_event(ClientPid, {message, Message}, 5000).

stop(ClientPid) ->
  gen_fsm:sync_send_all_state_event(ClientPid, stop).

keypair() ->
  enacl:box_keypair().

box(Box, Nonce, PK, SK) ->
  enacl:box(Box, Nonce, PK, SK).

box_open(Box, Nonce, PK, SK) ->
  catch enacl:box_open(Box, Nonce, PK, SK).

encode_hello_packet(Codec) ->
  #codec{server_long_term_public_key=SLTPK,
                client_short_term_public_key=CSTPK,
                client_short_term_secret_key=CSTSK,
                server_extension=SE,
                client_extension=CE} = Codec,

  Zeros = <<0:512>>,
  Nonce = ecurvecp_nonces:short_term_nonce(CSTSK),
  NonceString = ecurvecp_nonces:nonce_string(hello, Nonce),
  Box = box(Zeros, NonceString, SLTPK, CSTSK),
  <<?HELLO_PKT, SE/binary, CE/binary, CSTPK/binary, Zeros/binary, Nonce/binary, Box/binary>>.

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
  Box = box(PlainText, NonceString, SSTPK, CSTSK),
  <<?INITIATE_PKT, SE/binary, CE/binary, CSTPK/binary, Cookie/binary, Nonce/binary, Box/binary>>.

encode_vouch(Codec) ->
  #codec{client_short_term_public_key=CSTPK,
                server_long_term_public_key=SLTPK,
                client_long_term_secret_key=CLTSK} = Codec,
  Nonce = ecurvecp_nonces:long_term_nonce_counter(CLTSK),
  NonceString = ecurvecp_nonces:nonce_string(vouch, Nonce),
  Box = box(CSTPK, NonceString, SLTPK, CLTSK),
  <<Nonce/binary, Box/binary>>.

generate_short_term_keypair(Codec) ->
  #{public := CSTPK, secret := CSTSK} = keypair(),
  Codec#codec{client_short_term_public_key=CSTPK,
                     client_short_term_secret_key=CSTSK}.

init([CLTPK, CLTSK, Ip, Port, ServerExt, SLTPK]) ->
  ClientExtension = ecurvecp:extension(),
  SocketOpts = [binary, {active, true}, inet, inet6],
  {ok, Socket} = gen_udp:open(0, SocketOpts),
  Codec = generate_short_term_keypair(#codec{client_extension=ClientExtension,
                                             server_extension=ServerExt,
                                             client_long_term_public_key=CLTPK,
                                             client_long_term_secret_key=CLTSK,
                                             server_long_term_public_key=SLTPK}),
  State = #st{ip=Ip, port=Port, socket=Socket, codec=Codec},
  {ok, connect, State, 0}.

connect(timeout, State) ->
  #st{socket=Socket, codec=Codec, handshake_ttl=Timeout, ip=Ip, port=Port} = State,
  Packet = encode_hello_packet(Codec),
  ok = gen_udp:send(Socket, Ip, Port, Packet),
  {next_state, cookie, State, Timeout}.

verify_extensions(<<MaybeCE:16/binary, MaybeSE:16/binary>>, Codec) ->
  #codec{client_extension=CE, server_extension=SE} = Codec,
  MaybeCE =:= CE andalso MaybeSE =:= SE.

decode_cookie_packet(<<?COOKIE_PKT, Exts:32/binary, Rest/binary>>, Codec) ->
  case verify_extensions(Exts, Codec) of
    true ->
      decode_cookie_body(Rest, Codec);
    false ->
      {error, invalid_cookie_extensions, Codec}
  end.

decode_cookie_body(<<Nonce:16/binary, Box:144/binary>>, Codec) ->
  #codec{server_long_term_public_key=SLTPK,
         client_short_term_secret_key=CSTSK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(cookie, Nonce),
  case box_open(Box, NonceString, SLTPK, CSTSK) of
    {ok, Contents} ->
      decode_cookie_box_contents(Contents, Codec);
    _ ->
      {error, invalid_cookie_box, Codec}
  end.

decode_cookie_box_contents(<<SSTPK:32/binary, Cookie:96/binary>>, Codec) ->
  {ok, Codec#codec{server_short_term_public_key=SSTPK, cookie=Cookie}};
decode_cookie_box_contents(_Contents, Codec) ->
  {error, invalid_cookie_box_contents, Codec}.

decode_server_message_packet(<<?SERVER_MESSAGE_PKT, Exts:32/binary, Rest/binary>>, Codec) ->
  case verify_extensions(Exts, Codec) of
    true ->
      decode_server_message_body(Rest, Codec);
    false ->
      {error, invalid_server_message_extensions}
  end.

decode_server_message_body(<<Nonce:8/binary, Box/binary>>, Codec) ->
  #codec{server_short_term_public_key=SSTPK,
         client_short_term_secret_key=CSTSK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(server_message, Nonce),
  case box_open(Box, NonceString, SSTPK, CSTSK) of
    {ok, Contents} ->
      {ok, Contents, Codec};
    {_, Reason} ->
      {error, Reason}
  end.

cookie(<<?COOKIE_PKT, _Rest/binary>> = Packet, State) ->
  #st{codec=Codec0, socket=Socket, ip=Ip, port=Port} = State,
  case decode_cookie_packet(Packet, Codec0) of
    {ok, Codec} ->
      InitiatePacket = encode_initiate_packet(Codec),
      ok = gen_udp:send(Socket, Ip, Port, InitiatePacket),
      {next_state, ready, State#st{codec=Codec}};
    {error, Reason} ->
      {stop, Reason, State}
  end;
cookie(timeout, State) ->
  {stop, handshake_timeout, State};
cookie(_Event, State) ->
  {stop, badarg, State}.

ready(<<?SERVER_MESSAGE_PKT, _Rest/binary>> = Packet, State) ->
  #st{codec=Codec0} = State,
  case decode_server_message_packet(Packet, Codec0) of
    {ok, _Message, Codec} ->
      {next_state, message, State#st{codec=Codec}};
    {error, Reason} ->
      {stop, Reason, State}
  end;
ready(_Event, State) ->
  {stop, badarg, State}.

message(<<?SERVER_MESSAGE_PKT, _Rest/binary>> = Packet, State) ->
  #st{codec=Codec0} = State,
  case decode_server_message_packet(Packet, Codec0) of
    {ok, Message, Codec} ->
      _ = reply(Message, State),
      {next_state, message, State#st{codec=Codec, from=undefined}};
    {error, Reason} ->
      {stop, Reason, State}
  end;
message(_Event, State) ->
  {next_state, message, State}.

message({message, PlainText}, From, State0) ->
  #st{codec=Codec, socket=Socket, ip=Ip, port=Port} = State0,
  {Message, State} = encode_client_message(PlainText, State0),
  Packet = encode_client_message_packet(Message, Codec),
  ok = gen_udp:send(Socket, Ip, Port, Packet),
  {next_state, message, State#st{from=From}}.

reply(ServerMessage, State) ->
  #st{from=From} = State,
  {_Id, PlainText} = decode_server_message(ServerMessage),
  gen_fsm:reply(From, PlainText).

decode_server_message(<<Id:4/binary, PlainText/binary>>) ->
  {Id, PlainText}.

encode_client_message_packet(Message, Codec) ->
  #codec{server_extension=SE,
         client_extension=CE,
         client_short_term_public_key=CSTPK,
         client_short_term_secret_key=CSTSK,
         server_short_term_public_key=SSTPK} = Codec,
  Nonce = ecurvecp_nonces:short_term_nonce(CSTSK),
  NonceString = ecurvecp_nonces:nonce_string(client_message, Nonce),
  Box = box(Message, NonceString, SSTPK, CSTSK),
  <<?CLIENT_MESSAGE_PKT, SE/binary, CE/binary, CSTPK/binary, Nonce/binary, Box/binary>>.

encode_client_message(PlainText, State) ->
  #st{message_count=MC0} = State,
  MC = MC0 + 1,
  Message = <<MC:32/unsigned-little-integer, PlainText/binary>>,
  {Message, State#st{message_count=MC}}.

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
handle_info(_Info, StateName, State) ->
  {next_state, StateName, State}.

code_change(_OldVsn, StateName, StateData, _Extra) ->
  {ok, StateName, StateData}.

terminate(_Reason, _StateName, _StateData) ->
  ok.

active_once(State) ->
  #st{socket=Socket} = State,
  ok = inet:setopts(Socket, [{active, true}]),
  State.

encode_domain_name() ->
  Bin = list_to_binary(?SERVER_DOMAIN),
  case (256 - size(Bin) rem 256) rem 256 of
    0 ->
      Bin;
    N ->
      <<Bin/binary, 0:(N*8)>>
  end.
