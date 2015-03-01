-module(ecurvecp_server).
-behavior(gen_fsm).

-export([start_link/2, start_link/3, start_link/4, send/3]).
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
         code_change/4, terminate/3]).
-export([hello/2, initiate/2, message/2]).

-include("ecurvecp.hrl").

-record(st, {
    server_long_term_public_key,
    server_long_term_secret_key,
    server_short_term_public_key,
    server_short_term_secret_key,
    client_long_term_public_key,
    client_short_term_public_key,
    minute_key,
    prev_minute_key,
    cookie,
    server_extension,
    client_extension,
    transport                       = ecurvecp_udp,
    handshake_ttl                   = 60000,
    ttl                             = 360000
  }).

start_link(KeyPair, Extension) ->
  start_link(KeyPair, Extension, []).

start_link(#{public := PK, secret := SK}, Extension, Opts) ->
  start_link(PK, SK, Extension, Opts).

start_link(PK, SK, Extension, Opts) ->
  Args = [PK, SK, Extension, proplists:unfold(Opts)],
  gen_fsm:start_link(?MODULE, Args, []).

box_open(Box, Nonce, PK, SK) ->
  catch enacl:box_open(Box, Nonce, PK, SK).

box(Box, Nonce, PK, SK) ->
  enacl:box(Box, Nonce, PK, SK).

secretbox(Box, Nonce, PK) ->
  enacl:secretbox(Box, Nonce, PK).

secretbox_open(Box, Nonce, K) ->
  enacl:secretbox_open(Box, Nonce, K).

keypair() ->
  enacl:box_keypair().

verify(X, Y) ->
  case catch(enacl:verify_32(X, Y)) of
    true ->
      true;
    _ ->
      false
  end.

generate_minute_key() ->
  enacl:randombytes(32).

send(ServerPid, From, Packet) ->
  gen_fsm:send_event(ServerPid, {curvecp, From, Packet}).

validate_recipient(<<CE:16/binary, Rest/binary>>, #st{client_extension=CE} = State) ->
  {ok, Rest, State};
validate_recipient(_Packet, StateData) ->
  {error, unmatched_server_extension, StateData}.

handle_hello_packet(<<CE:16/binary, CSTPK:32/binary, _:64/binary, Nonce:8/binary, Box:80/binary>>, State0) ->
  State = State0#st{client_extension=CE, client_short_term_public_key=CSTPK},
  handle_hello_box(Box, Nonce, State);
handle_hello_packet(_Packet, StateData) ->
  {error, unmatched_hello_packet, StateData}.

handle_hello_box(Box, Nonce, State) ->
  #st{server_long_term_secret_key=SLTSK,
      client_short_term_public_key=CSTPK} = State,
  NonceString = ecurvecp_nonces:nonce_string(hello, Nonce),
  case box_open(Box, NonceString, CSTPK, SLTSK) of
    {ok, Contents} ->
      verify_hello_box_contents(Contents, State);
    {_, Reason} ->
      {error, Reason, State}
  end.

verify_hello_box_contents(<<First:32/binary, Second:32/binary>>, State) ->
  Zeros = <<0:256>>,
  case catch(verify(First, Zeros) andalso verify(Second, Zeros)) of
    true ->
      encode_cookie_packet(generate_short_term_keys(State));
    _ ->
      {error, invalid_hello_box_contents, State}
  end;
verify_hello_box_contents(_Contents, State) ->
  {error, invalid_hello_box_contents, State}.

generate_short_term_keys(State) ->
  #{public := SSTPK, secret := SSTSK} = keypair(),
  State#st{server_short_term_public_key=SSTPK,
           server_short_term_secret_key=SSTSK}.

encode_cookie_packet(State) ->
  #st{client_short_term_public_key=CSTPK,
      server_long_term_secret_key=SLTSK,
      server_short_term_public_key=SSTPK,
      minute_key=MK,
      client_extension=CE,
      server_extension=SE} = State,

  Nonce = ecurvecp_nonces:long_term_nonce_counter(SLTSK),
  NonceString = ecurvecp_nonces:nonce_string(cookie, Nonce),
  Cookie = encode_cookie(CSTPK, SSTPK, MK),
  PlainText = <<SSTPK/binary, Cookie/binary>>,
  Box = box(PlainText, NonceString, CSTPK, SLTSK),
  Packet = <<?COOKIE_PKT, CE/binary, SE/binary, Nonce/binary, Box/binary>>,
  {ok, Packet, State}.

encode_cookie(ClientShortTermPubKey, ServerShortTermSecKey, MinuteKey) ->
  Msg = <<ClientShortTermPubKey/binary, ServerShortTermSecKey/binary>>,
  Nonce = ecurvecp_nonces:long_term_nonce_timestamp(),
  NonceString = ecurvecp_nonces:nonce_string(minute_key, Nonce),
  Box = secretbox(Msg, NonceString, MinuteKey),
  <<Nonce/binary, Box/binary>>.

handle_initiate_packet(<<CSTPK:32/binary, Cookie:96/binary, Nonce:8/binary, Box/binary>>, State) ->
  case verify_cookie(Cookie, CSTPK, State) of
    true ->
      handle_initiate_box(Box, Nonce, State);
    false ->
      {error, invalid_cookie, State}
  end;
handle_initiate_packet(_Packet, State) ->
  {error, invalid_initiate_packet, State}.

verify_cookie(<<Nonce:16/binary, Box:80/binary>>, CSTPK, State) ->
  #st{minute_key=MK} = State,
  NonceString = ecurvecp_nonces:nonce_string(minute_key, Nonce),
  case secretbox_open(Box, NonceString, MK) of
    {ok, <<BoxedCSTPK:32/binary, _:32/binary>>} ->
      verify(BoxedCSTPK, CSTPK);
    _ ->
      false
  end.

handle_initiate_box(Box, Nonce, State) ->
  #st{client_short_term_public_key=CSTPK,
      server_short_term_secret_key=SSTSK} = State,
  NonceString = ecurvecp_nonces:nonce_string(initiate, Nonce),
  case box_open(Box, NonceString, CSTPK, SSTSK) of
    {ok, Contents} ->
      handle_initiate_box_contents(Contents, State);
    _ ->
      {error, invalid_initate_box, State}
  end.

handle_initiate_box_contents(<<CLTPK:32/binary, Vouch:64/binary, DomainName:256/binary, Message/binary>>, State) ->
  case verify_vouch(CLTPK, Vouch, State) andalso
    verify_client(CLTPK, State) andalso
    verify_domain_name(DomainName, State) of
    true ->
      encode_server_message_packet(Message, State#st{client_long_term_public_key=CLTPK});
    false ->
      {error, invalid_initiate_box_contents, State}
  end;
handle_initiate_box_contents(_Contents, State) ->
  {error, invalid_initiate_box_contents, State}.

verify_vouch(CLTPK, <<Nonce:16/binary, Box:48/binary>>, State) ->
  #st{server_long_term_secret_key=SLTPK,
      client_short_term_public_key=CSTPK} = State,
  NonceString = ecurvecp_nonces:nonce_string(vouch, Nonce),
  case box_open(Box, NonceString, CLTPK, SLTPK) of
    {ok, VouchedCSTPK} ->
      verify(VouchedCSTPK, CSTPK);
    _ ->
      false
  end;
verify_vouch(_CLTPK, _Vouch, _State) ->
  false.

verify_client(_CLTPK, _State) ->
  true.

verify_domain_name(_DomainName, _State) ->
  true.

encode_server_message_packet(Message, State) ->
  #st{server_short_term_secret_key=SSTSK,
      client_short_term_public_key=CSTPK,
      client_extension=CE,
      server_extension=SE} = State,

  Nonce = ecurvecp_nonces:short_term_nonce(SSTSK),
  NonceString = ecurvecp_nonces:nonce_string(server_message, Nonce),
  Box = box(Message, NonceString, CSTPK, SSTSK),
  Packet = <<?SERVER_MESSAGE_PKT, CE/binary, SE/binary, Nonce/binary, Box/binary>>,
  {ok, Packet, State}.

handle_client_message_packet(<<_CSTPK:32/binary, Nonce:8/binary, Box/binary>>, State) ->
  #st{client_short_term_public_key=CSTPK,
      server_short_term_secret_key=SSTSK} = State,
  NonceString = ecurvecp_nonces:nonce_string(client_message, Nonce),
  case box_open(Box, NonceString, CSTPK, SSTSK) of
    {ok, Message} ->
      encode_server_message_packet(Message, State);
    _ ->
      {error, invalid_client_message, State}
  end;
handle_client_message_packet(_Packet, State) ->
  {error, invalid_client_message, State}.

parse_opts([], State) ->
  State;
parse_opts([{handshake_ttl, HTTL}|Rest], State) ->
  parse_opts(Rest, State#st{handshake_ttl=HTTL});
parse_opts([{ttl, TTL}|Rest], State) ->
  parse_opts(Rest, State#st{ttl=TTL});
parse_opts([{transport, Transport}|Rest], State) ->
  parse_opts(Rest, State#st{transport=Transport});
parse_opts([_|Rest], State) ->
  parse_opts(Rest, State).

init([PK, SK, Extension, Opts]) ->
  State = rotate_minute_keys(
      parse_opts(Opts, #st{server_long_term_public_key=PK,
                           server_long_term_secret_key=SK,
                           server_extension=Extension})),
  {ok, hello, State}.

hello({curvecp, From, <<?HELLO_PKT, _SE:16/binary, Packet/binary>>}, State0) ->
  #st{transport=Transport, handshake_ttl=Timeout} = State0,
  case handle_hello_packet(Packet, State0) of
    {ok, CookiePacket, State} ->
      #st{client_extension=CE} = State,
      true = gproc:add_local_name({?MODULE, CE}),
      ok = Transport:reply(From, CookiePacket),
      {next_state, initiate, State, Timeout};
    {error, Reason, State} ->
      {stop, Reason, State}
  end;
hello(timeout, State) ->
  {stop, timeout, State}.

initiate({curvecp, From, <<?INITIATE_PKT, _SE:16/binary, Packet/binary>>}, State0) ->
  #st{transport=Transport, handshake_ttl=Timeout} = State0,
  case validate_recipient(Packet, State0) of
    {ok, ValidatedPacket, State1} ->
      case handle_initiate_packet(ValidatedPacket, State1) of
        {ok, MessagePacket, State} ->
          ok = Transport:reply(From, MessagePacket),
          {next_state, message, State, Timeout};
        {error, Reason, State} ->
          {stop, Reason, State}
      end;
    {error, Reason, State} ->
      {stop, Reason, State}
  end;
initiate(timeout, State) ->
  {stop, handshake_timeout, State}.

message({curvecp, From, <<?CLIENT_MESSAGE_PKT, _SE:16/binary, Packet/binary>>}, State0) ->
  #st{transport=Transport, ttl=Timeout} = State0,
  case validate_recipient(Packet, State0) of
    {ok, ValidatedPacket, State1} ->
      case handle_client_message_packet(ValidatedPacket, State1) of
        {ok, MessagePacket, State} ->
          ok = Transport:reply(From, MessagePacket),
          {next_state, message, State, Timeout};
        {error, Reason, State} ->
          {stop, Reason, State}
      end;
    {error, Reason, State} ->
      {stop, Reason, State}
  end;
message(timeout, State) ->
  {stop, timeout, State}.

handle_event(_Event, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_sync_event(_Event, _From, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_info(rotate, StateName, StateData) ->
  {next_state, StateName, rotate_minute_keys(StateData)};
handle_info(_Info, StateName, StateData) ->
  {next_state, StateName, StateData}.

code_change(_OldVsn, StateName, StateData, _Extra) ->
  {ok, StateName, StateData}.

terminate(_Reason, _StateName, _StateData) ->
  ok.

rotate_minute_keys(#st{minute_key=undefined} = State) ->
  MinuteKey = generate_minute_key(),
  rotate_minute_keys(State#st{minute_key=MinuteKey});
rotate_minute_keys(State) ->
  #st{minute_key=PrevMinuteKey} = State,
  MinuteKey = generate_minute_key(),
  _Ref = erlang:send_after(60000, self(), rotate),
  State#st{minute_key=MinuteKey, prev_minute_key=PrevMinuteKey}.
