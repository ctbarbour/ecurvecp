-module(ecurvecp_server).
-behavior(gen_fsm).

-export([start_link/1, start_link/2]).
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
    client_pid
  }).

-type state() :: #st{}.

-spec start_link(key_pair()) -> {ok, pid()}.
start_link(#{public := PubKey, secret := SecKey}) ->
  start_link(PubKey, SecKey).

-spec start_link(key(), key()) -> {ok, pid()}.
start_link(PubKey, SecKey) ->
  gen_fsm:start_link(?MODULE, [PubKey, SecKey], []).

init([PubKey, SecKey]) ->
  _Ref = erlang:send_after(60000, self(), rotate),
  Extension = ecurvecp:extension(self()),
  MinuteKey = enacl:randombytes(32),
  PrevMinuteKey = enacl:randombytes(32),
  State = #st{server_long_term_public_key=PubKey,
              server_long_term_secret_key=SecKey,
              server_extension=Extension,
              minute_key=MinuteKey,
              prev_minute_key=PrevMinuteKey},
  {ok, hello, State}.

hello(<<?HELLO_PKT_PREFIX, SE:16/binary, CE:16/binary,
        ClientShortTermPubKey:32/binary, _:64/binary, Nonce:8/binary,
        Box:80/binary>>, #st{server_extension=SE} = StateData) ->
  #st{server_long_term_secret_key=LongTermSecKey,
      minute_key=MinuteKey} = StateData,
  case catch(enacl:box_open(Box, ecurvecp_nonces:nonce_string(hello, Nonce),
                            ClientShortTermPubKey, LongTermSecKey)) of
    {ok, _Zeros} ->
      #{public := ShortTermPubKey, secret := ShortTermSecKey} = enacl:box_keypair(),
      CookieNonce = ecurvecp_nonces:long_term_nonce_counter(LongTermSecKey),
      NonceString = ecurvecp_nonces:nonce_string(cookie, CookieNonce),
      Cookie = encode_cookie(ClientShortTermPubKey, ShortTermPubKey, MinuteKey),
      BoxMsg = <<ShortTermPubKey/binary, Cookie/binary>>,
      CookieBox = enacl:box(BoxMsg, NonceString, ClientShortTermPubKey, LongTermSecKey),
      CookieMsg = <<?COOKIE_PKT_PREFIX, CE/binary, SE/binary,
                    CookieNonce/binary, CookieBox/binary>>,

      ClientPid = ecurvecp:extension_pid(CE),
      ok = reply(ClientPid, CookieMsg),
      {next_state, initiate, StateData#st{cookie=Cookie,
                                          client_extension=CE,
                                          server_short_term_public_key=ShortTermPubKey,
                                          server_short_term_secret_key=ShortTermSecKey,
                                          client_pid=ClientPid}};
    {'EXIT', {badarg, _E}} ->
      {stop, badarg, StateData}
  end;
hello(_Event, StateData) ->
 {stop, badarg, StateData}.

initiate(<<?INITIATE_PKT_PREFIX, SE:16/binary, CE:16/binary, ClientShortTermPubKey:32/binary, Cookie:96/binary, InitiateNonce:8/binary, InitiateBox/binary>>,
         #st{cookie=Cookie, server_extension=SE, client_extension=CE} = StateData) ->
  #st{server_short_term_secret_key=ServerShortTermSecKey,
     client_pid=ClientPid} = StateData,
  case enacl:box_open(InitiateBox, ecurvecp_nonces:nonce_string(initiate, InitiateNonce), ClientShortTermPubKey, ServerShortTermSecKey) of
    {ok, <<ClientLongTermPubKey:32/binary, _Vouch:64/binary, _DomainName:256/binary, _Message/binary>>} ->
      Reply = encode_server_message(<<"CurveCPM">>, ClientShortTermPubKey,
                                      ServerShortTermSecKey),
      ReplyPkt = <<?SERVER_MESSAGE_PKT_PREFIX, CE/binary, SE/binary, Reply/binary>>,
      ok = reply(ClientPid, ReplyPkt),
      {next_state, message, StateData#st{client_long_term_public_key=ClientLongTermPubKey,
                                         client_short_term_public_key=ClientShortTermPubKey}};
    {error, failed_verification} ->
      ok = error_logger:error_msg("Received unverifiable Initiate~n"),
      {stop, failed_verification, StateData}
  end;
initiate(_Event, StateData) ->
  ok = error_logger:error_msg("Received invalid Initiate message~n"),
  {stop, badarg, StateData}.

message(<<?CLIENT_MESSAGE_PKT_PREFIX, SE:16/binary, CE:16/binary, MessageNonce:8/binary, MessageBox/binary>>,
        #st{server_extension=SE, client_extension=CE} = StateData) ->
  #st{client_short_term_public_key=ClientShortTermPubKey,
      server_short_term_secret_key=ServerShortTermSecKey,
      client_pid=ClientPid} = StateData,
  MessageNonceString = ecurvecp_nonces:nonce_string(client_message, MessageNonce),
  case enacl:box_open(MessageBox, MessageNonceString, ClientShortTermPubKey, ServerShortTermSecKey) of
    {ok, Message} ->
      Reply = encode_server_message(Message, ClientShortTermPubKey,
                                    ServerShortTermSecKey),
      ReplyPkt = <<?SERVER_MESSAGE_PKT_PREFIX, CE/binary, SE/binary, Reply/binary>>,
      ok = reply(ClientPid, ReplyPkt),
      {next_state, message, StateData};
    _ ->
      {stop, badarg, StateData}
  end.

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

-spec rotate_minute_keys(state()) -> state().
rotate_minute_keys(StateData) ->
  #st{minute_key=PrevMinuteKey} = StateData,
  MinuteKey = enacl:randombytes(32),
  StateData#st{minute_key=MinuteKey, prev_minute_key=PrevMinuteKey}.

-spec encode_cookie(<<_:32>>, <<_:32>>, <<_:32>>) -> <<_:96>>.
encode_cookie(ClientShortTermPubKey, ServerShortTermSecKey, MinuteKey) ->
  Msg = <<ClientShortTermPubKey/binary, ServerShortTermSecKey/binary>>,
  Nonce = ecurvecp_nonces:long_term_nonce_timestamp(),
  NonceString = <<"minute-k", Nonce/binary>>,
  Box = enacl:secretbox(Msg, NonceString, MinuteKey),
  <<Nonce/binary, Box/binary>>.

-spec reply(pid(), binary()) -> ok.
reply(ClientPid, Msg) ->
  gen_fsm:send_event(ClientPid, Msg).

-spec encode_server_message(binary(), key(), key()) -> binary().
encode_server_message(Message, ClientShortTermPubKey, ServerShortTermSecKey) ->
  Nonce = ecurvecp_nonces:short_term_nonce(ServerShortTermSecKey),
  NonceString = ecurvecp_nonces:nonce_string(server_message, Nonce),
  Box = enacl:box(Message, NonceString,
                  ClientShortTermPubKey, ServerShortTermSecKey),
  <<Nonce/binary, Box/binary>>.
