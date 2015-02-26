-module(ecurvecp_client).
-behavior(gen_fsm).

-export([start_link/3, start_link/4, send/2]).
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
         code_change/4, terminate/3]).
-export([start/2, cookie/2, reply/2, message/3]).

-define(SERVER_DOMAIN, "apple.com").

-include("ecurvecp.hrl").

-record(st, {
    client_long_term_public_key   :: key(),
    client_long_term_secret_key   :: key(),
    client_short_term_public_key  :: key(),
    client_short_term_secret_key  :: key(),
    server_long_term_public_key   :: key(),
    server_short_term_public_key  :: key(),
    cookie                        :: cookie(),
    client_extension              :: extension(),
    server_extension              :: extension(),
    server_pid                    :: pid(),
    from                          :: {reference(), pid()}
  }).

-spec start_link(pid(), key(), key_pair()) -> {ok, pid()}.
start_link(Server, ServerPublicKey, #{public := ClientPubKey, secret := ClientSecKey}) ->
  start_link(Server, ServerPublicKey, ClientPubKey, ClientSecKey).

-spec start_link(pid(), key(), key(), key()) -> {ok, pid()}.
start_link(Server, ServerPublicKey, ClientPublicKey, ClientSecretKey) ->
  gen_fsm:start_link(?MODULE, [Server, ServerPublicKey, ClientPublicKey, ClientSecretKey], []).

-spec send(pid(), term()) -> term().
send(ClientPid, Message) ->
  gen_fsm:sync_send_event(ClientPid, {message, Message}, 5000).

init([Server, ServerPublicKey, ClientPubKey, ClientSecKey]) ->
  ClientExtension = ecurvecp:extension(self()),
  ServerExtension = ecurvecp:extension(Server),
  StateData = #st{client_extension=ClientExtension,
                  server_extension=ServerExtension,
                  server_pid=Server,
                  server_long_term_public_key=ServerPublicKey,
                  client_long_term_public_key=ClientPubKey,
                  client_long_term_secret_key=ClientSecKey},
  {ok, start, StateData, 0}.

start(timeout, StateData) ->
  #st{server_long_term_public_key=ServerLongTermPubKey,
      server_extension=ServerExtension,
      client_extension=ClientExtension,
      server_pid=ServerPid} = StateData,
  #{public := ClientShortTermPubKey, secret := ClientShortTermSecKey} = enacl:box_keypair(),
  Hello = encode_hello(ServerLongTermPubKey, ClientShortTermSecKey),
  Zeros = <<0:512>>,
  HelloMsg = <<?HELLO_PKT_PREFIX, ServerExtension/binary, ClientExtension/binary,
               ClientShortTermPubKey/binary, Zeros/binary, Hello/binary>>,
  ok = gen_fsm:send_event(ServerPid, HelloMsg),
  {next_state, cookie, StateData#st{client_short_term_public_key=ClientShortTermPubKey,
                                    client_short_term_secret_key=ClientShortTermSecKey,
                                    server_extension=ServerExtension,
                                    server_long_term_public_key=ServerLongTermPubKey}};
start(_Event, StateData) ->
  {next_state, start, StateData}.

cookie(<<?COOKIE_PKT_PREFIX, CE:16/binary, SE:16/binary, CookieNonce:16/binary,
         CookieBox:144/binary>>,
       #st{client_extension=CE, server_extension=SE} = StateData) ->
  #st{server_long_term_public_key=ServerLongTermPubKey,
      client_long_term_secret_key=ClientLongTermSecKey,
      client_long_term_public_key=ClientLongTermPubKey,
      client_short_term_secret_key=ClientShortTermSecKey,
      client_short_term_public_key=ClientShortTermPubKey,
      server_pid=ServerPid} = StateData,
  CookieNonceString = ecurvecp_nonces:nonce_string(cookie, CookieNonce),
  case enacl:box_open(CookieBox, CookieNonceString,
                      ServerLongTermPubKey, ClientShortTermSecKey) of
    {ok, <<ServerShortTermPubKey:32/binary, Cookie:96/binary>>} ->
      Vouch = encode_vouch(ClientShortTermPubKey, ServerLongTermPubKey, ClientLongTermSecKey),
      Initiate = encode_initiate(ClientLongTermPubKey, ServerShortTermPubKey, ClientShortTermSecKey, Vouch, <<"CurveCPI">>),
      InitiateMsg = <<?INITIATE_PKT_PREFIX, SE/binary, CE/binary, ClientShortTermPubKey/binary, Cookie/binary, Initiate/binary>>,
      ok = gen_fsm:send_event(ServerPid, InitiateMsg),
      {next_state, reply, StateData#st{server_short_term_public_key=ServerShortTermPubKey,
                                         cookie=Cookie}};
    {ok, _Other} ->
      ok = error_logger:error_msg("Received unexpected Cookie contents~n"),
      {stop, badarg, StateData};
    {error, failed_verification} ->
      {stop, failed_verification, StateData}
  end;
cookie(Event, StateData) ->
  ok = error_logger:error_msg("Received unmatched message in state cookie~n~n~p~n~n", [Event]),
  {stop, normal, StateData}.

reply(<<?SERVER_MESSAGE_PKT_PREFIX, CE:16/binary, SE:16/binary, MessageNonce:8/binary, MessageBox/binary>>,
        #st{client_extension=CE, server_extension=SE} = StateData) ->
  #st{server_short_term_public_key=ServerShortTermPubKey,
      client_short_term_secret_key=ClientShortTermSecKey,
      from=From} = StateData,
  MessageNonceString = ecurvecp_nonces:nonce_string(server_message, MessageNonce),
  case enacl:box_open(MessageBox, MessageNonceString, ServerShortTermPubKey, ClientShortTermSecKey) of
    {ok, Message} ->
      _ = case From of
        undefined -> ok;
        _ -> gen_fsm:reply(From, Message)
      end,
      {next_state, message, StateData#st{from=undefined}};
    {error, failed_verification} ->
      ok = error_logger:error_msg("Received unverifiable Server Message~n"),
      {stop, failed_verification, StateData}
  end;
reply(_Event, StateData) ->
  {next_state, message, StateData}.

message({message, Message}, From, StateData) ->
  #st{server_short_term_public_key=ServerShortTermPubKey,
      client_short_term_secret_key=ClientShortTermSecKey,
      server_extension=SE,
      client_extension=CE,
      server_pid=ServerPid} = StateData,
  MessageBody = encode_client_message(Message, ServerShortTermPubKey, ClientShortTermSecKey),
  MessagePkt = <<?CLIENT_MESSAGE_PKT_PREFIX, SE/binary, CE/binary, MessageBody/binary>>,
  ok = gen_fsm:send_event(ServerPid, MessagePkt),
  {next_state, reply, StateData#st{from=From}}.

handle_event(_Event, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_sync_event(_Event, _From, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_info(_Info, StateName, StateData) ->
  {next_state, StateName, StateData}.

code_change(_OldVsn, StateName, StateData, _Extra) ->
  {ok, StateName, StateData}.

terminate(_Reason, _StateName, _StateData) ->
  ok.

-spec encode_domain_name() -> <<_:256>>.
encode_domain_name() ->
  Bin = list_to_binary(?SERVER_DOMAIN),
  case (256 - size(Bin) rem 256) rem 256 of
    0 ->
      Bin;
    N ->
      <<Bin/binary, 0:(N*8)>>
  end.

-spec encode_hello(key(), key()) -> <<_:88>>.
encode_hello(ServerLongTermPubKey, ClientShortTermSecKey) ->
  Zeros = <<0:512>>,
  Nonce = ecurvecp_nonces:short_term_nonce(ClientShortTermSecKey),
  NonceString = ecurvecp_nonces:nonce_string(hello, Nonce),
  Box = enacl:box(Zeros, NonceString, ServerLongTermPubKey, ClientShortTermSecKey),
  <<Nonce/binary, Box/binary>>.

-spec encode_vouch(key(), key(), key()) -> <<_:64>>.
encode_vouch(ClientShortTermPubKey, ServerLongTermPubKey, ClientLongTermSecKey) ->
  Nonce = ecurvecp_nonces:long_term_nonce_counter(ClientLongTermSecKey),
  NonceString = ecurvecp_nonces:nonce_string(vouch, Nonce),
  Box = enacl:box(ClientShortTermPubKey, NonceString, ServerLongTermPubKey,
                  ClientLongTermSecKey),
  <<Nonce/binary, Box/binary>>.

-spec encode_initiate(key(), key(), key(), <<_:64>>, binary()) -> binary().
encode_initiate(ClientLongTermPubKey, ServerShortTermPubKey, ClientShortTermSecKey, Vouch, Message) ->
  DomainName = encode_domain_name(),
  PlainText = <<ClientLongTermPubKey/binary, Vouch/binary, DomainName/binary, Message/binary>>,
  Nonce = ecurvecp_nonces:short_term_nonce(ClientShortTermSecKey),
  NonceString = ecurvecp_nonces:nonce_string(initiate, Nonce),
  Box = enacl:box(PlainText, NonceString, ServerShortTermPubKey, ClientShortTermSecKey),
  <<Nonce/binary, Box/binary>>.

-spec encode_client_message(binary(), key(), key()) -> binary().
encode_client_message(Message, ServerShortTermPubKey, ClientShortTermSecKey) ->
  Nonce = ecurvecp_nonces:short_term_nonce(ClientShortTermSecKey),
  NonceString = ecurvecp_nonces:nonce_string(client_message, Nonce),
  Box = enacl:box(Message, NonceString, ServerShortTermPubKey, ClientShortTermSecKey),
  <<Nonce/binary, Box/binary>>.
