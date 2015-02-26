-module(ecurvecp_client).
-behavior(gen_fsm).

-export([start_link/2, hello/3]).
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
         code_change/4, terminate/3]).
-export([start/2, cookie/2]).

-include("ecurvecp.hrl").

-record(st, {
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

hello(ClientPid, ServerPid, ServerLongTermPubKey) ->
  gen_fsm:send_event(ClientPid, {hello, ServerPid, ServerLongTermPubKey}).

-spec start_link(<<_:32>>, <<_:32>>) -> {ok, pid()}.
start_link(PubKey, SecKey) ->
  gen_fsm:start_link(?MODULE, [PubKey, SecKey], []).

init([PubKey, SecKey]) ->
  Extension = ecurvecp_messages:extension(self()),
  StateData = #st{client_extension=Extension,
                  client_long_term_public_key=PubKey,
                  client_long_term_secret_key=SecKey},
  {ok, start, StateData}.

start({hello, ServerPid, ServerLongTermPubKey}, StateData) ->
  #st{client_extension=ClientExtension} = StateData,
  #{public := ClientShortTermPubKey, secret := ClientShortTermSecKey} = enacl:box_keypair(),
  Zeros = binary:copy(<<0>>, 64),
  Nonce = enacl:randombytes(8),
  NonceString = ecurvecp_messages:nonce_string(hello, Nonce),
  Box = enacl:box(Zeros, NonceString, ServerLongTermPubKey, ClientShortTermSecKey),
  ServerExtension = ecurvecp_messages:extension(ServerPid),
  HelloMsg = <<?HELLO_MSG_PREFIX, ServerExtension/binary, ClientExtension/binary,
               ClientShortTermPubKey/binary, Zeros/binary, Nonce/binary, Box/binary>>,
  ok = gen_fsm:send_event(ServerPid, HelloMsg),
  {next_state, cookie, StateData#st{client_short_term_public_key=ClientShortTermPubKey,
                                    client_short_term_secret_key=ClientShortTermSecKey,
                                    server_extension=ServerExtension,
                                    server_long_term_public_key=ServerLongTermPubKey}};
start(_Event, StateData) ->
  {next_state, start, StateData}.

cookie(<<?COOKIE_MSG_PREFIX, _CE:16/binary, _SE:16/binary, Nonce:16/binary, Box:144/binary>>, StateData) ->
  #st{server_long_term_public_key=ServerPubKey, client_short_term_secret_key=ShortTermSecKey} = StateData,
  case catch(enacl:box_open(Box, ecurvecp_messages:nonce_string(cookie, Nonce),
                            ServerPubKey, ShortTermSecKey)) of
    {ok, <<ServerShortTermPubKey:32/binary, Cookie:96/binary>>} ->
      ok = error_logger:info_msg("Received Cookie ~p~n", [Cookie]),
      {stop, normal, StateData#st{server_short_term_public_key=ServerShortTermPubKey,
                                  cookie=Cookie}};
    {error, failed_verification} ->
      {stop, failed_verification, StateData};
    {'EXIT', {badarg, _}} ->
      {next_state, cookie, StateData}
  end;
cookie(Event, StateData) ->
  ok = error_logger:info_msg("Received unmatched message in state cookie~n~n~p~n~n", [Event]),
  {stop, normal, StateData}.

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


