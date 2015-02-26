-module(ecurvecp_server).
-behavior(gen_fsm).

-export([start_link/2]).
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
         code_change/4, terminate/3]).
-export([hello/2, initiate/2]).

-include("ecurvecp.hrl").

-record(st, {
    long_term_public_key,
    long_term_secret_key,
    short_term_public_key,
    short_term_secret_key,
    minute_key,
    prev_minute_key,
    cookie,
    server_extension,
    client_extension
  }).

-type state() :: #st{}.

start_link(PubKey, SecKey) ->
  gen_fsm:start_link(?MODULE, [PubKey, SecKey], []).

init([PubKey, SecKey]) ->
  _Ref = erlang:send_after(60000, self(), rotate),
  Extension = ecurvecp_messages:extension(self()),
  MinuteKey = enacl:randombytes(32),
  PrevMinuteKey = enacl:randombytes(32),
  State = #st{long_term_public_key=PubKey,
              long_term_secret_key=SecKey,
              server_extension=Extension,
              minute_key=MinuteKey,
              prev_minute_key=PrevMinuteKey},
  {ok, hello, State}.

hello(<<?HELLO_MSG_PREFIX, SE:16/binary, CE:16/binary,
        ClientShortTermPubKey:32/binary, _:64/binary, Nonce:8/binary,
        Box:80/binary>>, StateData) ->
  #st{long_term_secret_key=LongTermSecKey,
      minute_key=MinuteKey} = StateData,
  case catch(enacl:box_open(Box, ecurvecp_messages:nonce_string(hello, Nonce),
                            ClientShortTermPubKey, LongTermSecKey)) of
    {ok, _Zeros = <<_:64>>} ->
      #{public := ShortTermPubKey, secret := ShortTermSecKey} = enacl:box_keypair(),
      N = enacl:randombytes(16),
      NonceString = ecurvecp_messages:nonce_string(cookie, N),
      Cookie = cookie(ClientShortTermPubKey, ShortTermPubKey, MinuteKey),
      BoxMsg = <<ShortTermPubKey/binary, Cookie/binary>>,
      CookieBox = enacl:box(BoxMsg, NonceString, ClientShortTermPubKey, LongTermSecKey),
      CookieMsg = <<?COOKIE_MSG_PREFIX, CE/binary, SE/binary,
                    N/binary, CookieBox/binary>>,

      ClientPid = ecurvecp_messages:extension_pid(CE),
      ok = reply(ClientPid, CookieMsg),
      {next_state, initiate, StateData#st{cookie=Cookie,
                                          short_term_public_key=ShortTermPubKey,
                                          short_term_secret_key=ShortTermSecKey}};
    {'EXIT', {badarg, _E}} ->
      {next_state, hello, StateData}
  end;
hello(_Event, StateData) ->
  {next_state, hello, StateData}.

initiate(_Event, StateData) ->
  {next_state, initiate, StateData}.

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

-spec cookie(<<_:32>>, <<_:32>>, <<_:32>>) -> <<_:96>>.
cookie(ClientShortTermPubKey, ServerShortTermSK, MinuteKey) ->
  Msg = <<ClientShortTermPubKey/binary, ServerShortTermSK/binary>>,
  Nonce = enacl:randombytes(16),
  NonceString = <<"minute-k", Nonce/binary>>,
  Box = enacl:secretbox(Msg, NonceString, MinuteKey),
  <<Nonce/binary, Box/binary>>.

-spec reply(pid(), binary()) -> ok.
reply(ClientPid, Msg) ->
  gen_fsm:send_event(ClientPid, Msg).
