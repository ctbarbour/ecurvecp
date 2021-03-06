-module(ecurvecp_cookie).
-behavior(gen_server).

-export([start_link/0, current_key/0, keys/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3,
         terminate/2]).

-spec start_link() -> {ok, pid()}.
start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec current_key() -> binary().
current_key() ->
  gen_server:call(?MODULE, current_key).

-spec keys() -> [binary()].
keys() ->
  gen_server:call(?MODULE, keys).

init([]) ->
  Current = minute_key(),
  Previous = minute_key(),
  {ok, [Current, Previous]}.

handle_call(current_key, _From, [Current|_] = State) ->
  {reply, Current, State};
handle_call(keys, _From, State) ->
  {reply, State, State};
handle_call(_Msg, _From, State) ->
  {noreply, State}.

handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info(rotate_keys, [Prev|_]) ->
  _Ref = erlang:send_after(60000, self(), rotate_keys),
  Current = minute_key(),
  {noreply, [Current, Prev]};
handle_info(_Info, State) ->
  {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.

-spec minute_key() -> <<_:256>>.
minute_key() ->
  enacl:randombytes(32).
