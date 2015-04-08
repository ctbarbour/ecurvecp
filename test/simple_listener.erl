-module(simple_listener).
-export([start/1, stop/1, init/1, server/1]).

start(LPort) ->
  spawn_link(?MODULE, init, [LPort]).

stop(Pid) ->
  Pid ! stop,
  receive
    ok ->
      ok
  end.

init(LPort) ->
  process_flag(trap_exit, true),
  case ecurvecp_connection:listen([{port, LPort}]) of
    {ok, LSock} ->
      ok = error_logger:info_msg("[~p] Listening on ~p~n", [self(), LPort]),
      start_servers(10, LSock);
    {error, Reason} ->
      ok = error_logger:info("[~p] Error listening ~p~n", [self(), Reason]),
      {error, Reason}
  end.

start_servers(0, _) ->
  ok;
start_servers(Num, LSock) ->
  spawn(?MODULE, server, [LSock]),
  start_servers(Num-1, LSock).

server(LSock) ->
  case ecurvecp_connection:accept(LSock, infinity) of
    {ok, S} ->
      loop(S);
    Error ->
      ok = error_logger:info_msg("[~p] Error accept ~p~n", [self(), Error]),
      Error
  end.

loop(S) ->
  ecurvecp_connection:setopts(S, [{active, once}]),
  receive
    {ecurvecp, S, Data} ->
      ecurvecp_connection:send(S, Data),
      loop(S);
    stop ->
      ok;
    Error ->
      ok = error_logger:info_msg("[~p] Loop error ~p~n", [self(), Error]),
      ok
  end.
