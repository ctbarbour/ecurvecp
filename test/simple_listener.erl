-module(simple_listener).
-export([start_listeners/2, init/3, accept/1, server_loop/1]).

start_listeners(Num, Port) ->
  Pid = spawn(?MODULE, init, [self(), Num, Port]),
  receive
    ok ->
      {ok, Pid}
  after
    5000 ->
      {error, timeout}
  end.

init(Parent, Num, Port) ->
  {ok, LSock} = ecurvecp_connection:listen([{port, Port}]),
  Acceptors = start_acceptors(Num, LSock),
  Parent ! ok,
  sup_loop(LSock, Acceptors).

sup_loop(LSock, Acceptors) ->
  receive
    {'EXIT', Acceptor, _Reason} ->
      A = lists:delete(Acceptor, Acceptors),
      sup_loop(LSock, [spawn(?MODULE, accept, [LSock])|A]);
    _ ->
      sup_loop(LSock, Acceptors)
  end.

start_acceptors(Num, LSock) ->
  start_acceptors(Num, LSock, []).

start_acceptors(0, _, Acceptors) ->
  Acceptors;
start_acceptors(Num, LSock, Acceptors) ->
  Acceptor = spawn(?MODULE, accept, [LSock]),
  start_acceptors(Num-1, LSock, [Acceptor|Acceptors]).

accept(LSock) ->
  case ecurvecp_connection:accept(LSock, infinity) of
    {ok, Sock} ->
      server_loop(Sock);
    Error ->
      Error
  end.

server_loop(Sock) ->
  ok = ecurvecp_connection:setopts(Sock, [{active, once}]),
  receive
    {ecurvecp, Sock, Data} ->
      ok = ecurvecp_connection:send(Sock, Data),
      server_loop(Sock);
    Error ->
      Error
  end.
