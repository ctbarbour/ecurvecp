-module(simple_sender).
-export([start/0, connect/3, send/2, recv/1, close/1, exit/1, init/0]).

start() ->
  spawn_link(?MODULE, init, []).

init() ->
  loop(undefiend, undefined).

connect(Pid, Ip, Port) ->
  Pid ! {connect, Ip, Port, self()},
  receive
    Resp ->
      Resp
  end.

send(Pid, Packet) ->
  Pid ! {send, Packet},
  ok.

recv(Pid) ->
  Pid ! {recv, self()},
  receive
    Data ->
      {tcp, Data}
  end.

close(Pid) ->
  Pid ! {close, self()},
  receive
    Resp ->
      Resp
  end.

exit(Pid) ->
  Pid ! exit,
  receive
    ok ->
      ok
  end.

loop(Socket, F) ->
  receive
    {connect, Ip, Port, From} ->
      case gen_tcp:connect(Ip, Port, [{packet, 2}, binary, {active, false}], 5000) of
        {ok, S} ->
          From ! ok,
          loop(S, undefined);
        Error ->
          From ! Error
      end;
    {send, Packet} ->
      ok = gen_tcp:send(Socket, Packet),
      loop(Socket, F);
    {recv, From} ->
      ok = inet:setopts(Socket, [{active, once}]),
      loop(Socket, From);
    {tcp, Socket, Data} ->
      F ! Data,
      loop(Socket, undefined);
    {close, From} ->
      From ! (catch gen_tcp:close(Socket)),
      loop(undefined, undefined);
    {exit, From} ->
      From ! ok,
      ok
  end.
