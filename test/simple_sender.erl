-module(simple_sender).
-export([start/0, connect/3, send/2, recv/1, close/1, exit/1, init/0]).

start() ->
  spawn_link(?MODULE, init, []).

init() ->
  loop(undefiend).

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
      Data
  end.

close(Pid) ->
  Pid ! close,
  ok.

exit(Pid) ->
  Pid ! exit,
  receive
    ok ->
      ok
  end.

loop(Socket) ->
  receive
    {connect, Ip, Port, From} ->
      ok = error_logger:info_msg("[~p] Connecting to ~p:~p~n", [self(), Ip, Port]),
      case gen_tcp:connect(Ip, Port, [{packet, 2}, binary, {active, false}], 5000) of
        {ok, S} ->
          From ! ok,
          loop(S);
        Error ->
          From ! Error
      end;
    {send, Packet} ->
      ok = gen_tcp:send(Socket, Packet),
      loop(Socket);
    {recv, From} ->
      case gen_tcp:recv(Socket, 5000) of
        {ok, Data} ->
          From ! {tcp, Data};
        Error ->
          From ! Error
      end;
    close ->
      catch gen_tcp:close(Socket),
      loop(undefined);
    {exit, From} ->
      From ! ok,
      ok
  end.

