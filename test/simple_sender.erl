-module(simple_sender).
-behavior(gen_server).

-export([start/0, start_link/0, connect/3, send/2, recv/1, close/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).

-record(st, {sock, from}).

start_link() ->
  gen_server:start_link(?MODULE, [], []).

start() ->
  gen_server:start(?MODULE, [], []).

connect(Pid, Ip, Port) ->
  gen_server:call(Pid, {connect, Ip, Port}).

send(Pid, Packet) ->
  gen_server:call(Pid, {send, Packet}).

recv(Pid) ->
  gen_server:call(Pid, recv, 1000).

close(Pid) ->
  try
    gen_server:call(Pid, close)
  catch
    exit:{noproc, _} ->
      ok
  end.

init([]) ->
  {ok, #st{}}.

handle_call({connect, Ip, Port}, _From, St) ->
  {ok, Sock} = gen_tcp:connect(Ip, Port, [{packet, 2}, binary, {active, false}], 5000),
  {reply, ok, St#st{sock=Sock}};
handle_call({send, Packet}, _From, #st{sock=Sock} = St) ->
  ok = gen_tcp:send(Sock, Packet),
  {reply, ok, St};
handle_call(recv, From, #st{sock=Sock} = St) ->
  ok = inet:setopts(Sock, [{active, once}]),
  {noreply, St#st{from=From}};
handle_call(close, _From, #st{sock=Sock} = St) ->
  if Sock /= undefined ->
      gen_tcp:close(Sock);
    true ->
      ok
  end,
  {stop, normal, ok, St};
handle_call(_, _, St) ->
  {noreply, St}.

handle_cast(_, St) ->
  {noreply, St}.

handle_info({tcp, Sock, Data}, #st{sock=Sock, from=From} = St) ->
  _ = gen_server:reply(From, Data),
  {noreply, St#st{from=undefined}};
handle_info({tcp_closed, Sock}, #st{sock=Sock, from=From} = St) ->
  if From /= undefined ->
      _ = gen_server:reply(From, {error, closed});
    true ->
      ok
  end,
  {noreply, St#st{sock=undefined}};
handle_info(Info, State) ->
  ok = error_logger:info_msg("unmatched info ~p\n", [Info]),
  {noreply, State}.

code_change(_OldVsn, St, _Extra) ->
  {ok, St}.

terminate(_Reason, _St) ->
  ok.
