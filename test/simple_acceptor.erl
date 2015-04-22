-module(simple_acceptor).
-behavior(gen_server).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3,
         terminate/2]).
-export([start/1, send/2, recv/1, close/1]).

-record(st, {lsock, sock, q}).

start(LSock) ->
  gen_server:start(?MODULE, [LSock], []).

recv(Pid) ->
  gen_server:call(Pid, recv).

send(Pid, Data) ->
  gen_server:call(Pid, {send, Data}).

close(Pid) ->
  gen_server:call(Pid, close).

init([LSock]) ->
  {ok, #st{lsock=LSock, q=queue:new()}, 0}.

handle_call(recv, From, State) ->
  #st{sock=Sock, q=Q} = State,
  ok = ecurvecp_connection:setopts(Sock, [{active, once}]),
  {noreply, State#st{q=queue:in(From, Q)}};
handle_call({send, Data}, _From, State) ->
  #st{sock=Sock} = State,
  {reply, ecurvecp_connection:send(Sock, Data), State};
handle_call(close, _From, State) ->
  {stop, normal, ok, State};
handle_call(Msg, _From, State) ->
  ok = error_logger:info_msg("Unmatched call ~p\n", [Msg]),
  {stop, badarg, State}.

handle_cast(_, State) ->
  {noreply, State}.

handle_info(timeout, #st{lsock=LSock} = State) ->
  case ecurvecp_connection:accept(LSock, infinity) of
    {ok, Sock} ->
      ok = ecurvecp_connection:setopts(Sock, [{active, once}]),
      {noreply, State#st{sock=Sock}};
    {error, closed} ->
      {stop, normal, State};
    {error, _Reason} = Error ->
      {stop, Error, State}
  end;
handle_info({ecurvecp, Sock, Data}, #st{sock=Sock} = S) ->
  #st{q=Q} = S,
  ok = ecurvecp_connection:send(Sock, Data),
  ok = ecurvecp_connection:setopts(Sock, [{active, once}]),
  case queue:out(Q) of
    {{value, From}, Q2} ->
      gen_server:reply(From, Data),
      {noreply, S#st{q=Q2}};
    {empty, _} ->
      {noreply, S}
  end;
handle_info({ecurvecp_closed, Sock}, #st{sock=Sock, q=Q} = S) ->
  case queue:out(Q) of
    {{value, From}, Q2} ->
      gen_server:reply(From, {error, closed}),
      {stop, normal, S#st{q=Q2}};
    {empty, _} ->
      {stop, normal, S}
  end;
handle_info(Info, S) ->
  ok = error_logger:info_msg("Unmatched info ~p\n", [Info]),
  {stop, badarg, S}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.
