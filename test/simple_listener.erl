-module(simple_listener).
-behavior(gen_server).

-export([start/2, start_link/2, send/2, recv/1, close/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).

-record(st, {port, lsock, csock, q}).

start_link(Ip, Port) ->
  gen_server:start_link(?MODULE, [Ip, Port], []).

start(Ip, Port) ->
  gen_server:start(?MODULE, [Ip, Port], []).

recv(Pid) ->
  gen_server:call(Pid, recv).

send(Pid, Data) ->
  gen_server:call(Pid, {send, Data}).

close(Pid) ->
  gen_server:call(Pid, close).

init([Ip, Port]) ->
  case ecurvecp_connection:listen([{ip, Ip}, {port, Port}]) of
    {ok, LSock} ->
      {ok, #st{port=Port, lsock=LSock, q=queue:new()}, 0};
    {error, _Reason} = Error ->
      {stop, Error}
  end.

handle_call(recv, From, State) ->
  #st{csock=Sock, q=Q} = State,
  ok = ecurvecp_connection:setopts(Sock, [{active, once}]),
  {noreply, State#st{q=queue:in(From, Q)}};
handle_call({send, Data}, _From, State) ->
  #st{csock=Sock} = State,
  {reply, ecurvecp_connection:send(Sock, Data), State};
handle_call(close, _From, State) ->
  {stop, normal, ok, State};
handle_call(Msg, _From, State) ->
  ok = error_logger:info_msg("Unmatched call ~p\n", [Msg]),
  {stop, badarg, State}.

handle_cast(_, State) ->
  {noreply, State}.

handle_info(timeout, #st{lsock=LSock} = S) ->
  case ecurvecp_connection:accept(LSock, infinity) of
    {ok, Sock} ->
      ok = ecurvecp_connection:setopts(Sock, [{active, once}]),
      {noreply, S#st{csock=Sock}};
    {error, closed} ->
      {stop, normal, S};
    {error, _Reason} = Error ->
      {stop, Error, S}
  end;
handle_info({ecurvecp, Sock, Data}, #st{csock=Sock} = S) ->
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
handle_info({ecurvecp_closed, Sock}, #st{csock=Sock} = S) ->
  {stop, normal, S};
handle_info(Info, S) ->
  ok = error_logger:info_msg("Unmatched info ~p\n", [Info]),
  {stop, badarg, S}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.
