-module(simple_listener).
-behavior(gen_server).

-export([start/2, acceptor/1, close/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3, terminate/2]).

-record(st, {port, lsock, acceptors}).

start(Ip, Port) ->
  gen_server:start(?MODULE, [Ip, Port], []).

close(Pid) ->
  gen_server:call(Pid, close).

acceptor(Pid) ->
  gen_server:call(Pid, acceptor).

init([Ip, Port]) ->
  case ecurvecp_connection:listen([{ip, Ip}, {port, Port}]) of
    {ok, LSock} ->
      {ok, #st{port=Port, lsock=LSock}};
    {error, _Reason} = Error ->
      {stop, Error}
  end.

handle_call(close, _From, State) ->
  {stop, normal, ok, State};
handle_call(acceptor, _From, #st{lsock=LSock} = S) ->
  {reply, simple_acceptor:start(LSock), S};
handle_call(Msg, _From, State) ->
  ok = error_logger:info_msg("Unmatched call ~p\n", [Msg]),
  {stop, badarg, State}.

handle_cast(_, State) ->
  {noreply, State}.

handle_info(Info, S) ->
  ok = error_logger:info_msg("Unmatched info ~p\n", [Info]),
  {stop, badarg, S}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.
