-module(ecurvecp_server_sup).
-behavior(supervisor).

-export([start_link/0, start_listener/4, stop_listener/1]).
-export([init/1]).

start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_listener(Ref, NumListeners, TransOpts, ProtoOpts) ->
  Transport = ranch_tcp,
  Protocol = ecurvecp_protocol,
  Spec = ranch:child_spec(Ref, NumListeners, Transport, TransOpts, Protocol, ProtoOpts),
  supervisor:start_child(?MODULE, Spec).

stop_listener(Ref) ->
  case supervisor:terminate_child(?MODULE, {ranch_listener_sup, Ref}) of
    ok ->
      _ = supervisor:delete_child(?MODULE, {ranch_listener_sup, Ref}),
      _ = [ets:delete(ranch_server, {F, Ref}) || F <- [port, max_conns, opts]],
      ok;
    Error ->
      Error
  end.

init([]) ->
  RestartStrategy = one_for_one,
  MaxRestarts = 10,
  MaxTime = 3600,

  RanchSup = {ranch_sup,
              {ranch_sup, start_link, []},
              permanent, 5000, supervisor, [ranch_sup]},

  {ok, {{RestartStrategy, MaxRestarts, MaxTime}, [RanchSup]}}.
