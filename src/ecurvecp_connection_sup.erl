-module(ecurvecp_connection_sup).
-behaviour(supervisor).

-export([start_link/0, start_child/1]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_child(Args) ->
    supervisor:start_child(?MODULE, Args).

init([]) ->
    RestartStrategy = simple_one_for_one,
    MaxR = 50,
    MaxT = 3600,
    Name = undefined,
    StartFunc = {ecurvecp_connection, start_link, []},
    Restart = temporary,
    Shutdown = 4000,
    Modules = [ecurvecp_connection],
    Type = worker,
    ChildSpec = {Name, StartFunc, Restart, Shutdown, Type, Modules},
    {ok,
      {{RestartStrategy, MaxR, MaxT},
       [ChildSpec]}}.
