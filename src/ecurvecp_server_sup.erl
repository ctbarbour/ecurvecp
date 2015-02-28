-module(ecurvecp_server_sup).
-behavior(supervisor).

-export([start_link/1, start_server/1]).
-export([init/1]).

start_link(ServerKeyPair) ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, [ServerKeyPair]).

start_server(ClientExt) ->
  supervisor:start_child(?MODULE, [ClientExt]).

init([ServerKeyPair]) ->
  ChildSpec = {undefined,
               {ecurvecp_server, start_link, [ServerKeyPair]},
               temporary, 5000, worker, [ecurvecp_server]},
  {ok, {{simple_one_for_one, 10, 10}, [ChildSpec]}}.
