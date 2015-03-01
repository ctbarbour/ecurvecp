-module(ecurvecp_server_sup).
-behavior(supervisor).

-export([start_link/2, start_server/0]).
-export([init/1]).

start_link(ServerKeyPair, Extension) ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, [ServerKeyPair, Extension]).

start_server() ->
  supervisor:start_child(?MODULE, []).

init([ServerKeyPair, Extension]) ->
  ChildSpec = {undefined,
               {ecurvecp_server, start_link, [ServerKeyPair, Extension]},
               temporary, 5000, worker, [ecurvecp_server]},
  {ok, {{simple_one_for_one, 10, 10}, [ChildSpec]}}.
