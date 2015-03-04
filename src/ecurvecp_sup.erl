-module(ecurvecp_sup).
-behavior(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
  ecurvecp_nonces = ets:new(ecurvecp_nonces, [named_table, public, set]),

  ServerSup = {ecurvecp_server_sup,
               {ecurvecp_server_sup, start_link, []},
               permanent, 5000, supervisor, [ecurvecp_server_sup]},

  ClientSup = {ecurvecp_client_sup,
               {ecurvecp_client_sup, start_link, []},
               permanent, 5000, supervisor, [ecurvecp_client_sup]},

  {ok, {{one_for_one, 10, 10}, [ServerSup, ClientSup]}}.
