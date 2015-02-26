-module(ecurvecp_sup).
-behavior(supervisor).

-export([start_link/0, start_server/2]).
-export([init/1]).

start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_server(PublicKey, SecretKey) ->
  ServerSpec = server_spec(PublicKey, SecretKey),
  supervisor:start_child(?MODULE, ServerSpec).

server_spec(PublicKey, SecretKey) ->
  {ecurvecp_server,
   {ecurvecp_server, start_link, [PublicKey, SecretKey]},
   temporary, 5000, worker, [ecurvecp_server]}.

init([]) ->
  {ok, {{one_for_one, 10, 10}, []}}.
