-module(ecurvecp_sup).
-behavior(supervisor).

-export([start_link/0, start_client/3, start_server/1]).
-export([init/1]).

start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_client(Server, ServerPublicKey, KeyPair) ->
  ClientSpec = client_spec(Server, ServerPublicKey, KeyPair),
  supervisor:start_child(?MODULE, ClientSpec).

start_server(KeyPair) ->
  ServerSpec = server_spec(KeyPair),
  supervisor:start_child(?MODULE, ServerSpec).

client_spec(Server, ServerPublicKey, ClientKeyPair) ->
  {ecurvecp_client,
   {ecurvecp_client, start_link, [Server, ServerPublicKey, ClientKeyPair]},
   temporary, 5000, worker, [ecurvecp_client]}.

server_spec(ServerKeyPair) ->
  {ecurvecp_server,
   {ecurvecp_server, start_link, [ServerKeyPair]},
   temporary, 5000, worker, [ecurvecp_server]}.

init([]) ->
  {ok, {{one_for_one, 10, 10}, []}}.
