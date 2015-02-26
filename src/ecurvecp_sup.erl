-module(ecurvecp_sup).
-behavior(supervisor).

-export([start_link/0, start_client/1, start_server/1]).
-export([init/1]).

start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_client(KeyPair) ->
  ClientSpec = client_spec(KeyPair),
  supervisor:start_child(?MODULE, ClientSpec).

start_server(KeyPair) ->
  ServerSpec = server_spec(KeyPair),
  supervisor:start_child(?MODULE, ServerSpec).

client_spec(#{public := PubKey, secret := SecKey}) ->
  {ecurvecp_client,
   {ecurvecp_client, start_link, [PubKey, SecKey]},
   temporary, 5000, worker, [ecurvecp_client]}.

server_spec(#{public := PubKey, secret := SecKey}) ->
  {ecurvecp_server,
   {ecurvecp_server, start_link, [PubKey, SecKey]},
   temporary, 5000, worker, [ecurvecp_server]}.

init([]) ->
  {ok, {{one_for_one, 10, 10}, []}}.
