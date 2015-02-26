-module(ecurvecp_sup).
-behavior(supervisor).

-export([start_link/0, start_server/2]).
-export([init/1]).

-include("ecurvecp.hrl").

-spec start_link() -> {ok, pid()}.
start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec start_server(key(), key()) -> {ok, pid()}.
start_server(PublicKey, SecretKey) ->
  ServerSpec = server_spec(PublicKey, SecretKey),
  supervisor:start_child(?MODULE, ServerSpec).

server_spec(PublicKey, SecretKey) ->
  {ecurvecp_server,
   {ecurvecp_server, start_link, [PublicKey, SecretKey]},
   temporary, 5000, worker, [ecurvecp_server]}.

init([]) ->
  ecurvecp_nonces = ets:new(ecurvecp_nonces, [public, named_table, ordered_set]),
  {ok, {{one_for_one, 10, 10}, []}}.
