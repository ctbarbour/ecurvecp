-module(ecurvecp_client_sup).
-behavior(supervisor).

-export([start_link/0, start_client/4]).
-export([init/1]).

start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_client(Ip, Port, Extension, PublicKey) ->
  Args = [Ip, Port, Extension, PublicKey],
  supervisor:start_child(?MODULE, Args).

init([]) ->
  ClientKeypair = application:get_env(ecurvecp, client_keypair, enacl:box_keypair()),
  Spec = {undefined,
          {ecurvecp_client, start_link, [ClientKeypair]},
          temporary, 5000, worker, [ecurvecp_client]},
  {ok, {{simple_one_for_one, 10, 10}, [Spec]}}.
