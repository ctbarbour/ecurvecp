-module(ecurvecp_sup).
-behavior(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
  LongTermKeypair = application:get_env(ecurvecp, long_term_keypair, enacl:box_keypair()),

  ConnSup = {ecurvecp_connection_sup,
             {ecurvecp_connection_sup, start_link, []},
             permanent, 5000, supervisor, [ecurvecp_connection_sup]},

  Cookie = {ecurvecp_cookie,
            {ecurvecp_cookie, start_link, []},
            permanent, 5000, worker, [ecurvecp_cookie]},

  Vault = {ecurvecp_vault,
           {ecurvecp_vault, start_link, [LongTermKeypair]},
           permanent, 5000, worker, [ecurvecp_vault]},

  {ok, {{one_for_one, 10, 10}, [Vault, Cookie, ConnSup]}}.
