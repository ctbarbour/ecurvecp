-module(ecurvecp_sup).
-behavior(supervisor).

-export([start_link/0]).
-export([init/1]).

-include("ecurvecp.hrl").

-spec start_link() -> {ok, pid()}.
start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
  ecurvecp_nonces = ets:new(ecurvecp_nonces, [public, named_table, ordered_set]),

  ServerKeyPair = enacl:box_keypair(),
  ListenIp = gproc:get_env(l, ecurvecp, listen_ip, [app_env, os_env, {default, all}]),
  ListenPort = gproc:get_env(l, ecurvecp, listen_port, [app_env, os_env, {default, 1337}]),

  ServerSup = {ecurvecp_server_sup,
               {ecurvecp_server_sup, start_link, [ServerKeyPair]},
               permanent, 5000, supervisor, [ecurvecp_server_sup]},

  ConnSup = {ecurve_conn,
             {ecurve_conn, start_link, [ListenIp, ListenPort]},
             permanent, 5000, worker, [ecurve_conn]},

  {ok, {{one_for_one, 10, 10}, [ServerSup, ConnSup]}}.
