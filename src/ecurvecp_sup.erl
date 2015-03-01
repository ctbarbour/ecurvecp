-module(ecurvecp_sup).
-behavior(supervisor).

-export([start_link/0]).
-export([init/1]).

-include("ecurvecp.hrl").

-spec start_link() -> {ok, pid()}.
start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
  ServerKeyPair = application:get_env(ecurvecp, server_keypair, enacl:box_keypair()),
  ListenIp = application:get_env(ecurvecp, listen_ip, all),
  ListenPort = application:get_env(ecurvecp, listen_port, 1337),
  Extension = application:get_env(ecurvecp, server_extension, ecurvecp:extension()),

  ecurvecp_nonces = ets:new(ecurvecp_nonces, [named_table, public, set]),

  Args = [ListenIp, ListenPort, Extension],
  UDPSup = {ecurvecp_udp,
            {ecurvecp_udp, start_link, Args},
             permanent, 5000, worker, [ecurvecp_udp]},

  ServerSup = {ecurvecp_server_sup,
               {ecurvecp_server_sup, start_link, [ServerKeyPair, Extension]},
               permanent, 5000, supervisor, [ecurvecp_sup]},

  ClientSup = {ecurvecp_client_sup,
               {ecurvecp_client_sup, start_link, []},
               permanent, 5000, supervisor, [ecurvecp_client_sup]},

  {ok, {{one_for_one, 10, 10}, [ServerSup, UDPSup, ClientSup]}}.
