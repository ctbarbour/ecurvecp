-module(ecurvecp).

-export([start_client/3, start_client/4, extension/0]).

-include("ecurvecp.hrl").

-spec start_client(pid(), key(), key_pair()) -> {ok, pid()}.
start_client(Server, ServerPublicKey, #{public := ClientPublicKey, secret := ClientSecretKey}) ->
  start_client(Server, ServerPublicKey, ClientPublicKey, ClientSecretKey).

-spec start_client(pid(), key(), key(), key()) -> {ok, pid()}.
start_client(Server, ServerPublicKey, ClientPublicKey, ClientSecretKey) ->
  ecurvecp_client:start_link(Server, ServerPublicKey, ClientPublicKey, ClientSecretKey).

-spec extension() -> extension().
extension() ->
  druuid:v4().
