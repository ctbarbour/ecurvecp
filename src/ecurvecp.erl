-module(ecurvecp).

-export([start_client/3, start_client/4,
         start_server/1, start_server/2]).

start_client(Server, ServerPublicKey, #{public := ClientPublicKey, secret := ClientSecretKey}) ->
  start_client(Server, ServerPublicKey, ClientPublicKey, ClientSecretKey).

start_client(Server, ServerPublicKey, ClientPublicKey, ClientSecretKey) ->
  ecurvecp_client:start_link(Server, ServerPublicKey, ClientPublicKey, ClientSecretKey).

start_server(#{public := PublicKey, secret := SecretKey}) ->
  start_server(PublicKey, SecretKey).

start_server(PublicKey, SecretKey) ->
  ecurvecp_sup:start_server(PublicKey, SecretKey).
