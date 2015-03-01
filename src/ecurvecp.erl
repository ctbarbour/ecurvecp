-module(ecurvecp).

-export([start_client/4, extension/0]).

start_client(Ip, Port, ServerExtension, ServerPublicKey) ->
  ecurvecp_client_sup:start_client(Ip, Port, ServerExtension, ServerPublicKey).

extension() ->
  druuid:v4().
