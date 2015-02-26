-module(ecurvecp).

-export([start_client/3, start_client/4,
         start_server/1, start_server/2]).
-export([extension/1, extension_pid/1]).

-include("ecurvecp.hrl").

-spec start_client(pid(), key(), key_pair()) -> {ok, pid()}.
start_client(Server, ServerPublicKey, #{public := ClientPublicKey, secret := ClientSecretKey}) ->
  start_client(Server, ServerPublicKey, ClientPublicKey, ClientSecretKey).

-spec start_client(pid(), key(), key(), key()) -> {ok, pid()}.
start_client(Server, ServerPublicKey, ClientPublicKey, ClientSecretKey) ->
  ecurvecp_client:start_link(Server, ServerPublicKey, ClientPublicKey, ClientSecretKey).

-spec start_server(key_pair()) -> {ok, pid()}.
start_server(#{public := PublicKey, secret := SecretKey}) ->
  start_server(PublicKey, SecretKey).

-spec start_server(key(), key()) -> {ok, pid()}.
start_server(PublicKey, SecretKey) ->
  ecurvecp_sup:start_server(PublicKey, SecretKey).

-spec extension(pid()) -> <<_:16>>.
extension(Pid) ->
  Bin = list_to_binary(pid_to_list(Pid)),
  case (16 - size(Bin) rem 16) rem 16 of
    0 ->
      Bin;
    N ->
      <<Bin/binary, 0:(N*8)>>
  end.

-spec extension_pid(<<_:16>>) -> pid().
extension_pid(Bin) ->
  list_to_pid(
    binary_to_list(hd(binary:split(Bin, [<<0>>], [trim, global])))).
