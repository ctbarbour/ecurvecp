-module(ecurvecp_messages).

-export([nonce/1, nonce_string/2, extension/1, extension_pid/1]).

-include("ecurvecp.hrl").

-spec nonce(message_type()) -> {nonce(), nonce_string()}.
nonce(hello) ->
  Nonce = enacl:randombytes(8),
  {Nonce, nonce_string(hello, Nonce)};
nonce(cookie) ->
  Nonce = enacl:randombytes(16),
  {Nonce, nonce_string(cookie, Nonce)};
nonce(vouch) ->
  Nonce = enacl:randombytes(16),
  {Nonce, nonce_string(vouch, Nonce)};
nonce(initiate) ->
  Nonce = enacl:randombytes(8),
  {Nonce, nonce_string(initiate, Nonce)};
nonce(server_message) ->
  Nonce = enacl:randombytes(8),
  {Nonce, nonce_string(server_message, Nonce)};
nonce(client_message) ->
  Nonce = enacl:randombytes(8),
  {Nonce, nonce_string(client_message, Nonce)}.

-spec nonce_string(message_type(), <<_:8>> | <<_:16>>) -> <<_:24>>.
nonce_string(hello, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-H", Nonce/binary>>;
nonce_string(cookie, <<_:16/binary>> = Nonce) ->
  <<"CurveCPK", Nonce/binary>>;
nonce_string(vouch, <<_:16/binary>> = Nonce) ->
  <<"CurveCPV", Nonce/binary>>;
nonce_string(initiate, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-I", Nonce/binary>>;
nonce_string(server_message, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-server-M", Nonce/binary>>;
nonce_string(client_message, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-M", Nonce/binary>>.

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
