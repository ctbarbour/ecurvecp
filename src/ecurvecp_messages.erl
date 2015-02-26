-module(ecurvecp_messages).

-export([nonce_string/2, extension/1, extension_pid/1]).

-type message_type() :: hello | cookie | initiate
  | server_message | client_message.

-spec nonce_string(message_type(), <<_:8>> | <<_:16>>) -> <<_:24>>.
nonce_string(hello, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-H", Nonce/binary>>;
nonce_string(cookie, <<_:16/binary>> = Nonce) ->
  <<"CurveCPK", Nonce/binary>>;
nonce_string(initiate, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-I", Nonce/binary>>;
nonce_string(servce_message, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-server-M", Nonce/binary>>;
nonce_string(client_message, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-M", Nonce/binary>>.

-spec extension(pid()) -> <<_:16>>.
extension(Pid) ->
  List = pid_to_list(Pid),
  Size = length(List),
  case 16 - Size of
    Diff when Diff > 0 ->
      << Size/integer, (list_to_binary(List))/binary, (binary:copy(<<0>>, Diff - 1))/binary >>;
    _Diff ->
      exit({pid_too_larger, Pid})
  end.

-spec extension_pid(<<_:16>>) -> pid().
extension_pid(<<Size/integer, Rest/binary>>) ->
  <<Pid:Size/binary, _/binary>> = Rest,
  list_to_pid(binary_to_list(Pid)).
