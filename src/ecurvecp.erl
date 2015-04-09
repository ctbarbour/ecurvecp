-module(ecurvecp).

-export([get_prop_or_env/2, get_prop_or_env/3, get_env/2]).

-export([name/0,
         secure/0,
         messages/0,
         accept/2,
         accept_ack/2,
         listen/1,
         connect/3, connect/4,
         recv/2,
         send/2,
         controlling_process/2,
         close/1,
         shutdown/2,
         setopts/2,
         peername/1,
         sockname/1
      ]).

name() ->
  ecurvecp.

secure() ->
  true.

messages() ->
  ecurvecp_connection:messages().

accept(Socket, Timeout) ->
  ecurvecp_connection:accept(Socket, Timeout).

accept_ack(_Socket, _Timeout) ->
  ok.

listen(Opts) ->
  ecurvecp_connection:listen(Opts).

connect(Address, Port, Opts) ->
  ecurvecp_connection:connect(Address, Port, Opts, infinity).

connect(Address, Port, Opts, Timeout) ->
  ecurvecp_connection:connect(Address, Port, Opts, Timeout).

send(Socket, Data) ->
  ecurvecp_connection:send(Socket, Data).

recv(Socket, Timeout) ->
  ecurvecp_connection:recv(Socket, Timeout).

close(Socket) ->
  ecurvecp_connection:close(Socket).

setopts(Socket, Opts) ->
  ecurvecp_connection:setopts(Socket, Opts).

peername(Socket) ->
  ecurvecp_connection:peername(Socket).

sockname(Socket) ->
  ecurvecp_connection:sockname(Socket).

shutdown(Socket, How) ->
  ecurvecp_connection:shutdown(Socket, How).

controlling_process(Socket, Pid) ->
  ecurvecp_connection:controlling_process(Socket, Pid).

get_prop_or_env(Key, Props) ->
  get_prop_or_env(Key, Props, undefined).

get_prop_or_env(Key, Props, Default) ->
  case proplists:get_value(Key, Props) of
    undefined ->
      get_env(Key, Default);
    Value ->
      Value
  end.

get_env(Key, Default) ->
  application:get_env(?MODULE, Key, Default).
