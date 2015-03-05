-module(test_transport).

-export([setopts/2, send/2, messages/0, close/1]).

setopts(_Socket, _Opts) -> ok.
send(_Socket, _Msg) -> ok.
messages() -> {ok, closed, error}.
close(_Socket) -> ok.
