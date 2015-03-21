-module(test_transport).

-export([setopts/2, messages/0, close/1, send/2]).

setopts(_, _) -> ok.
messages() -> {ok, closed, error}.
close(_) -> ok.
send(Socket, Packet) ->
  Socket ! {?MODULE, self(), Packet},
  ok.
