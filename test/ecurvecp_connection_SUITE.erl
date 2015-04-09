-module(ecurvecp_connection_SUITE).

-export([all/0,
         groups/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_testcase/2,
         end_per_testcase/2]).

-export([handshake/1]).

-include_lib("common_test/include/ct.hrl").

all() ->
  [{group, basic}].

groups() ->
  [{basic, [shuffle, {repeat, 30}], [handshake]}].

init_per_suite(Config) ->
  ok = error_logger:tty(false),
  ok = application:load(ecurvecp),
  Keypair = enacl:box_keypair(),
  ok = application:set_env(ecurvecp, long_term_keypair, Keypair),
  _ = application:ensure_all_started(ecurvecp),
  Opts = [{keypair, Keypair}, {host, {127,0,0,1}}, {port, 1337}],
  Opts ++ Config.

end_per_suite(_Config) ->
  _ = application:stop(ecurvecp),
  ok.

init_per_testcase(_, Config) ->
  Config.

end_per_testcase(_, _Config) ->
  ok.

handshake(Config) ->
  Host = ?config(host, Config),
  Port = ?config(port, Config),
  #{public := PK} = ?config(keypair, Config),
  Server = start_server(Port),
  Client = start_client(Host, Port, PK),
  true = wait_all([Client, Server]),
  ok.

wait_all([]) ->
  true;
wait_all([P|Rest]) ->
  receive
    {ok, P} ->
      wait_all(Rest);
    {P, {error, Err}} ->
      {error, Err}
  after
    10000 ->
      {error, timeout}
  end.

start_server(Port) ->
  Caller = self(),
  spawn(fun() ->
        {ok, LSock} = ecurvecp_connection:listen([{port, Port}]),
        {ok, Socket} = ecurvecp_connection:accept(LSock, 5000),
        {ok, <<"1">>} = ecurvecp_connection:recv(Socket, 5000),
        ok = ecurvecp_connection:send(Socket, <<"1">>),
        {ok, <<"2">>} = ecurvecp_connection:recv(Socket, 5000),
        ok = ecurvecp_connection:send(Socket, <<"2">>),
        {ok, <<"3">>} = ecurvecp_connection:recv(Socket, 5000),
        ok = ecurvecp_connection:send(Socket, <<"3">>),
        ok = ecurvecp_connection:close(Socket),
        Caller ! {ok, self()}
    end).

start_client(Host, Port, Key) ->
  Caller = self(),
  spawn(fun() ->
        {ok, Socket} = ecurvecp_connection:connect(Host, Port, [{peer_long_term_public_key, Key}], 5000),
        ok = ecurvecp_connection:send(Socket, <<"1">>),
        {ok, <<"1">>} = ecurvecp_connection:recv(Socket, 5000),
        ok = ecurvecp_connection:send(Socket, <<"2">>),
        {ok, <<"2">>} = ecurvecp_connection:recv(Socket, 5000),
        ok = ecurvecp_connection:send(Socket, <<"3">>),
        {ok, <<"3">>} = ecurvecp_connection:recv(Socket, 5000),
        ok = ecurvecp_connection:close(Socket),
        Caller ! {ok, self()}
    end).
