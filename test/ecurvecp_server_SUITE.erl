-module(ecurvecp_server_SUITE).

-export([all/0,
         init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

-export([server_handshake/1]).

-include_lib("common_test/include/ct.hrl").

all() ->
  [server_handshake].

init_per_suite(Config) ->
  ok = application:start(ecurvecp),
  ClientLongTermKeypair = enacl:box_keypair(),
  ClientShortTermKeypair = enacl:box_keypair(),
  ServerKeypair = enacl:box_keypair(),
  SE = druuid:v4(),
  CE = druuid:v4(),
  [{server_keypair, ServerKeypair},
   {server_extension, SE},
   {client_extension, CE},
   {client_long_term_keypair, ClientLongTermKeypair},
   {client_short_term_keypair, ClientShortTermKeypair} | Config].

end_per_suite(_Config) ->
  application:stop(ecurvecp).

init_per_testcase(server_handshake, Config) ->
  {ok, Server} = ecurvecp_protocol:start_link(self(), test_transport,
                                       [{server_keypair, ?config(server_keypair, Config)},
                                        {server_extension, ?config(server_extension, Config)}]),
  [{server, Server}|Config].

end_per_testcase(server_handshake, Config) ->
  Server = ?config(server, Config),
  ok = ecurvecp_protocol:stop(Server),
  ok.

server_handshake(Config) ->
  Server = ?config(server, Config),
  #{public := SLTPK} = ?config(server_keypair, Config),
  #{public := CLTPK, secret := CLTSK} = ?config(client_long_term_keypair, Config),
  #{public := CSTPK, secret := CSTSK} = ?config(client_short_term_keypair, Config),
  SE = ?config(server_extension, Config),
  CE = ?config(client_extension, Config),
  HelloPacket = ecurvecp_codec:encode_hello_packet(CSTPK, CSTSK, SLTPK, SE, CE),
  Response = send_and_wait(Server, HelloPacket),
  CookiePacket = ecurvecp_codec:decode_cookie_packet(Response),
  #{server_short_term_public_key := SSTPK,
    cookie := Cookie} = ecurvecp_codec:decode_cookie_box(CookiePacket, SLTPK, CSTSK),
  Vouch = ecurvecp_codec:encode_vouch(CLTSK, CSTPK, SLTPK),
  DomainName = ecurvecp_codec:encode_domain_name("geo.apple.com"),
  InitiatePacket = ecurvecp_codec:encode_initiate_packet(CLTPK, CSTPK, CSTSK, SSTPK, Vouch, Cookie, DomainName, SE, CE),
  _ServerMsgPacket = send_and_wait(Server, InitiatePacket).

send_and_wait(Server, Packet) ->
  MRef = erlang:monitor(process, Server),
  Server ! {ok, self(), Packet},
  receive
    {test_transport, Server, Response} ->
      Response;
    {'DOWN', MRef, process, Server, Reason} ->
      exit({server_shutdown, Reason});
    _ ->
      exit(unmatched_messages)
  after
    100 ->
      exit(timeout)
  end.
