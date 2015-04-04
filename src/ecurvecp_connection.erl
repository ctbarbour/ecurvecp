-module(ecurvecp_connection).
-behavior(gen_fsm).

-define(HELLO, "QvnQ5XlH").
-define(WELCOME, "RL3aNMXK").
-define(INITIATE, "QvnQ5XlI").
-define(READY, "RL3aNMXR").
-define(MESSAGE, "RL3aNMXM").
-define(ERROR, "ERROR---").

-define(MAJOR_V, 1).
-define(MINOR_V, 0).
-define(VERSION, <<?MAJOR_V:8/unsigned-integer, ?MINOR_V:8/unsigned-integer>>).

-export([name/0]).
-export([secure/0]).
-export([messages/0]).
-export([accept_ack/2]).
-export([connect/3]).
-export([setopts/2]).
-export([peername/1]).
-export([sockname/1]).
-export([shutdown/2]).

-export([start_link/1,
         listen/1,
         accept/2,
         connect/4,
         recv/2,
         send/2,
         controlling_process/2,
         close/1
        ]).

-export([init/1,
         handle_event/3,
         handle_sync_event/4,
         handle_info/3,
         code_change/4,
         terminate/3
        ]).

-export([waiting/3,
         hello/2,
         welcome/2,
         initiate/2,
         ready/2,
         established/2, established/3
        ]).

-export([parse_packet/1]).
-export([encode_hello_packet/4]).
-export([decode_hello_packet/2]).
-export([encode_welcome_packet/4]).
-export([decode_welcome_packet/3]).
-export([encode_cookie/2]).
-export([verify_cookie/2]).
-export([encode_initiate_packet/7]).
-export([encode_vouch/4]).
-export([verify_vouch/6]).
-export([decode_initiate_packet/3]).
-export([encode_ready_packet/3]).
-export([decode_ready_packet/3]).
-export([encode_msg_packet/5]).
-export([decode_msg_packet/4]).

-record(hello_packet, {
    version,
    client_short_term_public_key,
    nonce,
    box
  }).

-record(welcome_packet, {
    nonce,
    box
  }).

-record(initiate_packet, {
    cookie,
    nonce,
    box
  }).

-record(ready_packet, {
    box,
    nonce
  }).

-record(msg_packet, {
    nonce,
    box
  }).

-record(error_packet, {
    reason
  }).

-record(ecurvecp_lsock, {
    lsock :: inet:socket()
  }).

-record(ecurvecp_socket, {
    pid :: pid()
  }).

-record(st, {
    socket                        :: inet:socket(),
    controller                    :: {module(), reference()},
    peer                          :: {address(), inet:port_number()},
    from                          :: from(),
    handshake_ttl                 :: timeout(),
    connection_ttl                :: timeout(),
    vault                         :: module(),
    peer_long_term_public_key     :: key(),
    peer_short_term_public_key    :: key(),
    short_term_public_key         :: key(),
    short_term_secret_key         :: key(),
    short_term_shared_key         :: key(),
    nonce_counter                 :: non_neg_integer(),
    received_nonce_counter        :: non_neg_integer(),
    buffer                        :: queue:queue(iodata()),
    recv_queue                    :: queue:queue(pid()),
    negotiated_version            :: pos_integer(),
    active                        :: boolean() | once,
    side                          :: client | server
  }).

-type from()              :: {pid(), reference()}.
-type key()               :: <<_:256>>.
-type lsock()             :: #ecurvecp_lsock{}.
-type csock()             :: #ecurvecp_socket{}.
-type socket()            :: lsock() | csock().
-type opts()              :: [atom() | {atom(), term()}].
-type address()           :: inet:ip_address() | inet:hostname().
-type hello_packet()      :: #hello_packet{}.
-type welcome_packet()    :: #welcome_packet{}.
-type initiate_packet()   :: #initiate_packet{}.
-type msg_packet()        :: #msg_packet{}.
-type ready_packet()      :: #ready_packet{}.
-type ecurvecp_packet()   :: hello_packet() | welcome_packet()
  | initiate_packet() | ready_packet() | msg_packet().

name() ->
  ecurvecp.

secure() ->
  true.

messages() ->
  {ecurvecp, ecurvecp_closed, ecurvecp_error}.

accept_ack(_Socket, _Timeout) ->
  ok.

setopts(Socket, Opts) ->
  #ecurvecp_socket{pid=Pid} = Socket,
  gen_fsm:sync_send_all_state_event(Pid, {setopts, Opts}).

peername(#ecurvecp_lsock{lsock=Socket}) ->
  inet:peername(Socket);
peername(#ecurvecp_socket{pid=Pid}) ->
  gen_fsm:sync_send_all_state_event(Pid, peername).

sockname(#ecurvecp_lsock{lsock=Socket}) ->
  inet:sockname(Socket);
sockname(#ecurvecp_socket{pid=Pid}) ->
  gen_fsm:sync_send_all_state_event(Pid, sockname).

shutdown(Socket, How) ->
  #ecurvecp_socket{pid=Pid} = Socket,
  gen_fsm:sync_send_all_state_event(Pid, {shutdown, How}).

start_link(Controller) ->
  gen_fsm:start_link(?MODULE, [Controller], []).

-spec listen(opts()) -> {ok, socket()} | {error, atom()}.
listen(Opts) ->
  TcpOpts = [binary,
             {packet, 2},
             {active, false},
             {reuseaddr, true},
             {nodelay, true},
             {backlog, 1024},
             {send_timeout, 30000},
             {send_timeout_close, true} | Opts],
  case gen_tcp:listen(0, TcpOpts) of
    {ok, LSock} ->
      {ok, #ecurvecp_lsock{lsock=LSock}};
    {error, Reason} ->
      {error, Reason}
  end.

-spec accept(socket(), timeout())
  -> {ok, socket()} | {error, closed | timeout | atom()}.
accept(#ecurvecp_lsock{lsock=LSock}, Timeout) ->
  {ok, Pid} = start_fsm(),
  case gen_fsm:sync_send_event(Pid, {accept, LSock, Timeout}, infinity) of
    ok ->
      {ok, #ecurvecp_socket{pid=Pid}};
    {error, Reason} ->
      {error, Reason}
  end.

-spec connect(address(), inet:port_number(), opts())
  -> {ok, csock()} | {error, atom()}.
connect(Address, Port, Opts) ->
  connect(Address, Port, Opts, infinity).

-spec connect(address(), inet:port_number(), opts(), timeout())
  -> {ok, socket()} | {error, atom()}.
connect(Address, Port, Opts, Timeout) ->
  {ok, Pid} = start_fsm(),
  Options = [{handshake_ttl, Timeout} | Opts],
  case gen_fsm:sync_send_event(Pid, {connect, Address, Port, Options}, infinity) of
    ok ->
      {ok, #ecurvecp_socket{pid=Pid}};
    {error, Reason} ->
      {error, Reason}
  end.

-spec send(socket(), iodata()) -> ok | {error, atom()}.
send(#ecurvecp_socket{pid=Pid}, Packet) ->
  case catch(gen_fsm:sync_send_event(Pid, {send, Packet})) of
    ok ->
      ok;
    {error, Reason} ->
      {error, Reason};
    {'EXIT', {noproc, _}} ->
      {error, closed}
  end.

-spec recv(socket(), timeout())
  -> {ok, term()} | {error, closed | timeout | atom()}.
recv(#ecurvecp_socket{pid=Pid}, Timeout) ->
  try
    gen_fsm:sync_send_event(Pid, recv, Timeout)
  catch
    exit:{noproc, _} ->
      {error, closed};
    exit:{timeout, _} ->
      {error, timeout}
  end.

-spec close(socket()) -> ok | {error, atom()}.
close(#ecurvecp_socket{pid=Pid}) ->
  gen_fsm:sync_send_event(Pid, close).

-spec controlling_process(socket(), pid())
  -> ok | {error, closed | not_owner | atom()}.
controlling_process(#ecurvecp_socket{pid=Pid}, Controller) ->
  gen_fsm:sync_send_all_state_event(Pid, {controlling_process, Controller}).

init([Controller]) ->
  MRef = erlang:monitor(process, Controller),
  State = #st{controller={Controller, MRef},
              nonce_counter=0,
              received_nonce_counter=0,
              vault=ecurvecp_vault,
              buffer=queue:new(),
              active=false,
              recv_queue=queue:new()},
  {ok, waiting, State}.

-spec parse_packet(binary())
  -> {ok, ecurvecp_packet()} | {error, unmatched_packet}.
parse_packet(<<?HELLO, Version:2/binary, _Z:64/binary, CSP:32/binary,
               Nonce:8/binary, Box:80/binary>>) ->
  {ok, #hello_packet{version=Version,
                     client_short_term_public_key=CSP,
                     nonce=Nonce,
                     box=Box}};
parse_packet(<<?INITIATE, Cookie:96/binary, Nonce:8/binary, Box/binary>>) ->
  {ok, #initiate_packet{cookie=Cookie,
                        nonce=Nonce,
                        box=Box}};
parse_packet(<<?WELCOME, Nonce:16/binary, Box:144/binary>>) ->
  {ok, #welcome_packet{nonce=Nonce, box=Box}};
parse_packet(<<?READY, Nonce:8/binary, Box/binary>>) ->
  {ok, #ready_packet{nonce=Nonce, box=Box}};
parse_packet(<<?MESSAGE, Nonce:8/binary, Box/binary>>) ->
  {ok, #msg_packet{nonce=Nonce, box=Box}};
parse_packet(<<?ERROR, Reason/binary>>) ->
  {ok, #error_packet{reason=Reason}};
parse_packet(_) ->
  {error, unmatched_packet}.

encode_hello_packet(SLP, CSP, CSS, NonceCounter) ->
  Z = binary:copy(<<0>>, 64),
  Nonce = <<NonceCounter:64/unsigned-little-integer>>,
  NonceString = nonce_string(hello, Nonce),
  Box = enacl:box(Z, NonceString, SLP, CSS),
  <<?HELLO, ?VERSION/binary, Z/binary, CSP/binary, Nonce/binary, Box/binary>>.

decode_hello_packet(Hello, Vault) ->
  #hello_packet{nonce=Nonce, box=Box, version=Version,
                client_short_term_public_key=CSP} = Hello,
  case verify_version(Version) of
    true ->
      case verify_hello_packet_box(Nonce, Box, CSP, Vault) of
        true ->
          {ok, CSP};
        false ->
          {error, invalid_hello_box}
      end;
    false ->
      {error, version_mismatch}
  end.

verify_version(<<?MAJOR_V:8/unsigned-integer, _Minor:8/unsigned-integer>>) ->
  true;
verify_version(_Version) ->
  false.

verify_hello_packet_box(Nonce, Box, CSP, Vault) ->
  NonceString = nonce_string(hello, Nonce),
  case Vault:box_open(Box, NonceString, CSP) of
    {ok, Contents} ->
      verify_hello_box_contents(Contents);
    {error, failed_verification} ->
      false
  end.

verify_hello_box_contents(<<First:32/binary, Second:32/binary>>) ->
  Zeros = binary:copy(<<0>>, 32),
  enacl:verify_32(First, Zeros) andalso enacl:verify_32(Second, Zeros);
verify_hello_box_contents(_Contents) ->
  false.

%% - packet id (8 octets)
%% - server long nonce (16 octets) implicitly prefixed with 8 octets to form 24 octet nonce
%% - box (144 octets) that encrypts the server short-term public key (SSP) (32 octets)
%%    and the server cookie (K) (96 octets), from the server long-term public key (SLP) (32 octets) to
%%    the client short-term public key (CSP) (32 octets)
%%    Box[S', K](S -> C')
%%    - Create the box using client short-term public key and the server long-term secret key
%%    - Open the box using the server long-term public key and the client short-term secret key
encode_welcome_packet(CSP, SSP, SSS, Vault) ->
  Nonce = enacl:randombytes(16),
  NonceString = nonce_string(welcome, Nonce),
  Cookie = encode_cookie(CSP, SSS),
  PlainText = <<SSP/binary, Cookie/binary>>,
  Box = Vault:box(PlainText, NonceString, CSP),
  <<?WELCOME, Nonce/binary, Box/binary>>.

%% Cookie consists of two fields
%%  - server long nonce (16 octets) implicitly prefixed with 8 octets to form 24 octet nonce
%%  - box (80 octets) containing client short-term public key (CSP) (32 octets) and the
%%    server short-term secret key (SSS) (32 octets) encrypted to and from a secret short-term
%%    "cookie key". Box[C', s'](t)
encode_cookie(CSP, SSS) ->
  MinuteKey = ecurvecp_cookie:current_key(),
  PlainText = <<CSP/binary, SSS/binary>>,
  Nonce = enacl:randombytes(16),
  NonceString = nonce_string(minute_key, Nonce),
  Box = enacl:secretbox(PlainText, NonceString, MinuteKey),
  <<Nonce/binary, Box/binary>>.

%% Opens Box[S', K](S -> C') with (S, c')
decode_welcome_packet(Packet, SLP, CSS) ->
  #welcome_packet{nonce=Nonce, box=Box} = Packet,
  NonceString = nonce_string(welcome, Nonce),
  case enacl:box_open(Box, NonceString, SLP, CSS) of
    {ok, Contents} ->
      decode_welcome_box_contents(Contents);
    {error, failed_verification} ->
      {error, failed_to_open_cookie_box}
  end.

decode_welcome_box_contents(<<SSP:32/binary, Cookie:96/binary>>) ->
  {ok, SSP, Cookie};
decode_welcome_box_contents(_Contents) ->
  {error, invalid_welcome_box_contents}.

%% packet id - (8 octets)
%% cookie - The cookie (K) provided by the server (96 octets)
%% client short nonce - (8 octets) implicitly prefixed with 16 octets to for 24 octet nonce
%% box - (>= 144 octets) includes the client long-term public key (CLP) (32 octets),
%%  the vouch (V) (96 octets) and the metadata (>= 0 octets) encrypted from the
%%  client short-term public key (CSP) to the servers short-term public key (SSP)
%%  Box[C, V](C', S')
encode_initiate_packet(Cookie, SSP, SLP, Vault, CSP, CSS, NonceCounter) ->
  CLP = Vault:public_key(),
  Vouch = encode_vouch(CSP, SLP, SSP, Vault),
  Metadata = binary:copy(<<0>>, 64),
  PlainText = <<CLP/binary, Vouch/binary, Metadata/binary>>,
  Nonce = <<NonceCounter:64/unsigned-little-integer>>,
  NonceString = nonce_string(initiate, Nonce),
  Box = enacl:box(PlainText, NonceString, SSP, CSS),
  <<?INITIATE, Cookie/binary, Nonce/binary, Box/binary>>.

%% Vouch contains two fields
%%  - client long nonce (16 octets) implicitly prefixed with 8 octets to form 24 octet nonce
%%  - vouch box (80 octets) that encrypts the client short-term public key (CSP) (32 octets)
%%    and the server long-term public key (SLP) from the client long-term public key (CLP) to
%%    the server short-term public key (SSP).
%%    Box[C', S](C -> S')
%%    - Create using server short-term public key and client long-term secret key
%%    - Open using client long-term public key and server short-term secret key
encode_vouch(CSP, SLP, SSP, Vault) ->
  Nonce = enacl:randombytes(16),
  NonceString = nonce_string(vouch, Nonce),
  PlainText = <<CSP/binary, SLP/binary>>,
  Box = Vault:box(PlainText, NonceString, SSP),
  <<Nonce/binary, Box/binary>>.

%% Verify the cookie. Open the initiate box and verify the vouched keys.
decode_initiate_packet(Packet, CSP, Vault) ->
  #initiate_packet{cookie=Cookie, nonce=Nonce, box=Box} = Packet,
  case verify_cookie(Cookie, CSP) of
    {ok, CSP, SSS} ->
      case verify_initiate_box(Nonce, Box, CSP, SSS, Vault) of
        true ->
          {ok, CSP, SSS};
        false ->
          {error, invalid_initiate_box_contents}
      end;
    Error ->
      Error
  end.

%% Open the cookie to retrieve the boxed client short-term public key (CSP) and
%% the servers short-term secret key (SSS)
verify_cookie(<<Nonce:16/binary, Box:80/binary>>, CSP) ->
  MinuteKeys = ecurvecp_cookie:keys(),
  NonceString = nonce_string(minute_key, Nonce),
  minute_key_cookie_verify(NonceString, Box, CSP, MinuteKeys);
verify_cookie(_Cookie, _CSP) ->
  {error, invalid_cookie}.

%% Open the cookie with the current minute. If the current key doesn't work
%% use the previous. If neither work, fail.
minute_key_cookie_verify(_NonceString, _Box, _CSP, []) ->
  {error, invalid_cookie};
minute_key_cookie_verify(NonceString, Box, CSP, [Curr|Prev]) ->
  case enacl:secretbox_open(Box, NonceString, Curr) of
    {ok, <<BoxedCSP:32/binary, BoxedSSS:32/binary>>} ->
      case enacl:verify_32(BoxedCSP, CSP) of
        true ->
          {ok, CSP, BoxedSSS};
        false ->
          {error, invalid_cookie}
      end;
    {error, failed_verification} ->
      minute_key_cookie_verify(NonceString, Box, CSP, Prev)
  end.

%% Open Box[C, V](C' -> S') with (C',s'). Verify the contents of the vouch.
verify_initiate_box(Nonce, Box, CSP, SSS, Vault) ->
  NonceString = nonce_string(initiate, Nonce),
  case enacl:box_open(Box, NonceString, CSP, SSS) of
    {ok, <<CLP:32/binary, VouchNonce:16/binary, VouchBox:80/binary, _Metadata/binary>>} ->
      SLP = Vault:public_key(),
      verify_vouch(CLP, CSP, VouchNonce, VouchBox, SLP, SSS);
    {error, failed_verification} ->
      {error, invalid_initiate_box}
  end.

%% Open Vouch Box[C', S](C -> S') with (C, s') and verify the boxed client short-term public key
%% is identical the one received in the initiate box. Further verify that the boxed
%% server long-term public key is identical to the one in the vault.
verify_vouch(CLP, CSP, Nonce, Box, SLP, SSS) ->
  NonceString = nonce_string(vouch, Nonce),
  case enacl:box_open(Box, NonceString, CLP, SSS) of
    {ok, <<BoxedCSP:32/binary, BoxedSLP:32/binary>>} ->
      enacl:verify_32(BoxedCSP, CSP) andalso enacl:verify_32(BoxedSLP, SLP);
    {error, failed_verification} ->
      {error, invalid_vouch}
  end.

%% package id - (8 octets)
%% server short nonce - (8 octets) implicitly prefixed with 16 octets to form 24 octet nonce
%% box - (>= 16 octets) including any metadata encrypted from the servers short-term public key
%% to the client short-term public key. Box[M](C' -> S')
encode_ready_packet(NonceCounter, CSP, SSS) ->
  Nonce = <<NonceCounter:64/unsigned-little-integer>>,
  NonceString = nonce_string(ready, Nonce),
  PlainText = binary:copy(<<0>>, 64),
  Box = enacl:box(PlainText, NonceString, CSP, SSS),
  <<?READY, Nonce/binary, Box/binary>>.

%% Open Box[M](C' -> S') with (S', c')
decode_ready_packet(Packet, SSP, CSS) ->
  #ready_packet{nonce=Nonce, box=Box} = Packet,
  NonceString = nonce_string(ready, Nonce),
  case enacl:box_open(Box, NonceString, SSP, CSS) of
    {ok, Contents} ->
      {ok, Contents};
    {error, failed_verification} ->
      {error, invalid_ready_box}
  end.

%% Box[M](C' -> S')
%% Message data encoded from the sender's short-term key to receiver's
%% short-term key
encode_msg_packet(Msg, Side, NonceCounter, PK, SK) ->
  Nonce = <<NonceCounter:64/unsigned-little-integer>>,
  NonceString = nonce_string(Side, Nonce),
  Box = enacl:box(Msg, NonceString, PK, SK),
  <<?MESSAGE, Nonce/binary, Box/binary>>.

decode_msg_packet(Packet, Side, PK, SK) ->
  #msg_packet{nonce=Nonce, box=Box} = Packet,
  NonceString = case Side of
    server ->
      nonce_string(client, Nonce);
    client ->
      nonce_string(server, Nonce)
  end,
  enacl:box_open(Box, NonceString, PK, SK).

%% Server and Client States
waiting({accept, LSock, Timeout}, From, StateData) ->
  HandshakeTTL = 60000,
  ConnectionTTL = 360000,
  case gen_tcp:accept(LSock, Timeout) of
    {ok, Socket} ->
      ok = inet:setopts(Socket, [{active, once}]),
      {next_state, hello, StateData#st{from=From, socket=Socket,
                                       handshake_ttl=HandshakeTTL,
                                       side=server,
                                       connection_ttl=ConnectionTTL},
       HandshakeTTL};
    {error, _Reason} = Error ->
      {stop, normal, Error, StateData}
  end;
waiting({connect, Address, Port, Opts}, From, StateData) ->
  #st{nonce_counter=N} = StateData,
  DefaultOpts = [{packet, 2}, binary, {active, false}],
  TCPOpts = lists:foldl(fun(A, O) ->
          lists:keydelete(A, 1, O)
      end, DefaultOpts ++ Opts, [server_long_term_public_key, handshake_ttl]),

  SLP = proplists:get_value(server_long_term_public_key, Opts),
  HandshakeTTL = ecurvecp:get_prop_or_env(handshake_ttl, Opts, 60000),
  ConnTTL = ecurvecp:get_prop_or_env(connection_ttl, Opts, 360000),

  case gen_tcp:connect(Address, Port, TCPOpts) of
    {ok, Socket} ->
      #{public := CSP, secret := CSS} = enacl:box_keypair(),
      Packet = encode_hello_packet(SLP, CSP, CSS, N),
      case gen_tcp:send(Socket, Packet) of
        ok ->
          ok = inet:setopts(Socket, [{active, once}]),
          {next_state, welcome, StateData#st{
              from=From,
              peer={Address, Port},
              nonce_counter=N+1,
              peer_long_term_public_key=SLP,
              short_term_public_key=CSP,
              short_term_secret_key=CSS,
              socket=Socket,
              side=client,
              handshake_ttl=HandshakeTTL,
              connection_ttl=ConnTTL}, HandshakeTTL};
        {error, Reason} ->
          {stop, normal, {error, Reason}, StateData}
      end;
    {error, Reason} ->
      {stop, normal, {error, Reason}, StateData}
  end;
waiting(Msg, _From, State) ->
  ok = error_logger:info_msg("Received unmatched event ~p in state waiting.", [Msg]),
  {stop, normal, badmatch, State}.

%% From internal tcp socket
established(#msg_packet{} = Packet, StateData) ->
  #st{peer_short_term_public_key=PK, short_term_secret_key=SK,
      received_nonce_counter=RC, active=Active,
      controller={Controller, _}, side=Side} = StateData,
  case decode_msg_packet(Packet, Side, PK, SK) of
    {ok, Contents} ->
      case Active of
        once ->
          Controller ! {ecurvecp, #ecurvecp_socket{pid=self()}, Contents},
          process_recv_queue(StateData#st{buffer=Contents, active=false, received_nonce_counter=RC+1});
        true ->
          Controller ! {ecurvecp, #ecurvecp_socket{pid=self()}, Contents},
          process_recv_queue(StateData#st{buffer=Contents, received_nonce_counter=RC+1});
        false ->
          process_recv_queue(StateData#st{buffer=Contents, received_nonce_counter=RC+1})
      end;
    {error, _Reason} = Error ->
      {stop, Error, StateData}
  end;
established(_Packet, StateData) ->
  transition_close(StateData).

%% From public API
established({send, Msg}, _From, StateData) ->
  #st{socket=Socket, peer_short_term_public_key=PK,
     short_term_secret_key=SK, nonce_counter=N,
     side=Side} = StateData,
  %% Box[M](C' -> S')
  %% server short-term public key, client short-term secret-key
  %% open with client short-term public key, server short-term secret key
  Packet = encode_msg_packet(Msg, Side, N, PK, SK),
  case gen_tcp:send(Socket, Packet) of
    ok ->
      {reply, ok, established, StateData#st{nonce_counter=N+1}};
    {error, _Reason} = Error ->
      {reply, Error, established, StateData}
  end;
established(recv, From, StateData) ->
  #st{socket=Socket, recv_queue=RecvQueue} = StateData,
  ok = inet:setopts(Socket, [{active, once}]),
  {next_state, established, StateData#st{recv_queue=queue:in(From, RecvQueue)}};
established(close, _From, StateData) ->
  #st{socket=Socket} = StateData,
  ok = gen_tcp:close(Socket),
  {stop, normal, ok, StateData#st{socket=undefined}};
established(Event, _From, StateData) ->
  ok = error_logger:info_msg("Unmatched event ~p in state established", [Event]),
  {next_state, established, StateData}.

%% Server States
hello(#hello_packet{} = Packet, StateData) ->
  #st{handshake_ttl=Timeout, socket=Socket, vault=Vault, received_nonce_counter=RN} = StateData,
  case decode_hello_packet(Packet, Vault) of
    {ok, CSP} ->
      #{public := SSP, secret := SSS} = enacl:box_keypair(),
      WelcomePacket = encode_welcome_packet(CSP, SSP, SSS, Vault),
      case gen_tcp:send(Socket, WelcomePacket) of
        ok ->
          ok = inet:setopts(Socket, [{active, once}]),
          {next_state, initiate,
           StateData#st{peer_short_term_public_key=CSP,
                        received_nonce_counter=RN+1},
           Timeout};
        {error, _Reason} = Error ->
          {stop, Error, StateData}
      end;
    {error, _Reason} = Error ->
      {stop, Error, StateData}
  end;
hello(_Packet, StateData) ->
  transition_close(StateData).

initiate(#initiate_packet{} = Packet, StateData) ->
  #st{socket=Socket, peer_short_term_public_key=CSP,
      connection_ttl=Timeout, vault=Vault,
      nonce_counter=N, received_nonce_counter=RN, from=From} = StateData,
  case decode_initiate_packet(Packet, CSP, Vault) of
    {ok, CLP, SSS} ->
      ReadyPacket = encode_ready_packet(N, CSP, SSS),
      case gen_tcp:send(Socket, ReadyPacket) of
        ok ->
          _ = gen_fsm:reply(From, ok),
          {next_state, established, StateData#st{nonce_counter=N+1,
                                                 received_nonce_counter=RN+1,
                                                 from=undefined,
                                                 short_term_secret_key=SSS,
                                                 peer_long_term_public_key=CLP}, Timeout};
        {error, _Reason} ->
          transition_close(StateData)
      end;
    {error, _Error} ->
      transition_close(StateData)
  end;
initiate(timeout, StateData) ->
  transition_close(StateData);
initiate(_Packet, StateData) ->
  transition_close(StateData).

%% Client States
welcome(#welcome_packet{} = Packet, StateData) ->
  #st{handshake_ttl=HandshakeTTL, peer_long_term_public_key=SLP,
      short_term_secret_key=CSS, short_term_public_key=CSP,
      vault=Vault, socket=Socket, nonce_counter=N} = StateData,
  case decode_welcome_packet(Packet, SLP, CSS) of
    {ok, SSP, Cookie} ->
      InitiatePacket = encode_initiate_packet(Cookie, SSP, SLP, Vault, CSP, CSS, N),
      case gen_tcp:send(Socket, InitiatePacket) of
        ok ->
          ok = inet:setopts(Socket, [{active, once}]),
          {next_state, ready,
           StateData#st{peer_short_term_public_key=SSP, nonce_counter=N+1},
           HandshakeTTL};
        {error, _Error} ->
          transition_close(StateData)
      end;
    {error, _Error} ->
      transition_close(StateData)
  end;
welcome(timeout, StateData) ->
  transition_close(StateData);
welcome(_Packet, StateData) ->
  transition_close(StateData).

ready(#ready_packet{} = Packet, StateData) ->
  #st{from=From, connection_ttl=Timeout,
      received_nonce_counter=RN,
      peer_short_term_public_key=SSP,
      short_term_secret_key=CSS} = StateData,
  case decode_ready_packet(Packet, SSP, CSS) of
    {ok, _Metadata} ->
      _ = gen_fsm:reply(From, ok),
      {next_state, established,
       StateData#st{from=undefined, received_nonce_counter=RN+1},
       Timeout};
    {error, _Error} ->
      transition_close(StateData)
  end;
ready(timeout, StateData) ->
  transition_close(StateData).

handle_event(Event, StateName, StateData) ->
  ok = error_logger:info_msg("Unmatched event ~p in state ~p", [Event, StateName]),
  {next_state, StateName, StateData}.

handle_sync_event({controlling_process, Controller}, {PrevController, _}, StateName,
                  #st{controller={PrevController, MRef}} = StateData) ->
  true = erlang:demonitor(MRef, [flush]),
  NewRef = erlang:monitor(process, Controller),
  {reply, ok, StateName, StateData#st{controller={Controller, NewRef}}};
handle_sync_event({controlling_process, _Controller}, _From, StateName, StateData) ->
  {reply, {error, not_owner}, StateName, StateData};
handle_sync_event(peername, _From, StateName, StateData) ->
  #st{socket=Socket} = StateData,
  {reply, inet:peername(Socket), StateName, StateData};
handle_sync_event(sockname, _From, StateName, StateData) ->
  #st{socket=Socket} = StateData,
  {reply, inet:sockname(Socket), StateName, StateData};
handle_sync_event({shutdown, How}, _From, StateName, StateData) ->
  #st{socket=Socket} = StateData,
  {reply, gen_tcp:shutdown(Socket, How), StateName, StateData};
handle_sync_event({setopts, Opts}, _From, StateName, StateData) ->
  #st{socket=Socket} = StateData,
  case lists:keyfind(active, 1, Opts) of
    {active, Active} ->
      ok = inet:setopts(Socket, Opts),
      {reply, ok, StateName, StateData#st{active=Active}};
    false ->
      ok = inet:setopts(Socket, Opts),
      {reply, ok, StateName, StateData}
  end;
handle_sync_event(Event, _From, StateName, StateData) ->
  error_logger:info_msg("Unmatched sync_event ~p in state ~p", [Event, StateName]),
  {next_state, StateName, StateData}.

handle_info({tcp, Socket, Data}, StateName, #st{socket=Socket} = StateData) ->
  handle_tcp(Data, StateName, StateData);
handle_info({tcp_closed, Socket}, _StateName, #st{socket=Socket} = StateData) ->
  handle_tcp_closed(StateData);
handle_info({'DOWN', MRef, process, Controller, _Reason}, _StateName, #st{controller={Controller, MRef}} = StateData) ->
  {stop, normal, StateData};
handle_info(Info, StateName, StateData) ->
  error_logger:info_msg("Unmatched info ~p in state ~p", [Info, StateName]),
  {next_state, StateName, StateData}.

terminate(_Reason, _StateName, StateData) ->
  #st{socket=Socket} = StateData,
  if Socket =:= undefined ->
      ok;
    true ->
      gen_tcp:close(Socket)
  end.

code_change(_OldVsn, StateName, StateData, _Extra) ->
  {ok, StateName, StateData}.

handle_tcp(Data, StateName, StateData) ->
  case parse_packet(Data) of
    {ok, Packet} ->
      case verify_nonce_count(Packet, StateData) of
        true ->
          ?MODULE:StateName(Packet, StateData);
        false ->
          transition_close(StateData)
      end;
    {error, _Reason} ->
      transition_close(StateData)
  end.

handle_tcp_closed(StateData) ->
  {stop, normal, StateData#st{socket=undefined}}.

transition_close(StateData) ->
  #st{socket=Socket, active=Active, controller={Controller, _}} = StateData,
  ok = gen_tcp:close(Socket),
  _ = [Controller ! {ecurvecp_closed, #ecurvecp_socket{pid=self()}} || Active],
  {stop, normal, StateData#st{socket=undefined}}.

start_fsm() ->
  Controller = self(),
  ecurvecp_connection_sup:start_child([Controller]).

process_recv_queue(StateData) ->
  #st{recv_queue=Queue, buffer=Buffer, socket=Socket} = StateData,
  case {queue:out(Queue), Buffer} of
    {{{value, _Receiver}, _NewQueue}, undefined} ->
      ok = inet:setopts(Socket, [{active, once}]),
      {next_state, established, StateData};
    {{{value, Receiver}, NewQueue}, Msg} ->
      _ = gen_fsm:reply(Receiver, {ok, Msg}),
      process_recv_queue(StateData#st{recv_queue=NewQueue, buffer=undefined});
    {{empty, _}, _} ->
      {next_state, established, StateData}
  end.

verify_nonce_count(#hello_packet{nonce=N}, #st{received_nonce_counter=RC}) ->
  N > RC;
verify_nonce_count(#initiate_packet{nonce=N}, #st{received_nonce_counter=RC}) ->
  N > RC;
verify_nonce_count(#msg_packet{nonce=N}, #st{received_nonce_counter=RC}) ->
  N > RC.

nonce_string(hello, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-H", Nonce/binary>>;
nonce_string(welcome, <<_:16/binary>> = Nonce) ->
  <<"CurveCPK", Nonce/binary>>;
nonce_string(vouch, <<_:16/binary>> = Nonce) ->
  <<"CurveCPV", Nonce/binary>>;
nonce_string(initiate, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-I", Nonce/binary>>;
nonce_string(server, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-server-M", Nonce/binary>>;
nonce_string(client, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-client-M", Nonce/binary>>;
nonce_string(minute_key, <<_:16/binary>> = Nonce) ->
  <<"minute-k", Nonce/binary>>;
nonce_string(ready, <<_:8/binary>> = Nonce) ->
  <<"CurveCP-server-R", Nonce/binary>>.
