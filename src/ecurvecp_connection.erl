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
-define(VERSION, <<?MAJOR_V/integer, ?MINOR_V/integer>>).
-define(COUNT_LIMIT, 18446744073709551616 - 1).

-export([messages/0,
         accept/2,
         listen/1,
         connect/4,
         recv/2,
         send/2,
         controlling_process/2,
         close/1,
         shutdown/2,
         setopts/2,
         peername/1,
         sockname/1
      ]).

-export([start_link/1,
         init/1,
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
-export([encode_msg_packet/4]).
-export([decode_msg_packet/3]).

-record(hello_packet, {
    version                       :: <<_:16>>,
    client_short_term_public_key  :: key(),
    nonce                         :: short_nonce(),
    box                           :: <<_:640>>
  }).

-record(welcome_packet, {
    nonce :: long_nonce(),
    box   :: <<_:1152>>
  }).

-record(initiate_packet, {
    cookie  :: cookie(),
    nonce   :: short_nonce(),
    box     :: binary()
  }).

-record(ready_packet, {
    nonce :: short_nonce(),
    box   :: binary()
  }).

-record(msg_packet, {
    nonce :: short_nonce(),
    box   :: binary()
  }).

-record(error_packet, {
    reason  :: iodata()
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
    shared_key                    :: key(),
    nonce_counter                 :: non_neg_integer(),
    received_nonce_counter        :: non_neg_integer(),
    buffer                        :: iodata(),
    recv_queue                    :: queue:queue(pid()),
    negotiated_version            :: version(),
    active                        :: boolean() | once,
    side                          :: side()
  }).

-type version()           :: {pos_integer(), pos_integer()}.
-type from()              :: {pid(), reference()}.
-type key()               :: <<_:256>>.
-type short_nonce()       :: <<_:64>>.
-type long_nonce()        :: <<_:128>>.
-type cookie()            :: <<_:768>>.
-type nonce()             :: short_nonce() | long_nonce().
-type nonce_key()         :: hello | welcome | initiate | ready | server
  | client | vouch | minute_key.
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
-type side()              :: client | server.
-type ecurvecp_packet()   :: hello_packet() | welcome_packet()
  | initiate_packet() | ready_packet() | msg_packet().
-type state_data()        :: #st{}.

-spec messages() -> {atom(), atom(), atom()}.
messages() ->
  {ecurvecp, ecurvecp_closed, ecurvecp_error}.

-spec setopts(socket(), opts()) -> ok.
setopts(Socket, Opts) ->
  #ecurvecp_socket{pid=Pid} = Socket,
  gen_fsm:sync_send_all_state_event(Pid, {setopts, Opts}).

-spec peername(socket()) -> {ok, {address(), inet:port_number()}}.
peername(#ecurvecp_lsock{lsock=Socket}) ->
  inet:peername(Socket);
peername(#ecurvecp_socket{pid=Pid}) ->
  gen_fsm:sync_send_all_state_event(Pid, peername).

-spec sockname(socket()) -> {ok, {address(), inet:port_number()}}.
sockname(#ecurvecp_lsock{lsock=Socket}) ->
  inet:sockname(Socket);
sockname(#ecurvecp_socket{pid=Pid}) ->
  gen_fsm:sync_send_all_state_event(Pid, sockname).

-spec shutdown(socket(), read | write | read_write) -> ok.
shutdown(Socket, How) ->
  #ecurvecp_socket{pid=Pid} = Socket,
  gen_fsm:sync_send_all_state_event(Pid, {shutdown, How}).

-spec start_link(pid()) -> {ok, pid()}.
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
              nonce_counter=1,
              received_nonce_counter=0,
              vault=ecurvecp_vault,
              active=false,
              handshake_ttl=60000,
              connection_ttl=360000,
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

-spec encode_hello_packet(key(), key(), key(), pos_integer()) -> binary().
encode_hello_packet(SLP, CSP, CSS, NonceCounter) ->
  Z = binary:copy(<<0>>, 64),
  Nonce = <<NonceCounter:64/unsigned-little-integer>>,
  NonceString = nonce_string(hello, Nonce),
  Box = enacl:box(Z, NonceString, SLP, CSS),
  <<?HELLO, ?VERSION/binary, Z/binary, CSP/binary, Nonce/binary, Box/binary>>.

-spec decode_hello_packet(hello_packet(), module())
  -> {ok, key(), version()} | {error, invalid_hello_box}.
decode_hello_packet(Hello, Vault) ->
  #hello_packet{nonce=Nonce, box=Box, version=V,
                client_short_term_public_key=CSP} = Hello,
  case verify_version(V) of
    {ok, Version} ->
      case verify_hello_packet_box(Nonce, Box, CSP, Vault) of
        true ->
          {ok, CSP, Version};
        false ->
          {error, invalid_hello_box}
      end;
    Error ->
      Error
  end.

-spec verify_version(binary())
  -> {ok, version()}
  | {error, {version_mismatch, version()} | invalid_version_format}.
verify_version(<<?MAJOR_V/integer, Minor/integer>>) ->
  {ok, {?MAJOR_V, Minor}};
verify_version(<<Major/integer, Minor/integer>>) ->
  {error, {version_mismatch, {Major, Minor}}};
verify_version(_Version) ->
  {error, invalid_version_format}.

-spec verify_hello_packet_box(short_nonce(), binary(), key(), module())
  -> boolean().
verify_hello_packet_box(Nonce, Box, CSP, Vault) ->
  NonceString = nonce_string(hello, Nonce),
  case Vault:box_open(Box, NonceString, CSP) of
    {ok, Contents} ->
      verify_hello_box_contents(Contents);
    {error, failed_verification} ->
      false
  end.

-spec verify_hello_box_contents(binary()) -> boolean().
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
-spec encode_welcome_packet(key(), key(), key(), module()) -> binary().
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
-spec encode_cookie(key(), key()) -> cookie().
encode_cookie(CSP, SSS) ->
  MinuteKey = ecurvecp_cookie:current_key(),
  PlainText = <<CSP/binary, SSS/binary>>,
  Nonce = enacl:randombytes(16),
  NonceString = nonce_string(minute_key, Nonce),
  Box = enacl:secretbox(PlainText, NonceString, MinuteKey),
  <<Nonce/binary, Box/binary>>.

%% Opens Box[S', K](S -> C') with (S, c')
-spec decode_welcome_packet(welcome_packet(), key(), key())
  -> {ok, key(), cookie()}
  | {error, failed_to_open_cookie_box | invalid_welcome_box_contents}.
decode_welcome_packet(Packet, SLP, CSS) ->
  #welcome_packet{nonce=Nonce, box=Box} = Packet,
  NonceString = nonce_string(welcome, Nonce),
  case enacl:box_open(Box, NonceString, SLP, CSS) of
    {ok, Contents} ->
      decode_welcome_box_contents(Contents);
    {error, failed_verification} ->
      {error, failed_to_open_cookie_box}
  end.

-spec decode_welcome_box_contents(binary())
  -> {ok, key(), cookie()} | {error, invalid_welcome_box_contents}.
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
-spec encode_initiate_packet(cookie(), key(), key(), module(), key(), key(), pos_integer())
  -> binary().
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
-spec encode_vouch(key(), key(), key(), module()) -> binary().
encode_vouch(CSP, SLP, SSP, Vault) ->
  Nonce = enacl:randombytes(16),
  NonceString = nonce_string(vouch, Nonce),
  PlainText = <<CSP/binary, SLP/binary>>,
  Box = Vault:box(PlainText, NonceString, SSP),
  <<Nonce/binary, Box/binary>>.

%% Verify the cookie. Open the initiate box and verify the vouched keys.
-spec decode_initiate_packet(initiate_packet(), key(), module())
  -> {ok, <<_:256>>} | {error, invalid_initiate_box_contents}.
decode_initiate_packet(Packet, CSP, Vault) ->
  #initiate_packet{cookie=Cookie, nonce=Nonce, box=Box} = Packet,
  case verify_cookie(Cookie, CSP) of
    {ok, SSS} ->
      case verify_initiate_box(Nonce, Box, CSP, SSS, Vault) of
        true ->
          {ok, SSS};
        false ->
          {error, invalid_initiate_box_contents}
      end;
    Error ->
      Error
  end.

%% Open the cookie to retrieve the boxed client short-term public key (CSP) and
%% the servers short-term secret key (SSS)
-spec verify_cookie(binary(), key())
  -> {ok, <<_:256>>} | {error, invalid_cookie}.
verify_cookie(<<Nonce:16/binary, Box:80/binary>>, CSP) ->
  MinuteKeys = ecurvecp_cookie:keys(),
  NonceString = nonce_string(minute_key, Nonce),
  minute_key_cookie_verify(NonceString, Box, CSP, MinuteKeys);
verify_cookie(_Cookie, _CSP) ->
  {error, invalid_cookie}.

%% Open the cookie with the current minute. If the current key doesn't work
%% use the previous. If neither work, fail.
-spec minute_key_cookie_verify(<<_:192>>, binary(), key(), [key()])
  -> {ok, <<_:256>>} | {error, invalid_cookie}.
minute_key_cookie_verify(_NonceString, _Box, _CSP, []) ->
  {error, invalid_cookie};
minute_key_cookie_verify(NonceString, Box, CSP, [Curr|Prev]) ->
  case enacl:secretbox_open(Box, NonceString, Curr) of
    {ok, Contents} ->
      verify_cookie_box_contents(Contents, CSP);
    {error, failed_verification} ->
      minute_key_cookie_verify(NonceString, Box, CSP, Prev)
  end.

-spec verify_cookie_box_contents(binary(), key())
  -> {ok, <<_:256>>} | {error, invalid_cookie}.
verify_cookie_box_contents(<<BoxedCSP:32/binary, BoxedSSS:32/binary>>, CSP) ->
  case enacl:verify_32(BoxedCSP, CSP) of
    true ->
      {ok, BoxedSSS};
    false ->
      {error, invalid_cookie}
  end;
verify_cookie_box_contents(_Contents, _CSP) ->
  {error, invalid_cookie}.

%% Open Box[C, V](C' -> S') with (C',s'). Verify the contents of the vouch.
-spec verify_initiate_box(short_nonce(), binary(), key(), key(), module())
  -> boolean() | {error, invalid_initiate_box | invalid_vouch}.
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
-spec verify_vouch(key(), key(), long_nonce(), binary(), key(), key())
  -> boolean().
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
-spec encode_ready_packet(pos_integer(), key(), key()) -> binary().
encode_ready_packet(NonceCounter, CSP, SSS) ->
  Nonce = <<NonceCounter:64/unsigned-little-integer>>,
  NonceString = nonce_string(ready, Nonce),
  PlainText = binary:copy(<<0>>, 64),
  Box = enacl:box(PlainText, NonceString, CSP, SSS),
  <<?READY, Nonce/binary, Box/binary>>.

%% Open Box[M](C' -> S') with (S', c')
-spec decode_ready_packet(ready_packet(), key(), key())
  -> {ok, binary()} | {error, invalid_ready_box}.
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
-spec encode_msg_packet(binary(), side(), pos_integer(), key()) -> binary().
encode_msg_packet(Msg, Side, NonceCounter, Key) ->
  Nonce = <<NonceCounter:64/unsigned-little-integer>>,
  NonceString = nonce_string(Side, Nonce),
  Box = enacl:box_afternm(Msg, NonceString, Key),
  <<?MESSAGE, Nonce/binary, Box/binary>>.

-spec decode_msg_packet(msg_packet(), side(), key())
  -> {ok, binary()} | {error, failed_verification}.
decode_msg_packet(Packet, Side, Key) ->
  #msg_packet{nonce=Nonce, box=Box} = Packet,
  NonceString = case Side of
    server ->
      nonce_string(client, Nonce);
    client ->
      nonce_string(server, Nonce)
  end,
  enacl:box_open_afternm(Box, NonceString, Key).

%% Server and Client States
waiting({accept, LSock, Timeout}, From, StateData) ->
  #st{handshake_ttl=HandshakeTTL} = StateData,
  case gen_tcp:accept(LSock, Timeout) of
    {ok, Socket} ->
      {ok, Peer} = inet:peername(Socket),
      ok = inet:setopts(Socket, [{active, once}]),
      {next_state, hello, StateData#st{from=From, socket=Socket,
                                       peer=Peer,
                                       side=server},
       HandshakeTTL};
    {error, _Reason} = Error ->
      {stop, normal, Error, StateData}
  end;
waiting({connect, Address, Port, Opts}, From, StateData) ->
  #st{nonce_counter=N} = StateData,
  DefaultOpts = [{packet, 2}, binary, {active, false}],
  TCPOpts = lists:foldl(fun(A, O) ->
          lists:keydelete(A, 1, O)
      end, DefaultOpts ++ Opts, [peer_long_term_public_key, handshake_ttl, connection_ttl]),

  SLP = proplists:get_value(peer_long_term_public_key, Opts),
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
  ok = error_logger:warning_msg("Received unmatched event ~p in state waiting.", [Msg]),
  {next_state, waiting, State}.

%% From internal tcp socket
established(#msg_packet{} = Packet, StateData) ->
  #st{shared_key=Key,
      received_nonce_counter=RC, active=Active,
      controller={Controller, _}, side=Side} = StateData,
  case decode_msg_packet(Packet, Side, Key) of
    {ok, Contents} ->
      case Active of
        once ->
          Controller ! {ecurvecp, #ecurvecp_socket{pid=self()}, Contents},
          {next_state, established, StateData#st{active=false, received_nonce_counter=RC+1}};
        true ->
          Controller ! {ecurvecp, #ecurvecp_socket{pid=self()}, Contents},
          {next_state, established, StateData#st{received_nonce_counter=RC+1}};
        false ->
          process_recv_queue(StateData#st{buffer=Contents, received_nonce_counter=RC+1})
      end;
    {error, _Reason} = Error ->
      {stop, Error, StateData}
  end;
established(timeout, StateData) ->
  transition_close(handshake_timeout, StateData).

%% From public API
established({send, Msg}, _From, StateData) ->
  #st{socket=Socket, shared_key=Key, nonce_counter=N,
     side=Side} = StateData,
  Packet = encode_msg_packet(Msg, Side, N, Key),
  case gen_tcp:send(Socket, Packet) of
    ok ->
      {reply, ok, established, StateData#st{nonce_counter=N+1}};
    {error, _Reason} = Error ->
      {stop, normal, Error, StateData}
  end;
established(recv, From, StateData) ->
  #st{socket=Socket, recv_queue=RecvQueue} = StateData,
  ok = inet:setopts(Socket, [{active, once}]),
  {next_state, established, StateData#st{recv_queue=queue:in(From, RecvQueue)}};
established(close, _From, StateData) ->
  #st{socket=Socket} = StateData,
  ok = gen_tcp:close(Socket),
  {stop, normal, ok, StateData#st{socket=undefined}}.

%% Server States
hello(#hello_packet{} = Packet, StateData) ->
  #st{handshake_ttl=Timeout, socket=Socket, vault=Vault, received_nonce_counter=RN} = StateData,
  case decode_hello_packet(Packet, Vault) of
    {ok, CSP, Version} ->
      #{public := SSP, secret := SSS} = enacl:box_keypair(),
      WelcomePacket = encode_welcome_packet(CSP, SSP, SSS, Vault),
      case gen_tcp:send(Socket, WelcomePacket) of
        ok ->
          ok = inet:setopts(Socket, [{active, once}]),
          {next_state, initiate,
           StateData#st{peer_short_term_public_key=CSP,
                        negotiated_version=Version,
                        received_nonce_counter=RN+1},
           Timeout};
        {error, _Reason} = Error ->
          transition_close(Error, StateData)
      end;
    {error, _Reason} = Error ->
      ok = error_logger:info_msg("decode failure ~p\n", [Error]),
      transition_close(Error, StateData)
  end;
hello(timeout, StateData) ->
  transition_close(handshake_timeout, StateData).

initiate(#initiate_packet{} = Packet, StateData) ->
  #st{socket=Socket, peer_short_term_public_key=CSP,
      connection_ttl=Timeout, vault=Vault,
      nonce_counter=N, received_nonce_counter=RN, from=From} = StateData,
  case decode_initiate_packet(Packet, CSP, Vault) of
    {ok, SSS} ->
      ReadyPacket = encode_ready_packet(N, CSP, SSS),
      case gen_tcp:send(Socket, ReadyPacket) of
        ok ->
          SharedKey = enacl:box_beforenm(CSP, SSS),
          _ = gen_fsm:reply(From, ok),
          {next_state, established, StateData#st{nonce_counter=N+1,
                                                 received_nonce_counter=RN+1,
                                                 from=undefined,
                                                 shared_key=SharedKey,
                                                 short_term_secret_key=SSS},
           Timeout};
        {error, _Reason} = Error ->
          transition_close(Error, StateData)
      end;
    {error, _Reason} = Error ->
      transition_close(Error, StateData)
  end;
initiate(timeout, StateData) ->
  transition_close(handshake_timeout, StateData).

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
  transition_close(handshake_timeout, StateData).

ready(#ready_packet{} = Packet, StateData) ->
  #st{from=From, connection_ttl=Timeout,
      received_nonce_counter=RN,
      peer_short_term_public_key=SSP,
      short_term_secret_key=CSS} = StateData,
  case decode_ready_packet(Packet, SSP, CSS) of
    {ok, _Metadata} ->
      SharedKey = enacl:box_beforenm(SSP, CSS),
      _ = gen_fsm:reply(From, ok),
      {next_state, established,
       StateData#st{from=undefined, shared_key=SharedKey,
                    received_nonce_counter=RN+1},
       Timeout};
    {error, _Error} ->
      transition_close(StateData)
  end;
ready(timeout, StateData) ->
  transition_close(handshake_timeout, StateData).

handle_event(Event, StateName, StateData) ->
  ok = error_logger:warning_msg("Unmatched event ~p in state ~p", [Event, StateName]),
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
  error_logger:warning_msg("Unmatched sync_event ~p in state ~p", [Event, StateName]),
  {next_state, StateName, StateData}.

handle_info({tcp, Socket, Data}, StateName, #st{socket=Socket} = StateData) ->
  handle_tcp(Data, StateName, StateData);
handle_info({tcp_closed, Socket}, _StateName, #st{socket=Socket} = StateData) ->
  handle_tcp_closed(StateData);
handle_info({'DOWN', MRef, process, Controller, _Reason}, _StateName, #st{controller={Controller, MRef}} = StateData) ->
  {stop, normal, StateData};
handle_info(Info, StateName, StateData) ->
  error_logger:warning_msg("Unmatched info ~p in state ~p", [Info, StateName]),
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

-spec handle_tcp(iodata(), atom(), state_data())
  -> {next_state, atom(), state_data()}
  | {stop, atom(), term(), state_data()}.
handle_tcp(Data, StateName, StateData) ->
  case parse_packet(Data) of
    {ok, Packet} ->
      case verify_nonce_count(Packet, StateData) of
        true ->
          ?MODULE:StateName(Packet, StateData);
        false ->
          ok = error_logger:info_msg("invalid nonce count ~p~n", [Packet]),
          transition_close(StateData)
      end;
    {error, _Reason} ->
      ok = error_logger:info_msg("Failed to parse packet ~p~n", [Data]),
      transition_close(StateData)
  end.

-spec handle_tcp_closed(state_data()) -> {stop, normal, state_data()}.
handle_tcp_closed(StateData) ->
  transition_close(StateData).

-spec transition_close(state_data()) -> {stop, atom(), state_data()}.
transition_close(StateData) ->
  transition_close(normal, StateData).

-spec transition_close(atom(), state_data()) -> {stop, atom(), state_data()}.
transition_close(Reason, StateData) ->
  #st{socket=Socket, active=Active, controller={Controller, _}, from=From} = StateData,
  ok = gen_tcp:close(Socket),
  ok = case {Active, From} of
    {A, undefined} when A == true; A == once ->
      Controller ! {ecurvecp_closed, #ecurvecp_socket{pid=self()}},
      ok;
    _ ->
      ok
  end,
  ok = if From /= undefined ->
      _ = gen_fsm:reply(From, {error, closed}),
      ok;
    true ->
      ok
  end,
  {stop, Reason, StateData#st{socket=undefined, from=undefined}}.

-spec start_fsm() -> {ok, pid()}.
start_fsm() ->
  Controller = self(),
  ecurvecp_connection_sup:start_child([Controller]).

-spec process_recv_queue(state_data())
  -> {next_state, established, state_data(), timeout()}.
process_recv_queue(StateData) ->
  #st{recv_queue=Queue, buffer=Buffer, socket=Socket,
      connection_ttl=Timeout} = StateData,
  case {queue:out(Queue), Buffer} of
    {{{value, _Receiver}, _NewQueue}, undefined} ->
      ok = inet:setopts(Socket, [{active, once}]),
      {next_state, established, StateData, Timeout};
    {{{value, Receiver}, NewQueue}, Msg} ->
      _ = gen_fsm:reply(Receiver, {ok, Msg}),
      process_recv_queue(StateData#st{recv_queue=NewQueue, buffer=undefined});
    {{empty, _}, _} ->
      {next_state, established, StateData, Timeout}
  end.

-spec verify_nonce_count(ecurvecp_packet() | short_nonce(), state_data() | integer()) -> boolean().
verify_nonce_count(#hello_packet{nonce=N}, #st{received_nonce_counter=RC}) ->
  verify_nonce_bounds(N, RC);
verify_nonce_count(#initiate_packet{nonce=N}, #st{received_nonce_counter=RC}) ->
  verify_nonce_bounds(N, RC);
verify_nonce_count(#msg_packet{nonce=N}, #st{received_nonce_counter=RC}) ->
  verify_nonce_bounds(N, RC);
verify_nonce_count(_Packet, _StateData) ->
  true.

-spec verify_nonce_bounds(<<_:64>>, pos_integer()) -> boolean().
verify_nonce_bounds(<<N:64/unsigned-little-integer>>, RC) when is_integer(RC) ->
  N > RC andalso N =< ?COUNT_LIMIT.

-spec nonce_string(nonce_key(), nonce()) -> <<_:192>>.
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
