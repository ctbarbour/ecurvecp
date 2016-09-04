-module(ecurvecp_connection_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-behavior(proper_fsm).
-compile(export_all).

-define(IP, {127,0,0,1}).
-define(PORT, 1337).

-record(st, {
    c,
    rc,
    short_term_keypair,
    long_term_keypair,
    peer_long_term_pk,
    peer_short_term_pk,
    cookie,
    acceptor
  }).

server_handshake_test_() ->
   {timeout, 60,
    {setup,
      fun setup/0,
      fun cleanup/1,
      fun(_) -> [?_assert(check())] end}
   }.

setup() ->
  ok = error_logger:tty(false),
  application:start(ecurvecp).

cleanup(_) ->
  application:stop(ecurvecp).

check() ->
  proper:quickcheck(prop_server_handshake(), [{numtests, 200}, {start_size, 5}, {to_file, user}]).

initial_state() ->
  closed.

initial_state_data() ->
  #st{c=1, rc=0, short_term_keypair=g_keypair(), long_term_keypair=g_keypair(), peer_long_term_pk=ecurvecp_vault:public_key()}.

closed(_S) ->
  [{hello, {call, ?MODULE, connect, [{var, listener}, {var, sender}, {var, ip}, {var, port}]}}].

hello(S) ->
  [{initiate, {call, ?MODULE, send_hello_good, [{var, sender}, g_hello_good(S)]}},
   {closed, {call, ?MODULE, send_hello_bad, [{var, sender}, g_hello_bad(S)]}}].

initiate(S) ->
  [{established, {call, ?MODULE, send_initiate_good, [{var, sender}, g_initiate_good(S)]}}].

established(S) ->
  [{established, {call, ?MODULE, send_msg, [{var, sender}, binary(), S#st.c, S#st.peer_short_term_pk, S#st.short_term_keypair]}}].

next_state_data(closed, hello, S, Acceptor, {call, ?MODULE, connect, _}) ->
  S#st{acceptor=Acceptor};
next_state_data(hello, initiate, S, Welcome, {call, ?MODULE, send_hello_good, [_Sender, _Hello]}) ->
  PeerShortTermPK = {'call', ?MODULE, peer_short_term_pk, [Welcome, S#st.peer_long_term_pk, S#st.short_term_keypair]},
  Cookie = {'call', ?MODULE, extract_cookie, [Welcome, S#st.peer_long_term_pk, S#st.short_term_keypair]},
  S#st{c=S#st.c+1, peer_short_term_pk=PeerShortTermPK, cookie=Cookie};
next_state_data(initiate, established, S, _Ready, {call, ?MODULE, send_initiate_good, _}) ->
  S#st{c=S#st.c+1, rc=S#st.rc+1};
next_state_data(established, established, S, _Reply, {call, _, _, _}) ->
  S#st{c=S#st.c+1, rc=S#st.rc+1};
next_state_data(_, closed, S, _R, _C) ->
  S#st{acceptor=undefined, c=1, rc=0}.

precondition(_From, _To, _S, {call, _, _, _}) ->
  true.

postcondition(closed, hello, _S, {call, ?MODULE, connect, _}, _R) ->
  true;
postcondition(hello, initiate, S, {call, ?MODULE, send_hello_good, [_Sender, _Hello]}, Welcome) ->
  case decode_welcome(Welcome, S#st.peer_long_term_pk, S#st.short_term_keypair) of
    {ok, _, _} ->
      true;
    _Other ->
      false
  end;
postcondition(hello, closed, _S, {call, ?MODULE, send_hello_bad, [_Sender, _BadHello]}, {error, closed}) ->
  true;
postcondition(hello, closed, _S, {call, ?MODULE, send_hello_bad, [_Sender, _BadHello]}, _R) ->
  false;
postcondition(initiate, established, S, {call, ?MODULE, send_initiate_good, [_Sender, _Initiate]}, Ready) ->
  case decode_ready(Ready, S) of
    {ok, N, _} ->
      N > S#st.rc;
    {error, _} ->
      false
  end;
postcondition(initiate, closed, _S, {call, ?MODULE, send_initiate_bad, [_Sender, _Initiate]}, {error, closed}) ->
  true;
postcondition(initiate, closed, _S, {call, ?MODULE, send_initiate_bad, [_Sender, _Initiate]}, _R) ->
  false;
postcondition(initiate, established, S, {call, ?MODULE, send_initiate, [_, ShortKey, _LongKey, PeerPK, _NC, Welcome]}, Ready) ->
  {_, SK} = ShortKey,
  case decode_welcome(Welcome, PeerPK, SK) of
    {ok, SSP, _Cookie} ->
      case decode_ready(Ready, SSP, SK) of
        {ok, N, _} ->
          N > S#st.rc;
        {error, _} ->
          false
      end;
    _ ->
      false
  end;
postcondition(established, established, S, {call, ?MODULE, send_msg, [_, _, _, PK, ShortKey]}, Data) ->
  {_, SK} = ShortKey,
  case decode_msg(Data, PK, SK) of
    {ok, N, _} ->
      N > S#st.rc;
    {error, _} ->
      false
  end.

g_initial_state() ->
  {initial_state(), initial_state_data()}.

g_padding_good() ->
  g_padding(64).

g_padding_bad() ->
  ?SIZED(S, g_padding(S)).

g_padding(S) ->
  ?LET(Pad, vector(S, <<0>>), list_to_binary(Pad)).

g_hello_prefix_good() ->
  exactly(<<"QvnQ5XlH">>).

g_hello_prefix_bad() ->
  binary(8).

g_version_good() ->
  exactly(<<1/integer, 0/integer>>).

g_version_bad() ->
  ?LET({Major, Minor}, {integer(), integer()}, <<Major/integer, Minor/integer>>).

g_hello_nonce_string(Nonce) ->
  <<"CurveCP-client-H", Nonce/binary>>.

g_short_nonce_good(NC) ->
  <<NC:64/unsigned-little-integer>>.

g_short_nonce_bad(NC) ->
  ?LET({Type, C},
       {oneof([little, big]), ?SUCHTHAT(N, integer(0, inf), N /= NC)},
       begin
         case Type of
           little ->
             <<C:64/unsigned-little-integer>>;
           big ->
             <<C:64/unsigned-big-integer>>
         end
      end).

g_hello_good(#st{short_term_keypair={PK, SK}, peer_long_term_pk=PeerPK, c=NC}) ->
  ?LET({Prefix, Version, Zeros, Nonce},
       {g_hello_prefix_good(), g_version_good(), g_padding_good(), g_short_nonce_good(NC)},
       begin
          ?LET(NString, g_hello_nonce_string(Nonce),
               begin
                 Box = enacl:box(Zeros, NString, PeerPK, SK),
                 <<Prefix/binary, Version/binary, Zeros/binary, PK/binary, Nonce/binary, Box/binary>>
               end)
       end).

g_initiate_good(#st{short_term_keypair={SP, SS}, long_term_keypair={LP, LS}, peer_long_term_pk=PeerPK, peer_short_term_pk=SSP, cookie=Cookie, c=NC}) ->
  ?LET({Prefix, Kookie, Nonce, Vouch},
       {g_initiate_prefix_good(), exactly(Cookie), g_short_nonce_good(NC), g_vouch_good(SP, PeerPK, SSP, LS)},
       begin
         ?LET(NString, g_initiate_nonce_string_good(Nonce),
              begin
                ?debugFmt("Cookie: ~p\n", [Cookie]),
                Box = enacl:box(<<LP/binary, Vouch/binary, 0/integer>>, NString, SSP, SS),
                <<Prefix/binary, Kookie/binary, Nonce/binary, Box/binary>>
              end)
    end).

g_initiate_bad(_S) ->
  exactly(<<"badInitiate">>).

g_initiate_prefix_good() ->
  exactly(<<"QvnQ5XlI">>).

g_vouch_good(SP, PeerPK, SSP, LS) ->
  ?LET(Nonce, binary(16),
       begin
         ?LET(NString, g_vouch_nonce_string_good(Nonce),
              begin
                ?debugFmt("SSP: ~p\n", [SSP]),
                ?debugFmt("SSP eval: ~p\n", [eval(SSP)]),
                Box = enacl:box(<<SP/binary, PeerPK/binary>>, NString, SSP, LS),
                <<Nonce/binary, Box/binary>>
              end)
    end).

g_vouch_nonce_string_good(Nonce) ->
  exactly(<<"CurveCPV", Nonce/binary>>).

g_vouch_nonce_string_bad(Nonce) ->
  ?LET(Prefix,
       ?SUCHTHAT(P, binary(8) P /= <<"CurveCPV">>),
       <<Prefix/binary, Nonce/binary>>).

g_initiate_nonce_string_good(Nonce) ->
  exactly(<<"CurveCP-client-I", Nonce/binary>>).

g_initiate_nonce_string_bad(Nonce) ->
  ?LET(Prefix,
       ?SUCHTHAT(P, binary(16) P /= <<"CurveCP-client-I">>),
       <<Prefix/binary, Nonce/binary>>).

g_hello_bad(#st{short_term_keypair={PK, SK}, peer_long_term_pk=PeerPK, c=NC}) ->
  ?LET({Prefix, Version, Padding, Nonce},
       {g_hello_prefix_bad(), g_version_bad(), g_padding_bad(), g_short_nonce_bad(NC)},
       begin
         ?LET(NString, g_hello_nonce_string(Nonce),
              begin
                Box = enacl:box(Padding, NString, PeerPK, SK),
                <<Prefix/binary, Version/binary, Padding/binary, PK/binary, Nonce/binary, Box/binary>>
              end)
       end).

g_keypair() ->
  #{public := PK, secret := SK} = enacl:box_keypair(),
  {PK, SK}.

send_hello_good(Sender, Hello) ->
  do_send(Sender, Hello).

send_hello_bad(Sender, BadHello) ->
  do_send(Sender, BadHello).

send_initiate_good(Sender, Initiate) ->
  do_send(Sender, Initiate).

send_initiate_bad(Sender, BadInitiate) ->
  do_send(Sender, BadInitiate).

send_initiate(Sender, ShortKey, LongKey, PeerPK, NC, Welcome) ->
  {LP, LS} = LongKey,
  {SP, SS} = ShortKey,
  case Welcome of
    <<"RL3aNMXK", Nonce:16/binary, Box:144/binary>> ->
      NString = <<"CurveCPK", Nonce/binary>>,
      case enacl:box_open(Box, NString, PeerPK, SS) of
        {ok, <<SSP:32/binary, Cookie:96/binary>>} ->
          INonce = <<NC:64/unsigned-little-integer>>,
          INString = <<"CurveCP-client-I", INonce/binary>>,
          VNonce = enacl:randombytes(16),
          VNString = <<"CurveCPV", VNonce/binary>>,
          VPlaintext = <<SP/binary, PeerPK/binary>>,
          VBox = enacl:box(VPlaintext, VNString, SSP, LS),
          Vouch = <<VNonce/binary, VBox/binary>>,
          IPlaintext = <<LP/binary, Vouch/binary, 0/integer>>,
          IBox = enacl:box(IPlaintext, INString, SSP, SS),
          IPacket = <<"QvnQ5XlI", Cookie/binary, INonce/binary, IBox/binary>>,
          do_send(Sender, IPacket);
        {error, failed_verification} ->
          false
      end;
    _ ->
      false
  end.

send_msg(Sender, Msg, NC, PK, Keypair) ->
  {_, SK} = Keypair,
  Nonce = <<NC:64/unsigned-little-integer>>,
  NString = <<"CurveCP-client-M", Nonce/binary>>,
  Box = enacl:box(Msg, NString, PK, SK),
  Packet = <<"RL3aNMXM", Nonce/binary, Box/binary>>,
  do_send(Sender, Packet).

connect(Listener, Sender, Ip, Port) ->
  {ok, Acceptor} = simple_listener:acceptor(Listener),
  ok = simple_sender:connect(Sender, Ip, Port),
  Acceptor.

do_send(Sender, Packet) ->
  ok = simple_sender:send(Sender, Packet),
  simple_sender:recv(Sender).

prop_server_handshake() ->
  {ok, Listener} = simple_listener:start(?IP, ?PORT),
  ?FORALL(State, g_initial_state(),
    ?FORALL(Cmds, proper_fsm:commands(?MODULE, State),
      ?TRAPEXIT(
        begin
          {ok, Sender} = simple_sender:start(),
          {H, S, Res} = proper_fsm:run_commands(?MODULE, Cmds, [{ip, ?IP}, {port, ?PORT}, {sender, Sender}, {listener, Listener}]),
          ok = simple_sender:close(Sender),
          ?WHENFAIL(
            io:format("History: ~p\nState: ~p\nResult: ~p\n", [H, S, Res]),
                      aggregate(zip(proper_fsm:state_names(H), command_names(Cmds)),
                      Res == ok))
        end))).

decode_welcome(Welcome, PK, {_, SK}) ->
  decode_welcome(Welcome, PK, SK);
decode_welcome(Welcome, PK, SK) ->
  case Welcome of
    <<"RL3aNMXK", Nonce:16/binary, Box:144/binary>> ->
      NString = <<"CurveCPK", Nonce/binary>>,
      case enacl:box_open(Box, NString, PK, SK) of
        {ok, <<SSP:32/binary, Cookie:96/binary>>} ->
          {ok, SSP, Cookie};
        {error, failed_verification} ->
          {error, failed_verification}
      end;
    _ ->
      {error, invalid_welcome_packet}
  end.

decode_ready(Ready, #st{peer_short_term_pk=SSP, short_term_keypair={_, SK}}) ->
  case Ready of
    <<"RL3aNMXR", Nonce:8/binary, Box/binary>> ->
      NString = <<"CurveCP-server-R", Nonce/binary>>,
      <<N:64/unsigned-little-integer>> = Nonce,
      case enacl:box_open(Box, NString, SSP, SK) of
        {ok, Contents} ->
          {ok, N, Contents};
        {error, failed_verification} ->
          {error, failed_verification}
      end;
    _ ->
      {error, invalid_ready}
  end.

decode_ready(Ready, SSP, SK) ->
  case Ready of
    <<"RL3aNMXR", Nonce:8/binary, Box/binary>> ->
      NString = <<"CurveCP-server-R", Nonce/binary>>,
      <<N:64/unsigned-little-integer>> = Nonce,
      case enacl:box_open(Box, NString, SSP, SK) of
        {ok, Contents} ->
          {ok, N, Contents};
        {error, failed_verification} ->
          {error, failed_verification}
      end;
    _ ->
      {error, invalid_ready}
  end.

decode_msg(Data, PK, SK) ->
  case Data of
    <<"RL3aNMXM", Nonce:8/binary, Box/binary>> ->
      NString = <<"CurveCP-server-M", Nonce/binary>>,
      case enacl:box_open(Box, NString, PK, SK) of
        {ok, Contents} ->
          <<N:64/unsigned-little-integer>> = Nonce,
          {ok, N, Contents};
        {error, failed_verification} ->
          {error, failed_verification}
      end;
    _ ->
      {error, invalid_msg}
  end.

extract_cookie(Welcome, PK, {_, SK}) ->
  case decode_welcome(Welcome, PK, SK) of
    {ok, _, Cookie} ->
      Cookie;
    Error ->
      Error
  end.

peer_short_term_pk(Welcome, PK, {_, SK}) ->
  case decode_welcome(Welcome, PK, SK) of
    {ok, SSP, _} ->
      SSP;
    Error ->
      Error
  end.
