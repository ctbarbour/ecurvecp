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
    peer_short_term_pk,
    peer_long_term_pk,
    last_msg
  }).

server_handshake_test_() ->
   {setup,
    fun setup/0,
    fun cleanup/1,
    fun(_) -> [?_assert(check())] end}.

setup() ->
  ok = error_logger:tty(false),
  application:start(ecurvecp).

cleanup(_) ->
  application:stop(ecurvecp).

check() ->
  proper:quickcheck(prop_server_handshake(), [{numtests, 100}, {start_size, 5}, {to_file, user}]).

initial_state() ->
  waiting.

initial_state_data() ->
  #st{c=1, rc=0, short_term_keypair=g_keypair(), long_term_keypair=g_keypair(), peer_long_term_pk=ecurvecp_vault:public_key()}.

waiting(_S) ->
  [{hello, {call, ?MODULE, connect, [{var, sender}, {var, ip}, {var, port}]}}].

hello(S) ->
  [{initiate, {call, ?MODULE, send_hello, [{var, sender}, g_hello_good(S)]}}].

initiate(S) ->
  [{established, {call, ?MODULE, send_initiate, [{var, sender}, S#st.short_term_keypair, S#st.long_term_keypair, S#st.peer_long_term_pk,  S#st.c, S#st.last_msg]}}].

established(S) ->
  [{established, {call, ?MODULE, send_msg, [{var, sender}, binary(), S#st.c, S#st.peer_short_term_pk, S#st.short_term_keypair]}}].

next_state_data(waiting, hello, S, _R, _) ->
  S;
next_state_data(hello, closed, S, _, _) ->
  S;
next_state_data(hello, initiate, S, Welcome, {call, ?MODULE, send_hello, [_Sender, _Hello]}) ->
  #st{c=C} = S,
  PeerShortTermKey = {call, ?MODULE, peer_short_term_pk, [Welcome, S#st.peer_long_term_pk, S#st.short_term_keypair]},
  S#st{last_msg=Welcome, c=C+1, peer_short_term_pk=PeerShortTermKey};
next_state_data(hello, initiate, S, Welcome, {call, ?MODULE, send_hello, [_Sender, _ShortTermKeypair, _, _, _, _, _]}) ->
  #st{c=C} = S,
  PeerShortTermKey = {call, ?MODULE, peer_short_term_pk, [Welcome, S#st.peer_long_term_pk, S#st.short_term_keypair]},
  S#st{last_msg=Welcome, c=C+1, peer_short_term_pk=PeerShortTermKey};
next_state_data(initiate, established, S, Ready, {call, _, _, _}) ->
  #st{c=C, rc=RC} = S,
  S#st{last_msg=Ready, c=C+1, rc=RC+1};
next_state_data(established, established, S, _Reply, {call, _, _, _}) ->
  #st{c=C} = S,
  S#st{c=C+1}.

precondition(_From, _To, _S, {call, _, _, _}) ->
  true.

postcondition(waiting, hello, _S, {call, ?MODULE, connect, _}, R) ->
  R =:= ok;
postcondition(hello, initiate, S, {call, ?MODULE, send_hello, [_Sender, _Hello]}, Welcome) ->
  case decode_welcome(Welcome, S#st.peer_long_term_pk, S#st.short_term_keypair) of
    {ok, _, _} ->
      true;
    _Other ->
      false
  end;
postcondition(hello, initiate, S, {call, ?MODULE, send_hello, [_Sender, ShortTermKeypair, PeerPK, _, _, _, _]}, Welcome) ->
  {_, SK} = ShortTermKeypair,
  ?debugFmt("State: ~p\nLocal: ~p\n", [S#st.short_term_keypair, ShortTermKeypair]),
  case decode_welcome(Welcome, PeerPK, SK) of
    {ok, _, _} ->
      true;
    _Other ->
      false
  end;
postcondition(hello, initiate, _S, {call, ?MODULE, send_hello, [_, _, ShortTermKeypair, PeerPK]}, Welcome) ->
  {_, SK} = ShortTermKeypair,
  case decode_welcome(Welcome, PeerPK, SK) of
    {ok, _, _} ->
      true;
    _Other ->
      false
  end;
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

g_hello_bad(_, _, _) ->
  exactly(bad_hello).

g_hello_prefix() ->
  exactly(<<"QvnQ5XlH">>).

g_version_good() ->
  exactly(<<1/integer, 0/integer>>).

g_version_bad() ->
  ?LET({Major, Minor}, {integer(), integer()}, <<Major/integer, Minor/integer>>).

g_hello_nonce_string(Nonce) ->
  <<"CurveCP-client-H", Nonce/binary>>.

g_short_nonce_good(NC) ->
  <<NC:64/unsigned-little-integer>>.

g_short_nonce_bad(NC) ->
  ?LET({Type, Size},
       {oneof([little, big]), ?SUCHTHAT(N, integer(0, inf), N /= NC), ?SUCHTHAT(I, integer(8, inf), I /= 64 andalso I rem 8 == 0)},
       begin
         case Type of
           little ->
             <<NC:Size/unsigned-little-integer>>;
           big ->
             <<NC:Size/unsigned-big-integer>>
         end
      end).

g_hello_good(#st{short_term_keypair={PK, SK}, peer_long_term_pk=PeerPK, c=NC}) ->
  ?LET({Prefix, Version, Zeros, Nonce},
       {g_hello_prefix(), g_version_good(), g_padding_good(), g_short_nonce_good(NC)},
       begin
          ?LET(NString, g_hello_nonce_string(Nonce),
               begin
                 Box = enacl:box(Zeros, NString, PeerPK, SK),
                 <<Prefix/binary, Version/binary, Zeros/binary, PK/binary, Nonce/binary, Box/binary>>
               end)
       end).

g_keypair() ->
  #{public := PK, secret := SK} = enacl:box_keypair(),
  {PK, SK}.

encode_hello(PeerKey, PeerPK, NC) ->
  {PK, SK} = PeerKey,
  Zeros = binary:copy(<<0>>, 64),
  Nonce = <<NC:64/unsigned-little-integer>>,
  NString = <<"CurveCP-client-H", Nonce/binary>>,
  Box = enacl:box(Zeros, NString, PeerPK, SK),
  <<"QvnQ5XlH", 1/integer, 0/integer, Zeros/binary, PK/binary, Nonce/binary, Box/binary>>.

send_hello(Sender, Hello) ->
  do_send(Sender, Hello).

send_hello(Sender, {PK, SK}, PeerPK, Prefix, Version, Padding, Nonce) ->
  NString = <<"CurveCP-client-H", Nonce/binary>>,
  Box = enacl:box(Padding, NString, PeerPK, SK),
  Packet = <<Prefix/binary, Version/binary, Padding/binary, PK/binary, Nonce/binary, Box/binary>>,
  do_send(Sender, Packet).

send_hello(Sender, NC, ShortTermKeypair, PeerKey) ->
  {PK, SK} = ShortTermKeypair,
  Zeros = binary:copy(<<0>>, 64),
  Nonce = <<NC:64/unsigned-little-integer>>,
  NString = <<"CurveCP-client-H", Nonce/binary>>,
  Box = enacl:box(Zeros, NString, PeerKey, SK),
  Packet = <<"QvnQ5XlH", 1/integer, 0/integer, Zeros/binary, PK/binary, Nonce/binary, Box/binary>>,
  do_send(Sender, Packet).

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

connect(Sender, Ip, Port) ->
  simple_sender:connect(Sender, Ip, Port).

do_send(Sender, Packet) ->
  ok = simple_sender:send(Sender, Packet),
  simple_sender:recv(Sender).

weight(_From, _To, _) ->
  1.

prop_server_handshake() ->
  ?FORALL(State, g_initial_state(),
    ?FORALL({Cmds, Port, ShortTermKeypair, LongTermKeypair},
            {proper_fsm:commands(?MODULE, State), choose(1024, 41915), g_keypair(), g_keypair()},
            ?TRAPEXIT(
              begin
                {ok, Listener} = simple_listener:start(?IP, Port),
                {ok, Sender} = simple_sender:start(),
                {H, S, Res} = proper_fsm:run_commands(?MODULE, Cmds, [{ip, ?IP}, {port, Port}, {sender, Sender}, {listener, Listener}, {short_term_keypair, ShortTermKeypair}, {long_term_keypair, LongTermKeypair}]),
                ok = simple_sender:close(Sender),
                ?WHENFAIL(
                  io:format("History: ~p\nState: ~p\nResult: ~p\n", [H, S, Res]),
                    aggregate(zip(proper_fsm:state_names(H), command_names(Cmds)),
                            Res =:= ok))
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

peer_short_term_pk(Welcome, PK, {_, SK}) ->
  case decode_welcome(Welcome, PK, SK) of
    {ok, SSP, _} ->
      SSP;
    Error ->
      Error
  end.
