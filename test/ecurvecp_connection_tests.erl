-module(ecurvecp_connection_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-behavior(proper_fsm).
-compile(export_all).

-define(IP, {127,0,0,1}).
-define(PORT, 1337).

-record(st, {
    sender_nonce_counter,
    short_term_keypair,
    long_term_keypair,
    peer_short_term_pk,
    last_msg
  }).

server_handshake_test_() ->
   {setup, fun setup/0, fun cleanup/1,
    fun(_) -> [?_assert(check())] end}.

setup() ->
  ok = error_logger:tty(false),
  _ = application:load(ecurvecp),
  Keypair = enacl:box_keypair(),
  ok = application:set_env(ecurvecp, long_term_keypair, Keypair),
  ok = application:start(ecurvecp),
  [{keypair, Keypair}].

cleanup(_) ->
  application:stop(ecurvecp).

check() ->
  case proper:quickcheck(prop_server_handshake(), [{to_file, user}]) of
    true ->
      true;
    _Other ->
      false
  end.

waiting(_S) ->
  [{hello, {call, ?MODULE, connect, [{var, sender}, {var, ip}, {var, port}]}}].

hello(S) ->
  [{initiate, {call, ?MODULE, send_hello, [{var, sender}, S#st.sender_nonce_counter, S#st.short_term_keypair, {var, peer_pk}]}}].

initiate(S) ->
  [{established, {call, ?MODULE, send_initiate, [{var, sender}, S#st.short_term_keypair, S#st.long_term_keypair, {var, peer_pk}, S#st.sender_nonce_counter, S#st.last_msg]}}].

established(S) ->
  [{established, {call, ?MODULE, send_msg, [{var, sender}, binary(), S#st.sender_nonce_counter, S#st.peer_short_term_pk, S#st.short_term_keypair]}}].

initial_state() ->
  waiting.

initial_state_data() ->
  #st{sender_nonce_counter=1,
      short_term_keypair=enacl:box_keypair(),
      long_term_keypair=enacl:box_keypair()}.

next_state_data(waiting, hello, S, _R, _) ->
  S;
next_state_data(hello, initiate, S, Welcome, {call, _, _, [_, _, ShortTermKeypair, PeerPK]}) ->
  #st{sender_nonce_counter=NC} = S,
  #{secret := SK} = ShortTermKeypair,
  PeerShortTermKey = {call, ?MODULE, peer_short_term_pk, [Welcome, PeerPK, SK]},
  S#st{last_msg=Welcome, sender_nonce_counter=NC+1, peer_short_term_pk=PeerShortTermKey};
next_state_data(initiate, established, S, Ready, {call, _, _, _}) ->
  #st{sender_nonce_counter=NC} = S,
  S#st{last_msg=Ready, sender_nonce_counter=NC+1};
next_state_data(established, established, S, _Reply, {call, _, _, _}) ->
  #st{sender_nonce_counter=NC} = S,
  S#st{sender_nonce_counter=NC+1}.

precondition(_From, _To, _S, {call, _, _, _}) ->
  true.

postcondition(waiting, hello, _S, {call, ?MODULE, connect, _}, R) ->
  R =:= ok;
postcondition(hello, initiate, _S, {call, ?MODULE, send_hello, [_, _, ShortTermKeypair, PeerPK]}, Welcome) ->
  #{secret := SK} = ShortTermKeypair,
  case decode_welcome(Welcome, PeerPK, SK) of
    {ok, _, _} ->
      true;
    _Other ->
      false
  end;
postcondition(initiate, established, _S, {call, ?MODULE, send_initiate, [_, ShortKey, _LongKey, PeerPK, _NC, Welcome]}, Ready) ->
  #{secret := SK} = ShortKey,
  case decode_welcome(Welcome, PeerPK, SK) of
    {ok, SSP, _Cookie} ->
      case decode_ready(Ready, SSP, SK) of
        {ok, _} ->
          true;
        {error, _} ->
          false
      end;
    _ ->
      false
  end;
postcondition(established, established, _S, {call, ?MODULE, send_msg, [_, _, _, PK, ShortKey]}, Data) ->
  #{secret := SK} = ShortKey,
  case decode_msg(Data, PK, SK) of
    {ok, _} ->
      true;
    {error, _} ->
      false
  end.

send_hello(Sender, NC, ShortTermKeypair, PeerKey) ->
  #{public := PK, secret := SK} = ShortTermKeypair,
  Zeros = binary:copy(<<0>>, 64),
  Nonce = <<NC:64/unsigned-little-integer>>,
  NString = <<"CurveCP-client-H", Nonce/binary>>,
  Box = enacl:box(Zeros, NString, PeerKey, SK),
  Packet = <<"QvnQ5XlH", 1/integer, 0/integer, Zeros/binary, PK/binary, Nonce/binary, Box/binary>>,
  do_send(Sender, Packet).

send_initiate(Sender, ShortKey, LongKey, PeerPK, NC, Welcome) ->
  #{public := LP, secret := LS} = LongKey,
  #{public := SP, secret := SS} = ShortKey,
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
  #{secret := SK} = Keypair,
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

weight(_From, _To, {call, ?MODULE, close, _}) ->
  1;
weight(_From, _To, {call, ?MODULE, _, _}) ->
  2.

prop_server_handshake() ->
  #{public := PK} = application:get_env(ecurvecp, long_term_keypair, undefined),
  ?FORALL({Cmds, Port}, {proper_fsm:commands(?MODULE), choose(1024, 41915)},
          ?TRAPEXIT(
            begin
              {ok, Listener} = simple_listener:start(?IP, Port),
              {ok, Sender} = simple_sender:start(),
              {H, S, Res} = proper_fsm:run_commands(?MODULE, Cmds, [{peer_pk, PK}, {ip, ?IP}, {port, Port}, {sender, Sender}, {listener, Listener}]),
              ok = simple_sender:close(Sender),
              ?WHENFAIL(
                io:format("History: ~p\nState: ~p\nResult: ~p\n", [H, S, Res]),
                  aggregate(zip(proper_fsm:state_names(H), command_names(Cmds)),
                          Res =:= ok))
            end)).

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
      enacl:box_open(Box, NString, SSP, SK);
    _ ->
      {error, invalid_ready}
  end.

decode_msg(Data, PK, SK) ->
  case Data of
    <<"RL3aNMXM", Nonce:8/binary, Box/binary>> ->
      NString = <<"CurveCP-server-M", Nonce/binary>>,
      enacl:box_open(Box, NString, PK, SK);
    _ ->
      {error, invalid_msg}
  end.

peer_short_term_pk(Welcome, PK, SK) ->
  case decode_welcome(Welcome, PK, SK) of
    {ok, SSP, _} ->
      SSP;
    Error ->
      Error
  end.
