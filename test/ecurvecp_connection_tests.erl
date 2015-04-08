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
    peer_pk,
    last_msg
  }).

server_handshake_test_() ->
   {setup, fun setup/0, fun cleanup/1,
    fun(_) -> [?_assert(check())] end}.

setup() ->
  ok = application:load(ecurvecp),
  Keypair = enacl:box_keypair(),
  ok = application:set_env(ecurvecp, long_term_keypair, Keypair),
  {ok, _Apps} = application:ensure_all_started(ecurvecp),
  [{keypair, Keypair}].

cleanup(_) ->
  ok.

check() ->
  case proper:quickcheck(server_handshake_prop(), [{to_file, user}]) of
    [] ->
      true;
    Other ->
      ?debugFmt("Quickcheck failure: ~p~n", [Other]),
      false
  end.

accept(_S) ->
  [{hello, {call, ?MODULE, connect, [{var, sender}, {var, ip}, {var, port}]}}].

hello(S) ->
  [{initiate, {call, ?MODULE, send_hello, [{var, sender}, S#st.sender_nonce_counter, S#st.short_term_keypair, {var, peer_pk}]}}].

initiate(S) ->
  [{established, {call, ?MODULE, send_initiate, [{var, sender}, S#st.short_term_keypair, S#st.long_term_keypair, S#st.peer_pk, S#st.sender_nonce_counter, S#st.last_msg]}}].

established(S) ->
  [{established, {call, ?MODULE, send_msg, [{var, sender}, S#st.short_term_keypair, S#st.peer_short_term_pk, S#st.sender_nonce_counter, binary()]}}].

initial_state() ->
  accept.

initial_state_data() ->
  #st{sender_nonce_counter=0}.

next_state_data(accept, hello, S, _Sender, {call, _, _, _}) ->
  S#st{short_term_keypair=enacl:box_keypair()};
next_state_data(hello, initiate, S, Welcome, {call, _, _, _}) ->
  #st{sender_nonce_counter=NC} = S,
  S#st{last_msg=Welcome, sender_nonce_counter=NC+1};
next_state_data(initiate, established, S, Ready, {call, _, _, _}) ->
  #st{sender_nonce_counter=NC} = S,
  S#st{last_msg=Ready, sender_nonce_counter=NC+1};
next_state_data(established, established, S, _Reply, {call, _, _, _}) ->
  #st{sender_nonce_counter=NC} = S,
  S#st{sender_nonce_counter=NC+1}.

precondition(_From, _To, _S, {call, _, _, _}) ->
  true.

postcondition(accept, hello, _S, {call, ?MODULE, connect, [_, _, _]}, Resp) ->
  ok =:= Resp;
postcondition(hello, initiate, _S, {call, ?MODULE, send_hello, [_, _, ShortTermKeypair, PeerPK]}, Welcome) ->
  #{secret := SK} = ShortTermKeypair,
  case Welcome of
    <<"RL3aNMXK", Nonce:16/binary, Box:144/binary>> ->
      NString = <<"CurvecpCPK", Nonce/binary>>,
      case enacl:box_open(Box, NString, PeerPK, SK) of
        {ok, <<_SSP:32/binary, _Cookie:96/binary>>} ->
          true;
        {error, failed_verification} ->
          false
      end;
    _ ->
      false
  end;
postcondition(initiate, established, _S, {call, ?MODULE, send_initiate, [_, ShortKey, LongKey, PeerKey, NC, Welcome]}, Ready) ->
  #{public := PeerPK} = PeerKey,
  #{secret := SK} = ShortKey,
  case Welcome of
    <<"RL3aNMXK", WNonce:16/binary, WBox:144/binary>> ->
      WNString = <<"CurvecpCPK", WNonce/binary>>,
      case enacl:box_open(WBox, WNString, PeerPK, SK) of
        {ok, <<SSP:32/binary, _Cookie:96/binary>>} ->
          case Ready of
            <<"RL3aNMXR", Nonce:8/binary, Box/binary>> ->
              NString = <<"CurveCP-server-R", Nonce/binary>>,
              case enacl:box_open(Box, NString, SSP, SK) of
                {ok, _Contents} ->
                  true;
                {error, failed_verification} ->
                  false
              end;
            _ ->
              false
          end;
        {error, failed_verification} ->
          false
      end;
    _ ->
      false
  end;
postcondition(established, established, _S, {call, ?MODULE, send_msg, _}, R) ->
  true.

connect(Sender, Ip, Port) ->
  simple_sender:connect(Sender, Ip, Port).

send_hello(Sender, NC, ShortTermKeypair, PeerKey) ->
  #{secret := SK} = ShortTermKeypair,
  Zeros = binary:copy(<<0>>, 64),
  Nonce = <<NC:64/unsigned-little-integer>>,
  NString = <<"CurveCP-client-H", Nonce/binary>>,
  Box = enacl:box(Zeros, NString, PeerKey, SK),
  Packet = <<"QvnQ5XlH", 1:8/integer, 0:8/integer, Zeros/binary, Nonce/binary, Box/binary>>,
  do_send(Sender, Packet).

send_initiate(Sender, ShortKey, LongKey, PeerPK, NC, Welcome) ->
  #{public := LP, secret := LS} = LongKey,
  #{public := SP, secret := SS} = ShortKey,
  case Welcome of
    <<"RL3aNMXK", Nonce:16/binary, Box:144/binary>> ->
      NString = <<"CurvecpCPK", Nonce/binary>>,
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
          ?debugFmt("Sending initiate: ~p~n", [IPacket]),
          do_send(Sender, IPacket);
        {error, failed_verification} ->
          false
      end;
    _ ->
      false
  end.

do_send(Sender, Packet) ->
  ok = simple_sender:send(Sender, Packet),
  ?debugFmt("Sent ~p~n", [Sender]),
  case simple_sender:recv(Sender) of
    {tcp, Data} ->
      ?debugFmt("Received: ~p~n", [Data]),
      Data;
    {error, Error} ->
      {error, Error}
  end.

server_handshake_prop() ->
  #{public := PK} = application:get_env(ecurvecp, long_term_keypair, undefined),
  Listener = simple_listener:start(?PORT),
  ?FORALL(Cmds, proper_fsm:commands(?MODULE),
          begin
            Sender = simple_sender:start(),
            {H, S, Res} = proper_fsm:run_commands(?MODULE, Cmds, [{peer_pk, PK}, {listener, Listener}, {sender, Sender}, {ip, ?IP}, {port, ?PORT}]),
            ?WHENFAIL(io:format("History: ~p~nState: ~p~nResult: ~p~n",
                                [H, S, Res]),
                      Res =:= ok)
          end).
