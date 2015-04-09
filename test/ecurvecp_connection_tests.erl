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
  _ = application:ensure_all_started(ecurvecp),
  [{keypair, Keypair}].

cleanup(_) ->
  ok.

check() ->
  case proper:quickcheck(prop_server_handshake(), [{to_file, user}]) of
    true ->
      true;
    _Other ->
      false
  end.

closed(_S) ->
  [{hello, {call, ?MODULE, connect, [{var, sender}, ?IP, ?PORT]}}].

hello(S) ->
  [{initiate, {call, ?MODULE, send_hello, [{var, sender}, S#st.sender_nonce_counter, S#st.short_term_keypair, {var, peer_pk}]}},
   {closed, {call, ?MODULE, close, [{var, sender}]}}].

initiate(S) ->
  [{established, {call, ?MODULE, send_initiate, [{var, sender}, S#st.short_term_keypair, S#st.long_term_keypair, {var, peer_pk}, S#st.sender_nonce_counter, S#st.last_msg]}},
   {closed, {call, ?MODULE, close, [{var, sender}]}}].

established(S) ->
  [{established, {call, ?MODULE, send_msg, [{var, sender}, binary(), S#st.sender_nonce_counter, S#st.peer_short_term_pk, S#st.short_term_keypair]}},
   {closed, {call, ?MODULE, close, [{var, sender}]}}].

initial_state() ->
  closed.

initial_state_data() ->
  #st{sender_nonce_counter=1, long_term_keypair=enacl:box_keypair()}.

next_state_data(closed, hello, S, _Sender, {call, _, _, _}) ->
  S#st{short_term_keypair=enacl:box_keypair()};
next_state_data(hello, initiate, S, Welcome, {call, _, _, [_, _, ShortTermKeypair, PeerPK]}) ->
  #{secret := SK} = ShortTermKeypair,
  #st{sender_nonce_counter=NC} = S,
  S#st{last_msg=Welcome, sender_nonce_counter=NC+1, peer_short_term_pk={call, ?MODULE, peer_short_term_pk, [Welcome, PeerPK, SK]}};
next_state_data(hello, closed, S, _R, {call, _, _, _}) ->
  S;
next_state_data(initiate, established, S, Ready, {call, _, _, _}) ->
  #st{sender_nonce_counter=NC} = S,
  S#st{last_msg=Ready, sender_nonce_counter=NC+1};
next_state_data(initiate, closed, S, _, {call, _, _, _}) ->
  S;
next_state_data(established, established, S, _Reply, {call, _, _, _}) ->
  #st{sender_nonce_counter=NC} = S,
  S#st{sender_nonce_counter=NC+1};
next_state_data(established, closed, S, _, {call, _, _, _}) ->
  S.

precondition(_From, _To, _S, {call, _, _, _}) ->
  true.

postcondition(closed, hello, _S, {call, ?MODULE, connect, [_, _, _]}, Resp) ->
  ok =:= Resp;
postcondition(hello, initiate, _S, {call, ?MODULE, send_hello, [_, _, ShortTermKeypair, PeerPK]}, Welcome) ->
  #{secret := SK} = ShortTermKeypair,
  case decode_welcome(Welcome, PeerPK, SK) of
    {ok, _, _} ->
      true;
    _Other ->
      false
  end;
postcondition(hello, closed, _S, {call, ?MODULE, close, _}, R) ->
  ok =:= R;
postcondition(initiate, established, _S, {call, ?MODULE, send_initiate, [_, ShortKey, _LongKey, PeerPK, _NC, Welcome]}, Ready) ->
  #{secret := SK} = ShortKey,
  case decode_welcome(Welcome, PeerPK, SK) of
    {ok, SSP, _Cookie} ->
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
    _ ->
      false
  end;
postcondition(initiate, closed, _S, {call, ?MODULE, close, _}, R) ->
  ok =:= R;
postcondition(established, established, _S, {call, ?MODULE, send_msg, [_, _, _, PK, ShortKey]}, R) ->
  #{secret := SK} = ShortKey,
  case R of
    <<"RL3aNMXM", Nonce:8/binary, Box/binary>> ->
      NString = <<"CurveCP-server-M", Nonce/binary>>,
      case enacl:box_open(Box, NString, PK, SK) of
        {ok, _Contents} ->
          true;
        {error, failed_verification} ->
          false
      end;
    _ ->
      false
  end;
postcondition(established, closed, _S, {call, ?MODULE, close, _}, R) ->
  ok =:= R.

connect(Sender, Ip, Port) ->
  simple_sender:connect(Sender, Ip, Port).

close(Sender) ->
  simple_sender:close(Sender).

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

do_send(Sender, Packet) ->
  ok = simple_sender:send(Sender, Packet),
  case simple_sender:recv(Sender) of
    {tcp, Data} ->
      Data;
    {error, Error} ->
      {error, Error}
  end.

weight(_From, _To, {call, ?MODULE, close, _}) ->
  1;
weight(_From, _To, {call, ?MODULE, _, _}) ->
  2.

prop_server_handshake() ->
  #{public := PK} = application:get_env(ecurvecp, long_term_keypair, undefined),
  {ok, _Listener} = simple_listener:start_listeners(500, ?PORT),
  ?FORALL(Cmds, proper_fsm:commands(?MODULE),
          begin
            Sender = simple_sender:start(),
            {H, S, Res} = proper_fsm:run_commands(?MODULE, Cmds, [{peer_pk, PK}, {sender, Sender}]),
            ?WHENFAIL(
              io:format("History: ~p\nState: ~p\nResult: ~p\n", [H, S, Res]),
                aggregate(zip(proper_fsm:state_names(H), command_names(Cmds)),
                        Res =:= ok))
          end).

start_acceptors(0, _) ->
  ok;
start_acceptors(Num, LSock) ->
  spawn(fun() ->
        case ecurvecp_connection:accept(LSock, infinity) of
          {ok, Sock} ->
            fun Loop() ->
              ok = ecurvecp_connection:setopts(Sock, [{active, once}]),
              receive
                {ecurvecp, Sock, Data} ->
                  ok = ecurvecp_connection:send(Sock, Data),
                  Loop();
                _Other ->
                  ok
              end
            end();
          {error, Reason} ->
            {error, Reason}
        end
    end),
  start_acceptors(Num-1, LSock).

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

peer_short_term_pk(Welcome, PK, SK) ->
  case decode_welcome(Welcome, PK, SK) of
    {ok, SSP, _} ->
      SSP;
    Error ->
      Error
  end.
