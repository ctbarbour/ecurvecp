-module(ecurvecp_server_tests).
-behavior(proper_fsm).

-compile(export_all).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("ecurvecp/src/ecurvecp.hrl").

handshake_test_() ->
  {timeout, 60,
   {setup,
    fun setup/0,
    fun cleanup/1,
    fun(_) ->
      ?_assert(proper:quickcheck(prop_handshake(), [{to_file, user}]))
    end
  }}.

-record(st, {
    pid
  }).

setup() ->
  {ok, _} = application:ensure_all_started(ecurvecp).

cleanup(_) ->
  ok = application:stop(ecurvecp).

extension() ->
  ecurvecp:extension().

hello_packet() ->
  #hello_packet{server_extension=extension(),
                client_extension=extension(),
                client_short_term_public_key=binary(32),
                nonce=binary(8),
                box=binary(80)}.

initiate_packet() ->
  {initiate_packet, extension(), extension(), binary(32), binary(96), binary(16), binary(144)}.

client_message_packet() ->
  {client_message_packet, extension(), extension(), binary(32), binary(8), binary()}.

curvecp_packet() ->
  oneof([hello_packet(), initiate_packet(), client_message_packet()]).

initial_state() ->
  hello.

initial_state_data() ->
  #st{}.

hello(S) ->
  [{initiate, {call, ?MODULE, send_packet, [curvecp_packet(), S]}}].

initiate(S) ->
  [{finalize, {call, ?MODULE, send_packet, [curvecp_packet(), S]}}].

finalize(S) ->
  [{history, {call, ?MODULE, send_packet, [curvecp_packet(), S]}}].

message(S) ->
  [{message, {call, ?MODULE, send_packet, [curvecp_packet(), S]}}].

precondition(_From, _Target, _StateData, {call, _, _, _}) ->
  true.

postcondition(_StateName, _, _S, {call, _, send_packet, _}, _Result) ->
  true.

send_packet(Packet, #st{pid=Pid} = S) when Pid /= undefined ->
  #st{pid=Pid} = S,
  gen_fsm:send_event(Pid, Packet).

next_state_data(_, _, S, _, {call, _, send_packet, [Packet, _]}) ->
  case Packet of
    #hello_packet{} ->
      S;
    _ ->
      S
  end.

prop_handshake() ->
  ?FORALL(Cmds, proper_fsm:commands(?MODULE),
          begin
            {History, State, Result} = proper_fsm:run_commands(?MODULE, Cmds),
            ?WHENFAIL(io:format("History, ~w\nState: ~w\n, Result: ~w\n",
                                [History, State, Result]),
                      Result =:= ok)
          end).
