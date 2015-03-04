-module(ecurvecp_protocol).
-behavior(gen_fsm).
-behavior(ranch_protocol).

-export([start_link/4, init/4, reply/2]).
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
         code_change/4, terminate/3]).
-export([hello/2, initiate/2, finalize/2, message/2, message/3]).

-include("ecurvecp.hrl").

-record(codec, {
    server_long_term_public_key,
    server_long_term_secret_key,
    server_short_term_public_key,
    server_short_term_secret_key,
    client_long_term_public_key,
    client_short_term_public_key,
    minute_key,
    prev_minute_key,
    shared_key,
    cookie,
    server_extension,
    client_extension
  }).

-record(st, {
    socket                    :: inet:socket(),
    transport                 :: ranch:transport(),
    codec                     :: codec(),
    handshake_ttl   = 60000   :: pos_integer(),
    ttl             = 360000  :: pos_integer()
  }).

-type codec() :: #codec{}.

socket_options() ->
  [{active, once},
   {packet, 4},
   {reuseaddr, true},
   binary].

reply(Pid, Message) ->
  gen_fsm:send_event(Pid, {reply, Message}).

start_link(Ref, Socket, Transport, Opts) ->
  proc_lib:start_link(?MODULE, init, [Ref, Socket, Transport, Opts]).

init(Ref, Socket, Transport, Opts) ->
  ok = proc_lib:init_ack({ok, self()}),
  ok = ranch:accept_ack(Ref),
  ok = Transport:setopts(Socket, socket_options()),
  #{public := SLTPK, secret := SLTSK} = proplists:get_value(server_keypair, Opts),
  ServerExtension = proplists:get_value(server_extension, Opts),

  Codec = rotate_minute_keys(
      #codec{server_long_term_public_key=SLTPK,
             server_long_term_secret_key=SLTSK,
             server_extension=ServerExtension}),

  State = #st{socket=Socket, transport=Transport, codec=Codec},
  gen_fsm:enter_loop(?MODULE, [], hello, State).

decode_curvecp_packet(<<?HELLO, SE:16/binary, CE:16/binary, CSTPK:32/binary,
                        _Z:64/binary, Nonce:8/binary, Box:80/binary>>) ->
  #hello_packet{server_extension=SE,
                client_extension=CE,
                client_short_term_public_key=CSTPK,
                nonce=Nonce,
                box=Box};
decode_curvecp_packet(<<?INITIATE, SE:16/binary, CE:16/binary, CSTPK:32/binary,
                        Cookie:96/binary, Nonce:8/binary, Box/binary>>) ->
  #initiate_packet{server_extension=SE, client_extension=CE,
                   client_short_term_public_key=CSTPK,
                   cookie=Cookie, nonce=Nonce, box=Box};
decode_curvecp_packet(<<?CLIENT_M, SE:16/binary, CE:16/binary, CSTPK:32/binary,
                        Nonce:8/binary, Box/binary>>) ->
  #client_msg_packet{server_extension=SE,
                     client_extension=CE,
                     client_short_term_public_key=CSTPK,
                     nonce=Nonce,
                     box=Box}.

init([]) ->
  {ok, #st{}}.

hello(#hello_packet{} = Hello, State) ->
  #st{handshake_ttl=Timeout} = State,
  Codec = generate_short_term_keys(
      decode_hello_packet(Hello, State#st.codec)),
  CookiePacket = encode_cookie_packet(Codec),
  ok = send(CookiePacket, State),
  {next_state, initiate, State#st{codec=Codec}, Timeout};
hello(timeout, State) ->
  {stop, timeout, State}.

initiate(#initiate_packet{} = Initiate, State) ->
  Codec = decode_initiate_packet(Initiate, State#st.codec),
  MessagePacket = encode_server_message_packet(<<"Welcome">>, Codec),
  ok = send(MessagePacket, State),
  {next_state, finalize, State#st{codec=Codec}, 0};
initiate(timeout, State) ->
  {stop, handshake_timeout, State}.

finalize(timeout, State) ->
  #st{ttl=Timeout} = State,
  Codec = generate_shared_key(State#st.codec),
  {next_state, message, State#st{codec=Codec}, Timeout}.

message(#client_msg_packet{} = Packet, State) ->
  #st{ttl=Timeout} = State,
  {ok, ClientM, Codec} = decode_client_message_packet(Packet, State#st.codec),
  ServerMessagePacket = encode_server_message_packet(ClientM, Codec),
  ok = send(ServerMessagePacket, State),
  {next_state, message, State#st{codec=Codec}, Timeout};
message(timeout, State) ->
  {stop, timeout, State}.

message({reply, Message}, _From, State) ->
  #st{ttl=Timeout} = State,
  ServerMessagePacket = encode_server_message_packet(Message, State#st.codec),
  ok = send(ServerMessagePacket, State),
  {next_state, message, State, Timeout}.

handle_event(_Event, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_sync_event(_Event, _From, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_info(rotate, StateName, StateData) ->
  Codec = rotate_minute_keys(StateData#st.codec),
  {next_state, StateName, StateData#st{codec=Codec}};
handle_info(Info, StateName, StateData) ->
  #st{socket=Socket, transport=Transport} = StateData,
  {Ok, Closed, Error} = Transport:messages(),
  case Info of
    {Ok, Socket, Packet} ->
      ?MODULE:StateName(decode_curvecp_packet(Packet), active_once(StateData));
    {Error, Socket} ->
      {stop, Error, StateData};
    {Closed, Socket} ->
      {stop, normal, StateData};
    _ ->
      {next_state, StateName, StateData}
  end.

code_change(_OldVsn, StateName, StateData, _Extra) ->
  {ok, StateName, StateData}.

terminate(_Reason, _StateName, StateData) ->
  #st{transport=Transport, socket=Socket} = StateData,
  ok = Transport:close(Socket),
  ok.

send(Packet, State) ->
  #st{transport=Transport, socket=Socket} = State,
  Transport:send(Socket, Packet).

decode_hello_packet(Hello, Codec) ->
  #hello_packet{nonce=Nonce,
                box=Box,
                client_short_term_public_key=CSTPK,
                server_extension=SE,
                client_extension=CE} = Hello,
  true = decode_hello_packet_box(Nonce, Box, CSTPK, Codec),
  Codec#codec{server_extension=SE, client_extension=CE,
              client_short_term_public_key=CSTPK}.

decode_hello_packet_box(Nonce, Box, CSTPK, Codec) ->
  #codec{server_long_term_secret_key=SLTSK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(hello, Nonce),
  {ok, Contents} = enacl:box_open(Box, NonceString, CSTPK, SLTSK),
  verify_hello_box_contents(Contents).

verify_hello_box_contents(<<First:32/binary, Second:32/binary>>) ->
  Zeros = binary:copy(<<0>>, 32),
  enacl:verify_32(First, Zeros) andalso enacl:verify_32(Second, Zeros);
verify_hello_box_contents(_Contents) ->
  false.

encode_cookie_packet(Codec) ->
  #codec{client_short_term_public_key=CSTPK,
         server_long_term_secret_key=SLTSK,
         server_short_term_public_key=SSTPK,
         minute_key=MK,
         client_extension=CE,
         server_extension=SE} = Codec,

  Nonce = ecurvecp_nonces:long_term_nonce_counter(SLTSK),
  NonceString = ecurvecp_nonces:nonce_string(cookie, Nonce),
  Cookie = encode_cookie(CSTPK, SSTPK, MK),
  PlainText = <<SSTPK/binary, Cookie/binary>>,
  Box = enacl:box(PlainText, NonceString, CSTPK, SLTSK),
  <<?COOKIE, CE/binary, SE/binary, Nonce/binary, Box/binary>>.

encode_cookie(ClientShortTermPubKey, ServerShortTermSecKey, MinuteKey) ->
  Msg = <<ClientShortTermPubKey/binary, ServerShortTermSecKey/binary>>,
  Nonce = ecurvecp_nonces:long_term_nonce_timestamp(),
  NonceString = ecurvecp_nonces:nonce_string(minute_key, Nonce),
  Box = enacl:secretbox(Msg, NonceString, MinuteKey),
  <<Nonce/binary, Box/binary>>.

decode_initiate_packet(Initiate, Codec) ->
  #initiate_packet{cookie=Cookie,
                   client_short_term_public_key=CSTPK,
                   nonce=Nonce,
                   box=Box} = Initiate,
  true = verify_cookie(Cookie, CSTPK, Codec),
  decode_initiate_box(Nonce, Box, Codec).

verify_cookie(<<Nonce:16/binary, Box:80/binary>>, CSTPK, Codec) ->
  % TODO: check both minute key and prev minute key
  #codec{minute_key=MK, prev_minute_key=_PMK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(minute_key, Nonce),
  case enacl:secretbox_open(Box, NonceString, MK) of
    {ok, <<BoxedCSTPK:32/binary, _:32/binary>>} ->
      enacl:verify_32(BoxedCSTPK, CSTPK);
    _ ->
      false
  end.

decode_initiate_box(Nonce, Box, Codec) ->
  #codec{client_short_term_public_key=CSTPK,
         server_short_term_secret_key=SSTSK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(initiate, Nonce),
  {ok, Contents} = enacl:box_open(Box, NonceString, CSTPK, SSTSK),
  verify_initiate_box_contents(Contents, Codec).

verify_initiate_box_contents(<<CLTPK:32/binary, Vouch:64/binary,
                               DomainName:256/binary, _Message/binary>>,
                             Codec) ->
  true = verify_vouch(CLTPK, Vouch, Codec) andalso
         verify_client(CLTPK, Codec) andalso
         verify_domain_name(DomainName, Codec),
  Codec#codec{client_long_term_public_key=CLTPK}.

verify_vouch(CLTPK, <<Nonce:16/binary, Box:48/binary>>, Codec) ->
  #codec{server_long_term_secret_key=SLTPK,
         client_short_term_public_key=CSTPK} = Codec,
  NonceString = ecurvecp_nonces:nonce_string(vouch, Nonce),
  {ok, VouchedCSTPK} = enacl:box_open(Box, NonceString, CLTPK, SLTPK),
  enacl:verify_32(VouchedCSTPK, CSTPK).

verify_client(_CLTPK, _Codec) ->
  true.

verify_domain_name(_DomainName, _Codec) ->
  true.

encode_server_message_packet(Message, Codec) ->
  #codec{server_short_term_secret_key=SSTSK,
         client_short_term_public_key=CSTPK,
         shared_key=SharedKey,
         client_extension=CE,
         server_extension=SE} = Codec,

  Nonce = ecurvecp_nonces:short_term_nonce(SSTSK),
  NonceString = ecurvecp_nonces:nonce_string(server_message, Nonce),
  Box = if
    SharedKey =:= undefined ->
      enacl:box(Message, NonceString, CSTPK, SSTSK);
    true ->
      enacl:box_afternm(Message, NonceString, SharedKey)
  end,
  <<?SERVER_M, CE/binary, SE/binary, Nonce/binary, Box/binary>>.

decode_client_message_packet(ClientMsgPacket, Codec) ->
  #client_msg_packet{nonce=Nonce, box=Box} = ClientMsgPacket,
  #codec{client_short_term_public_key=CSTPK,
         server_short_term_secret_key=SSTSK,
         shared_key=SharedKey} = Codec,

  NonceString = ecurvecp_nonces:nonce_string(client_message, Nonce),
  {ok, Message} = if
    SharedKey =:= undefined ->
      enacl:box_open(Box, NonceString, CSTPK, SSTSK);
    true ->
      enacl:box_open_afternm(Box, NonceString, SharedKey)
  end,
  {ok, Message, Codec}.

generate_shared_key(Codec) ->
  #codec{client_short_term_public_key=CSTPK,
         server_short_term_secret_key=SSTSK} = Codec,
  SharedKey = enacl:box_beforenm(CSTPK, SSTSK),
  Codec#codec{shared_key=SharedKey}.

generate_minute_key() ->
  enacl:randombytes(32).

generate_short_term_keys(Codec) ->
  #{public := SSTPK, secret := SSTSK} = enacl:box_keypair(),
  Codec#codec{server_short_term_public_key=SSTPK,
              server_short_term_secret_key=SSTSK}.

rotate_minute_keys(#codec{minute_key=undefined} = Codec) ->
  MinuteKey = generate_minute_key(),
  rotate_minute_keys(Codec#codec{minute_key=MinuteKey});
rotate_minute_keys(Codec) ->
  #codec{minute_key=PrevMinuteKey} = Codec,
  MinuteKey = generate_minute_key(),
  _Ref = erlang:send_after(60000, self(), rotate),
  Codec#codec{minute_key=MinuteKey, prev_minute_key=PrevMinuteKey}.

active_once(State) ->
  #st{transport=Transport, socket=Socket} = State,
  ok = Transport:setopts(Socket, [{active, once}]),
  State.
