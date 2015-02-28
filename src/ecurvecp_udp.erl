-module(ecurvecp_udp).
-behavior(gen_server).

-export([start_link/4, reply/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3,
         terminate/2]).

-include("ecurvecp.hrl").

-define(TAB, ?MODULE).

-record(st, {
    listen_ip               :: inet:ipaddress(),
    listen_port             :: inet:port_number(),
    socket                  :: inet:socket(),
    server_extension        :: <<_:16>>,
    keypair                 :: #{public => <<_:32>>, secret => <<_:32>>},
    pending       = 0       :: non_neg_integer(),
    clients       = 0       :: non_neg_integer(),
    max_clients   = 100     :: pos_integer(),
    max_pending   = 10      :: pos_integer(),
    client_ttl    = 360000  :: pos_integer(),
    pending_ttl   = 6000    :: pos_integer()
  }).

start_link(Ip, Port, Extension, KeyPair) ->
  Args = [Ip, Port, Extension, KeyPair],
  gen_server:start_link({local, ?MODULE}, ?MODULE, Args, []).

reply(To, Reply) ->
  gen_server:cast(?MODULE, {reply, {To, Reply}}).

init([Ip, Port, Extension, KeyPair]) ->
  ?TAB = ets:new(?TAB, [named_tabled, public, ordered_set]),
  SocketOpts = case Ip of
    all ->
      [];
    _ ->
      [{ip, Ip}]
  end ++ [binary, {active, once}, inet, inet6],
  {ok, Socket} = gen_udp:open(Port, SocketOpts),
  State = #st{listen_ip=Ip, listen_port=Port, socket=Socket,
              keypair=KeyPair, server_extension=Extension},
  {ok, State}.

handle_call(_Msg, _From, State) ->
  {noreply, State}.

handle_cast({reply, {Ip, Port, Packet}}, State) ->
  #st{socket=Socket} = State,
  ok = gen_udp:send(Socket, Ip, Port, Packet),
  {noreply, State};
handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info({udp, _, Ip, Port, Packet}, State) ->
  From = {Ip, Port},
  case Packet of
    <<?HELLO_PKT, _Rest/binary>> ->
      validate_curvecp_packet(Packet, From, State);
    <<?INITIATE_PKT, _Rest/binary>> ->
      validate_curvecp_packet(Packet, From, State);
    <<?CLIENT_MESSAGE_PKT, _Rest/binary>> ->
      validate_curvecp_packet(Packet, From, State);
    _ ->
      {noreply, State}
  end;
handle_info(_, State) ->
  {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.

validate_curvecp_packet(<<_:8/binary, SE:16/binary, _Rest/binary>> = Packet, From, State) ->
  case verify_server_extension(SE, State) of
    true ->
      handle_curvecp_packet(Packet, From, State);
    false ->
      {noreply, State}
  end;
validate_curvecp_packet(_Packet, _From, State) ->
  {noreply, State}.

verify_server_extension(ServerExt, #st{server_extension=ServerExt}) ->
  true;
verify_server_extension(_, _) ->
  false.

handle_curvecp_packet(<<?HELLO_PKT, _Rest/binary>> = Packet, From, State) ->
  {ok, _Pid} = ecurvecp_server_sup:start_server(),
  ok = ecurvecp_server:send(From, Packet),
  {noreply, State};
handle_curvecp_packet(<<?INITIATE_PKT, _Rest/binary>> = Packet, From, State) ->
  dispatch(Packet, From, State);
handle_curvecp_packet(<<?CLIENT_MESSAGE_PKT, _Rest/binary>> = Packet, From, State) ->
  dispatch(Packet, From, State).

dispatch(<<_:24/binary, CE:16/binary, _Rest/binary>> = Packet, From, State) ->
  case lookup(CE) of
    {ok, Pid} ->
      ok = ecurvecp_server:send(Pid, From, Packet),
      {noreply, State};
    not_found ->
      {noreply, State}
  end.

lookup(CE) ->
  case catch(gproc:lookup_local_name({ecurvecp_server, CE})) of
    {'EXIT', {badarg, _}} ->
      not_found;
    Pid ->
      Pid
  end.
