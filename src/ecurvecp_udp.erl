-module(ecurvecp_udp).
-behavior(gen_server).

-export([start_link/3, reply/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3,
         terminate/2]).

-include("ecurvecp.hrl").

-record(st, {
    listen_ip               :: inet:ipaddress(),
    listen_port             :: inet:port_number(),
    socket                  :: inet:socket(),
    server_extension        :: <<_:16>>,
    pending       = 0       :: non_neg_integer(),
    clients       = 0       :: non_neg_integer(),
    max_clients   = 100     :: pos_integer(),
    max_pending   = 10      :: pos_integer(),
    client_ttl    = 360000  :: pos_integer(),
    pending_ttl   = 6000    :: pos_integer()
  }).

start_link(Ip, Port, Extension) ->
  Args = [Ip, Port, Extension],
  gen_server:start_link({local, ?MODULE}, ?MODULE, Args, []).

reply({Ip, Port}, Packet) ->
  gen_server:cast(?MODULE, {reply, Ip, Port, Packet}).

init([Ip, Port, Extension]) ->
  SocketOpts = case Ip of
    all ->
      [];
    _ ->
      [{ip, Ip}]
  end ++ [binary, {active, once}, inet, inet6],
  {ok, Socket} = gen_udp:open(Port, SocketOpts),
  State = #st{listen_ip=Ip, listen_port=Port, socket=Socket,
              server_extension=Extension},
  {ok, State}.

handle_call(_Msg, _From, State) ->
  {noreply, State}.

handle_cast({reply, Ip, Port, Packet}, State) ->
  #st{socket=Socket} = State,
  ok = gen_udp:send(Socket, Ip, Port, Packet),
  {noreply, State};
handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info({udp, _, Ip, Port, Packet}, State) ->
  From = {Ip, Port},
  ok = ecurvecp_server:handle_curvecp_packet(From, Packet),
  {noreply, active_once(State)};
handle_info(_, State) ->
  {stop, badarg, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.

active_once(#st{socket=undefined} = State) ->
  State;
active_once(#st{socket=Socket} = State) ->
  ok = inet:setopts(Socket, [{active, once}]),
  State.
