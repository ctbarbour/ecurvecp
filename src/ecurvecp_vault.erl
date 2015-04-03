-module(ecurvecp_vault).
-behavior(gen_server).

-export([start_link/1, public_key/0, box/3, box_open/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, code_change/3,
         terminate/2]).

-define(TAB, ?MODULE).

-record(st, {
    public_key,
    secret_key
  }).

start_link(#{public := PK, secret := SK}) ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [PK, SK], []).

public_key() ->
  gen_server:call(?MODULE, public_key).

box(Msg, Nonce, PK) ->
  gen_server:call(?MODULE, {box, Msg, Nonce, PK}).

box_open(Box, Nonce, PK) ->
  gen_server:call(?MODULE, {box_open, Box, Nonce, PK}).

init([PK, SK]) ->
  {ok, #st{public_key=PK, secret_key=SK}}.

handle_call(public_key, _From, State) ->
  #st{public_key=PK} = State,
  {reply, PK, State};
handle_call({box, Msg, Nonce, PK}, _From, State) ->
  #st{secret_key=SK} = State,
  {reply, enacl:box(Msg, Nonce, PK, SK), State};
handle_call({box_open, Box, Nonce, PK}, _From, State) ->
  #st{secret_key=SK} = State,
  {reply, enacl:box_open(Box, Nonce, PK, SK), State};
handle_call(_Msg, _From, State) ->
  {noreply, State}.

handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info(_Info, State) ->
  {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.
