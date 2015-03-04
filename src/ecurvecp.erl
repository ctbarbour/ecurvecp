-module(ecurvecp).

-export([start_client/4, start_listener/4, extension/0]).

start_client(Ip, Port, ServerExtension, ServerPublicKey) ->
  ecurvecp_client_sup:start_client(Ip, Port, ServerExtension, ServerPublicKey).

start_listener(Ref, NumListeners, TransOpts, ProtoOpts) ->
  ServerKeypair = proplists:get_value(server_keypair, ProtoOpts, application:get_env(?MODULE, server_keypair, enacl:box_keypair())),
  ServerExtension = proplists:get_value(server_extension, ProtoOpts, application:get_env(?MODULE, server_extension, extension())),

  Port = proplists:get_value(listen_port, TransOpts, application:get_env(?MODULE, listen_port, 46779)),
  Ip = proplists:get_value(listen_ip, TransOpts, application:get_env(?MODULE, listen_ip, all)),

  NewTransOpts = lists:foldl(fun({Key, _Val} = Tuple, Acc) ->
        lists:keyreplace(Key, 1, Acc, Tuple)
    end, TransOpts, [{port, Port}, {ip, Ip}]),

  NewProtoOpts = lists:foldl(fun({Key, _Val} = Tuple, Acc) ->
        lists:keyreplace(Key, 1, Acc, Tuple)
    end, TransOpts, [{server_keypair, ServerKeypair}, {server_extension, ServerExtension}]),

  ecurvecp_server_sup:start_listener(Ref, NumListeners, NewTransOpts, NewProtoOpts).

extension() ->
  druuid:v4().
