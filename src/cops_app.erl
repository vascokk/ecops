-module(cops_app).

-behaviour(application).

%% Application callbacks
-export([start/2
        ,stop/1]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
  ClientSpecDec = application:get_env(cops, client_specific_decoder, pcmm_decoder),
  ClientSpecEnc = application:get_env(cops, client_specific_encoder, pcmm_encoder),
  cops_sup:start_link(ClientSpecDec, ClientSpecEnc).

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================
