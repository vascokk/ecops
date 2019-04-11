-module(cops_sup).

-behaviour(supervisor).

%% API
-export([start_link/2]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link(SpecificDecoderMod, SpecificEncoderMod) ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, [SpecificDecoderMod, SpecificEncoderMod]).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([SpecificDecoderMod, SpecificEncoderMod]) ->
    RestartStrategy = one_for_one,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,
    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},
    Restart = permanent,
    Shutdown = 2000,
    Type = worker,

    Decoder = {decoder, {decoder, start_link, [SpecificDecoderMod]},
               Restart, Shutdown, Type, [decoder]},
    Encoder = {encoder, {encoder, start_link, [SpecificEncoderMod]},
               Restart, Shutdown, Type, [encoder]},
    {ok, {SupFlags, [Decoder, Encoder]}}.

%%====================================================================
%% Internal functions
%%====================================================================
