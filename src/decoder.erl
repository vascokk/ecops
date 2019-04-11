-module(decoder).
-author("Vasco").

-behaviour(gen_server).

-include("cops.hrl").


%% API
-export([start_link/1]).
-export([decode_file/1, decode_packet/1]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {spec_dec_mod}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link(ClientSpecDec::module()) ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link(ClientSpecDec) ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [ClientSpecDec], []).


decode_file(File)->
  gen_server:call(?SERVER, {decode_file, File}).

decode_packet(Data) ->
  gen_server:call(?SERVER, {decode_packet, Data}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
-spec(init(Args :: term()) ->
  {ok, State :: #state{}} | {ok, State :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term()} | ignore).
init([ClientSpecDec]) ->
  {ok, #state{spec_dec_mod = ClientSpecDec}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_call(Request :: term(), From :: {pid(), Tag :: term()},
    State :: #state{}) ->
  {reply, Reply :: term(), NewState :: #state{}} |
  {reply, Reply :: term(), NewState :: #state{}, timeout() | hibernate} |
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), Reply :: term(), NewState :: #state{}} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_call({decode_file, File}, _From, #state{spec_dec_mod = ClientSpecDec} = State) ->
  {ok, Binary} = file:read_file(File),
  {ok, Header, Objects} = decode_header(Binary),
  Res = [Header, lists:flatten(decode(Objects, ClientSpecDec))],
  {reply, {ok, Res}, State};
handle_call({decode_packet, Data}, _From, #state{spec_dec_mod = ClientSpecDec} = State) ->
  {ok, Header, Objects} = decode_header(Data),
  Res = [Header, lists:flatten(decode(Objects, ClientSpecDec))],
  {reply, {ok, Res}, State}.
%%handle_call(_Request, _From, State) ->
%%  {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_cast(Request :: term(), State :: #state{}) ->
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_cast(_Request, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
-spec(handle_info(Info :: timeout() | term(), State :: #state{}) ->
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_info(_Info, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()),
    State :: #state{}) -> term()).
terminate(_Reason, _State) ->
  ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
-spec(code_change(OldVsn :: term() | {down, term()}, State :: #state{},
    Extra :: term()) ->
  {ok, NewState :: #state{}} | {error, Reason :: term()}).
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
%%decode_file(File)->
%%  {ok, Binary} = file:read_file(File),
%%  {ok, Header, Objects} = decode_header(Binary),
%%  [Header, lists:flatten(decode(Objects))].

decode(<<>>, _) ->
  [];
decode(<<Len:16, CNum:8, CType:8, Rest/bitstring>>, ClientSpecDec) when Rest =/= <<>> ->
  ContentLen=Len-4,
  <<Content:ContentLen/binary, RestNew/binary>> = Rest,
  Obj = #cops_object{length = Len, c_num = CNum, c_type = CType, content = decode_content(CNum, CType, Content, ClientSpecDec)},
  [Obj, decode(RestNew, ClientSpecDec)];
decode(<<Len:16, CNum:8, CType:8, Content/binary>>, ClientSpecDec)  ->
  Obj = #cops_object{length = Len, c_num = CNum, c_type = CType, content = decode_content(CNum, CType, Content, ClientSpecDec)},
  [Obj].


decode_header(<<Ver:4, Flags:4, OpCode:8, ClientType:16, MsgLength:32, Rest/bitstring>>) ->
  {ok, #common_header{version = Ver, flags = Flags, op_code = OpCode, client_type = ClientType, msg_lenght = MsgLength}, Rest}.

decode_content(CNum, CType, Content, ClientSpecDec) ->
  case CNum of
    ?HANDLE -> decode_handle(Content);
    ?CONTEXT -> decode_context(Content);
    ?IN_INT -> decode_interface(CType, Content);
    ?OUT_INT -> decode_interface(CType, Content);
    ?REASON_CODE -> decode_reason(Content);
    ?DECISION -> decode_decision(CType, Content, ClientSpecDec);
    ?LPDP_DECISION -> Content;
    ?ERROR -> decode_error(Content);
    ?KEEP_ALIVE_TIMER -> decode_ka_timer(Content);
    ?PEP_IDENTIFICATION -> decode_pep_id(Content);
    ?REPORT_TYPE -> decode_report_type(Content);
    ?CLIENT_SPECIFIC_INFO -> decode_client_specific(CType, Content, ClientSpecDec);
    _ -> Content
  end.

decode_handle(Content) ->
  #handle{handle = Content}.

decode_context(<<RType:16, MType:16>>) ->
  #context{r_type = RType, m_type = MType}.

decode_decision(CType, Content, ClientSpecDec) ->
  case CType of
    ?DECISION_FLAGS -> <<CommandCode:16, Flags:16>> = Content,
      #decision_flags{command_code = CommandCode, flags = Flags};
    ?DECISION_CLIENT_SPECIFIC -> #client_specific_data{content = lists:flatten(ClientSpecDec:decode(Content))};
    _ -> Content
  end.

decode_interface(CType, Content) ->
  case CType of
    1 -> <<IP4:32, IfIndex:32>> = Content,
      #interface{ip = IP4, ifindex = IfIndex};
    2 -> <<IP6:128, IfIndex:32>> = Content,
      #interface{ip = IP6, ifindex = IfIndex}
  end.

decode_reason(<<Code:16, Subcode:16>>) ->
  #reason{code = Code, sub_code = Subcode}.

decode_error(<<Code:16, Subcode:16>>) ->
  #error{code = Code, sub_code = Subcode}.

decode_report_type(<<ReportType:16, _:16>>) ->
  #report_type{report_type = ReportType}.

decode_pep_id(Context) ->
  #pep_id{pep_id = Context}.

decode_client_specific(_CType, Content, ClientSpecDec) ->
  #client_specific_data{content = lists:flatten(ClientSpecDec:decode(Content))}.

decode_ka_timer(<<_:16, Value:16>>) ->
  #keep_alive_timer{ka_timer_value = Value}.