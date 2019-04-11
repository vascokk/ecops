-module(encoder).
-author("Vasco").

-behaviour(gen_server).

-include("cops.hrl").

%% API
-export([start_link/1, encode/1, pad/1]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {spec_enc_mod}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link(ClientSpecEnc::module()) ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link(ClientSpecEnc) ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [ClientSpecEnc], []).

encode(Data) ->
  gen_server:call(?SERVER, {encode, Data}).

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
init([ClientSpecEnc]) ->
  {ok, #state{spec_enc_mod = ClientSpecEnc}}.

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
handle_call({encode, {Header, Objects}}, _From, #state{spec_enc_mod = ClientSpecEnc} = State) ->
  EncodedObjects = pad( list_to_binary( [encode_object(Obj, ClientSpecEnc) || Obj <- Objects]) ),
  ObjLen = size(EncodedObjects),
  HeaderBin = encode_header(Header, ?HEADER_LEN + ObjLen),
  {reply, {ok, <<HeaderBin/binary, EncodedObjects/binary>>}, State}.
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

%% pad to 4 octets
pad(Dec) when is_integer(Dec)->
  Binary = binary:encode_unsigned(Dec),
  case (4 - size(Binary) rem 4) rem 4 of
    0 -> Dec;
    N -> binary:decode_unsigned(<<Binary/binary, 0:(N*8)>>)
  end;
pad(Binary) when is_binary(Binary)->
  case (4 - size(Binary) rem 4) rem 4 of
    0 -> Binary;
    N -> <<Binary/binary, 0:(N*8)>>
  end.
%% pad to arbitrary length
pad_to(Width, Binary) ->
  case (Width - size(Binary) rem Width) rem Width
  of 0 -> Binary
    ; N -> <<Binary/binary, 0:(N*8)>>
  end.

encode_header(#common_header{version = Ver, flags = Flags, op_code = OpCode, client_type = ClientType}, MsgLength) ->
  <<Ver:4, Flags:4, OpCode:8, ClientType:16, MsgLength:32>>.



encode_object(#cops_object{c_num = CNum, c_type = CType, content = Content}, ClientSpecEnc) ->
  ContentBin = case CNum of
                        ?HANDLE -> encode_handle(Content);
                        ?CONTEXT -> encode_context(Content);
                      %%    ?IN_INT -> encode_interface(CType, Content);
                      %%    ?OUT_INT -> encode_interface(CType, Content);
                      %%    ?REASON_CODE -> encode_reason(Content);
                          ?DECISION -> encode_decision(CType, Content, ClientSpecEnc);
                      %%    ?LPDP_DECISION -> Content;
                      %%    ?ERROR -> encode_error(Content);
                          ?KEEP_ALIVE_TIMER -> encode_ka_timer(Content);
                          ?PEP_IDENTIFICATION -> encode_pep_id(Content);
                          ?REPORT_TYPE -> encode_report_type(Content);
                          ?CLIENT_SPECIFIC_INFO -> encode_client_specific(CType, Content, ClientSpecEnc);
                          _ -> Content
                        end,
  Len = 4 + size(ContentBin),
  <<Len:16, CNum:8, CType:8, ContentBin/binary>>.


encode_handle(#handle{handle = Handle}) ->
  <<Handle/binary>>.

encode_pep_id(#pep_id{pep_id = PepId}) ->
  <<PepId/binary>>.

encode_client_specific(CType, Content, ClientSpecEnc) ->
  Objects = Content#client_specific_data.content,
  EncodedObjects = list_to_binary([ ClientSpecEnc:encode(Obj) || Obj <- Objects]),
  <<EncodedObjects/binary>>.

encode_ka_timer(#keep_alive_timer{ka_timer_value = Value}) ->
  <<0:16, Value:16>>.

encode_context(#context{m_type = MType, r_type = RType}) ->
  <<RType:16, MType:16>>.

encode_decision(CType, Content, ClientSpecEnc) ->
  case CType of
    ?DECISION_FLAGS -> CommandCode = Content#decision_flags.command_code,
                       Flags = Content#decision_flags.flags,
                       <<CommandCode:16, Flags:16>>;
    ?DECISION_CLIENT_SPECIFIC -> ClientSpecEnc:encode(Content#client_specific_data.content);
    _ -> erlang:error(ctype_not_supported)
  end.

encode_report_type(#report_type{report_type = ReportType}) ->
  <<ReportType:16, 0:16 >>.