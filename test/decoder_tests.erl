-module(decoder_tests).
-author("Vasco").

-compile([debug_info, export_all]).

-include_lib("eunit/include/eunit.hrl").
-include("cops.hrl").

decoder_test_() ->
  {setup,
    fun () ->
      %lager:start(),
      %lager:set_loglevel(lager_console_backend, debug),
      application:set_env(cops, client_specific_decoder, pcmm_decoder),
      ok = application:start(cops)
    end,
    fun (_) ->
      %application:stop(lager),
      application:stop(cops)
    end,

    [{"Test Keep-Alive",
        fun decode_KA/0},
      {"Test Open-Client",
        fun decode_OPN/0},
      {"Test Client-Accept",
        fun decode_CAT/0},
      {"Test Decision (Gate-Set",
        fun decode_DEC/0},
      {"Test Report-State (Gate-Set-Ack)",
        fun decode_RPT/0},
      {"Test Request",
        fun decode_REQ/0},
      {"Test Gate-Delete",
        fun decode_DEL/0},
      {"Test Gate-Delete-Ack",
        fun decode_DEL_ACK/0}
    ]
  }.

decode_KA()->
  {ok, Res} =  decoder:decode_file("test/COPS_KA_pdu.bin"),
  ?debugMsg(io_lib:format("Res: ~p~n",[Res])),
  [Header, _] = Res,
  ?assertEqual(1, Header#common_header.version),
  ?assertEqual(?KA, Header#common_header.op_code),
  ?assertEqual(8, Header#common_header.msg_lenght).

decode_OPN()->
  {ok, Res} =  decoder:decode_file("test/COPS_OPN_pdu.bin"),
  ?debugMsg(io_lib:format("Res: ~p~n",[Res])),
  [Header, _Objects] = Res,
  ?assertEqual(1, Header#common_header.version),
  ?assertEqual(?OPN, Header#common_header.op_code),
  ?assertEqual(32778, Header#common_header.client_type),
  ?assertEqual(40, Header#common_header.msg_lenght).

decode_CAT()->
  {ok, Res} =  decoder:decode_file("test/COPS_CAT_pdu.bin"),
  ?debugMsg(io_lib:format("Res: ~p~n",[Res])),
  [Header, _Objects] = Res,
  ?assertEqual(1, Header#common_header.version),
  ?assertEqual(?CAT, Header#common_header.op_code),
  ?assertEqual(32778, Header#common_header.client_type),
  ?assertEqual(16, Header#common_header.msg_lenght).

decode_DEC()->
  {ok, Res} =  decoder:decode_file("test/COPS_DEC_pdu.bin"),
  ?debugMsg(io_lib:format("Res: ~p~n",[Res])),
  [Header, _Objects] = Res,
  ?assertEqual(1, Header#common_header.version),
  ?assertEqual(?DEC, Header#common_header.op_code),
  ?assertEqual(32778, Header#common_header.client_type),
  ?assertEqual(208, Header#common_header.msg_lenght).

decode_RPT()->
  {ok, Res} =  decoder:decode_file("test/COPS_RPT_pdu.bin"),
  ?debugMsg(io_lib:format("Res: ~p~n",[Res])),
  [Header, _Objects] = Res,
  ?assertEqual(1, Header#common_header.version),
  ?assertEqual(?RPT, Header#common_header.op_code),
  ?assertEqual(32778, Header#common_header.client_type),
  ?assertEqual(60, Header#common_header.msg_lenght).

decode_REQ()->
  {ok, Res} =  decoder:decode_file("test/COPS_REQ_pdu.bin"),
  ?debugMsg(io_lib:format("Res: ~p~n",[Res])),
  [Header, _Objects] = Res,
  ?assertEqual(1, Header#common_header.version),
  ?assertEqual(?REQ, Header#common_header.op_code),
  ?assertEqual(32778, Header#common_header.client_type),
  ?assertEqual(24, Header#common_header.msg_lenght).

decode_DEL()->
  {ok, Res} =  decoder:decode_file("test/COPS_DEL_pdu.bin"),
  ?debugMsg(io_lib:format("Res: ~p~n",[Res])),
  [Header, _Objects] = Res,
  ?assertEqual(1, Header#common_header.version),
  ?assertEqual(?DEC, Header#common_header.op_code),
  ?assertEqual(32778, Header#common_header.client_type),
  ?assertEqual(68, Header#common_header.msg_lenght).

decode_DEL_ACK()->
  {ok, Res} =  decoder:decode_file("test/COPS_DEL-ACK_pdu.bin"),
  ?debugMsg(io_lib:format("Res: ~p~n",[Res])),
  [Header, _Objects] = Res,
  ?assertEqual(1, Header#common_header.version),
  ?assertEqual(?RPT, Header#common_header.op_code),
  ?assertEqual(32778, Header#common_header.client_type),
  ?assertEqual(52, Header#common_header.msg_lenght).