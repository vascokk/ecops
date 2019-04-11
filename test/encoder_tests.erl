-module(encoder_tests).
-author("Vasco").
-compile([debug_info, export_all]).

-include_lib("eunit/include/eunit.hrl").
-include("cops.hrl").
-include("pcmm.hrl").


encoder_test_() ->
  {setup,
    fun () ->
      %lager:start(),
      %lager:set_loglevel(lager_console_backend, debug),
      application:set_env(cops, client_specific_encoder, pcmm_encoder),
      ok = application:start(cops)
    end,
    fun (_) ->
      %application:stop(lager),
      application:stop(cops)
    end,

    [{"Test Keep-Alive",
      fun encode_KA/0},
      {"Test Open-Client",
        fun encode_OPN/0},
      {"Test Client-Accept",
        fun encode_CAT/0},
      {"Test Decision",
        fun encode_DEC/0},
      {"Test Report-State",
        fun encode_RPT/0},
      {"Test Request",
        fun decode_REQ/0},
      {"Test Gate-Delete",
        fun encode_DEL/0},
      {"Test Gate-Delete-Ack",
        fun encode_DEL_ACK/0}
    ]
  }.

encode_KA() ->
  File = "test/COPS_KA_pdu.bin",
  H = #common_header{
    op_code = ?KA
  },
  {ok, Result} = encoder:encode({H, []}),
  ?assertEqual(read_file(File), Result).

encode_OPN()->
  File = "test/COPS_OPN_pdu.bin",
  H = #common_header{
    op_code = ?OPN,
    client_type = ?CLIENT_TYPE_PCMM
  },

  PEPID = #cops_object{
    c_num = ?PEP_IDENTIFICATION,
    c_type = 1,
    content = #pep_id{ pep_id = <<49,56,49,46,50,49,51,46,50,49,49,46,49,57,55,0>>}
  },
  Version = #cops_object{
                c_num = ?CLIENT_SPECIFIC_INFO,
                c_type = 1,
                content = #client_specific_data{
                  content = [#pcmm_object{
                                  s_num = 16,
                                  s_type = 1,
                                  content = #version_info{major = 4, minor = 0}
                            }]}},

  {ok, Result} = encoder:encode({H, [PEPID, Version]}),
  ?assertEqual(read_file(File), Result).

encode_CAT()->
  File = "test/COPS_CAT_pdu.bin",
  H = #common_header{
    op_code = ?CAT,
    client_type = ?CLIENT_TYPE_PCMM
  },

  KAT = #cops_object{
    c_num = ?KEEP_ALIVE_TIMER,
    c_type = 1,
    content = #keep_alive_timer{ka_timer_value = 30}},

  {ok, Result} = encoder:encode({H, [KAT]}),
  ?assertEqual(read_file(File), Result).

encode_DEC()->
  File = "test/COPS_DEC_pdu.bin",
  H = #common_header{
    op_code = ?DEC,
    client_type = ?CLIENT_TYPE_PCMM
  },

  Handle = #cops_object{
    c_num = 1, c_type = 1,
    content = #handle{handle = <<15,78,15,78>>}
  },
  Context = #cops_object{
    c_num = 2, c_type = 1,
    content = #context{r_type = 8, m_type = 0}
  },
  DecFlags = #cops_object{
    c_num = 6, c_type = 1,
    content = #decision_flags{command_code = 1, flags = 0}
    },
  ClientSpecData = #cops_object{
    c_num = 6, c_type = 4,
    content = #client_specific_data{content = [
      #pcmm_object{s_num = 1, s_type = 1, content = #transaction_id{transaction_id = 1, command_type = 4}},
      #pcmm_object{s_num = 2, s_type = 1, content = #am_id{app_type = 0, app_mgr_tag = 22136}},
      #pcmm_object{s_num = 3, s_type = 1, content = #subscriber_id{subscriber_id = 16#B5D5D563}},
      #pcmm_object{s_num = 5, s_type = 1, content = #gate_spec{dscp = 0,dscp_mask = 0,dscp_overwrite = 0,gate = 0,reserved = 0,session_class_id = 1,t1 = 0,t2 = 0, t3 = 0,t4 = 0}},
      #pcmm_object{s_num = 6, s_type = 2, content = #extended_classifier{
                                                          protocol_id = 17,
                                                          dscp = 0,
                                                          dscp_mask = 0,
                                                          src_ip_adr = 3372172032,
                                                          src_ip_mask = 4294967040,
                                                          dst_ip_addr = 3050689792,
                                                          dst_ip_mask = 4294967040,
                                                          src_port_start = 0,
                                                          src_port_end = 65535,
                                                          dst_port_start = 0,
                                                          dst_port_end = 65535,
                                                          classifier_id = 1,
                                                          priority = 64,
                                                          activation_state = 1,
                                                          action = 0,
                                                          reserved = 0
                                                        }},
      #pcmm_object{s_num = 7, s_type = 1, content = #flow_spec{envelope = 7, service_number = 5,
        authorized_envelope = #flow_spec_envelope{
          bucket_rate = 0.0,
          bucket_size = 365.0,
          peak_rate = 18250.0,
          min_policed_unit = 365,
          max_packet_size = 365,
          rate = 18250.0,
          slack_term = 800
        },
        reserved_envelope = #flow_spec_envelope{
          bucket_rate = 0.0,
          bucket_size = 365.0,
          peak_rate = 18250.0,
          min_policed_unit = 365,
          max_packet_size = 365,
          rate = 18250.0,
          slack_term = 800
        },
        commited_envelope = #flow_spec_envelope{
          bucket_rate = 0.0,
          bucket_size = 365.0,
          peak_rate = 18250.0,
          min_policed_unit = 365,
          max_packet_size = 365,
          rate = 18250.0,
          slack_term = 800
        }}}


    ]}
  },

  {ok, Result} = encoder:encode({H, [Handle, Context, DecFlags, ClientSpecData]}),
  ?assertEqual(read_file(File), Result).

encode_RPT() ->
  File = "test/COPS_RPT_pdu.bin",
  H = #common_header{
    flags = 1,
    op_code = ?RPT,
    client_type = ?CLIENT_TYPE_PCMM
  },

  Handle = #cops_object{
    c_num = 1, c_type = 1,
    content = #handle{handle = <<15,78,15,78>>}
  },


  ReportType = #cops_object{
    c_num = 12, c_type = 1,
    content = #report_type{report_type = 1}
  },

  ClientSpecData = #cops_object{
    c_num = 9, c_type = 1,
    content = #client_specific_data{content = [
      #pcmm_object{s_num = 1, s_type = 1, content = #transaction_id{transaction_id = 1, command_type = 5}},
      #pcmm_object{s_num = 2, s_type = 1, content = #am_id{app_type = 0, app_mgr_tag = 22136}},
      #pcmm_object{s_num = 3, s_type = 1, content = #subscriber_id{subscriber_id = 16#B5D5D563}},
      #pcmm_object{s_num = 4, s_type = 1, content = #gate_id{gate_id = <<189,159,0,87>>}} %%16#bd9f0057
    ]}},
  {ok, Result} = encoder:encode({H, [Handle, ReportType, ClientSpecData]}),
  ?assertEqual(read_file(File), Result).

read_file(File) ->
  {ok, Binary} = file:read_file(File),
  Binary.

decode_REQ() ->
  File = "test/COPS_REQ_pdu.bin",
  H = #common_header{
    op_code = ?REQ,
    client_type = ?CLIENT_TYPE_PCMM
  },

  Handle = #cops_object{
    c_num = 1, c_type = 1,
    content = #handle{handle = <<15,78,15,78>>}
  },
  Context = #cops_object{
    c_num = 2, c_type = 1,
    content = #context{r_type = 8, m_type = 0}
  },
  {ok, Result} = encoder:encode({H, [Handle, Context]}),
  ?assertEqual(read_file(File), Result).

pad_test() ->
  ?assertEqual(  <<2,0,0,0>>, encoder:pad(<<2>>)),
%%  %%?assertEqual(  binary:encode_unsigned(1711276032), encoder:pad(binary:encode_unsigned(102))).
  ?assertEqual(  1711276032, encoder:pad(102)). %% 0110 0110 to 0110 0110 0000 0000 0000 0000 0000 0000


encode_DEL() ->
  File = "test/COPS_DEL_pdu.bin",
  H = #common_header{
    op_code = ?DEC,
    client_type = ?CLIENT_TYPE_PCMM
  },

  Handle = #cops_object{
    c_num = 1, c_type = 1,
    content = #handle{handle = <<15,78,15,78>>}
  },
  Context = #cops_object{
    c_num = 2, c_type = 1,
    content = #context{r_type = 8, m_type = 0}
  },
  DecFlags = #cops_object{
    c_num = 6, c_type = 1,
    content = #decision_flags{command_code = 1, flags = 0}
  },
  ClientSpecData = #cops_object{
    c_num = 6, c_type = 4,
    content = #client_specific_data{content = [
      #pcmm_object{s_num = 1, s_type = 1, content = #transaction_id{transaction_id = 1, command_type = 10}},
      #pcmm_object{s_num = 2, s_type = 1, content = #am_id{app_type = 0, app_mgr_tag = 22136}},
      #pcmm_object{s_num = 3, s_type = 1, content = #subscriber_id{subscriber_id = 16#B5D5D563}},
      #pcmm_object{s_num = 4, s_type = 1, content = #gate_id{gate_id = <<189,159,0,87>>}} %%16#bd9f0057
    ]}
  },

  {ok, Result} = encoder:encode({H, [Handle, Context, DecFlags, ClientSpecData]}),
  ?assertEqual(read_file(File), Result).


encode_DEL_ACK() ->
  File = "test/COPS_DEL-ACK_pdu.bin",
  H = #common_header{
    flags = 1,
    op_code = ?RPT,
    client_type = ?CLIENT_TYPE_PCMM
  },

  Handle = #cops_object{
    c_num = 1, c_type = 1,
    content = #handle{handle = <<15,78,15,78>>}
  },


  ReportType = #cops_object{
    c_num = 12, c_type = 1,
    content = #report_type{report_type = 1}
  },

  ClientSpecData = #cops_object{
    c_num = 9, c_type = 1,
    content = #client_specific_data{content = [
      #pcmm_object{s_num = 1, s_type = 1, content = #transaction_id{transaction_id = 1, command_type = 11}},
      #pcmm_object{s_num = 2, s_type = 1, content = #am_id{app_type = 0, app_mgr_tag = 22136}},
      #pcmm_object{s_num = 4, s_type = 1, content = #gate_id{gate_id = <<189,159,0,87>>}} %%16#bd9f0057
    ]}},
  {ok, Result} = encoder:encode({H, [Handle, ReportType, ClientSpecData]}),
  ?assertEqual(read_file(File), Result).