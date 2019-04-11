-module(pcmm_decoder).
-author("Vasco").

-include("cops.hrl").
-include("pcmm.hrl").

%% API
-export([decode/1]).

decode(<<>>) ->
  [];
decode(<<Len:16, SNum:8, SType:8, Rest/bitstring>>) when Rest =/= <<>> ->
  ContentLen=Len-4,
  <<Content:ContentLen/binary, RestNew/binary>> = Rest,
  Obj = #pcmm_object{length = Len, s_num = SNum, s_type = SType, content = decode_content(SNum, SType, Content)},
  [Obj, decode(RestNew)];
decode(<<Len:16, SNum:8, SType:8, Content/bitstring>>)  ->
  Obj = #pcmm_object{length = Len, s_num = SNum, s_type = SType, content = decode_content(SNum, SType, Content)},
  [Obj].

decode_content(SNum, SType, Content) ->
  case SNum of
    ?PCMM_TRANSACTION_ID -> decode_transaction_id(Content);
    ?PCMM_AM_ID -> decode_am_id(Content);
    ?PCMM_SUBSCRIBER_ID -> decode_subscriber_id(Content);
    ?PCMM_GATE_SPEC -> decode_gate_spec(Content);
    ?PCMM_CLASSIFIERS -> decode_classifier(SType, Content);
    ?PCMM_TRAFFIC_PROFILE -> decode_traffic_profile(SType, Content);
    ?PCMM_VERSION_INFO -> decode_version_info(Content);
    ?PCMM_GATE_ID -> decode_gate_id(Content);
    _ -> Content
  end.



decode_transaction_id(<<TransactionId:16, CommandType:16>>) ->
  #transaction_id{transaction_id = TransactionId, command_type = CommandType}.

decode_am_id(<<AppType:16, AppMgrTag:16>>) ->
  #am_id{app_type = AppType, app_mgr_tag = AppMgrTag}.

decode_subscriber_id(Content) ->
  #subscriber_id{subscriber_id = Content}.

decode_gate_spec(<<ReservedFlags:6, DscpOverwrite:1, Gate:1, Dscp:8, DscpMask:8, SessionClassId:8, T1:16, T2:16, T3:16, T4:16>>) ->
  #gate_spec{reserved =  ReservedFlags, dscp_overwrite = DscpOverwrite, gate = Gate,
             dscp = Dscp, dscp_mask = DscpMask, session_class_id = SessionClassId,
             t1 = T1, t2 = T2, t3 = T3, t4 = T4}.

decode_classifier(1, <<ProtocolId:16, Dscp:8, DscpMask:8, SrcIpAddr:32, DstIpAddr:32, SrcPort:16, DstPort:16, Priority:8, Reserved:24>>) ->
  #classifier{
    protocol_id = ProtocolId,
    dscp = Dscp,
    dscp_mask = DscpMask,
    src_ip_addr = SrcIpAddr,
    dst_ip_addr = DstIpAddr,
    src_port = SrcPort,
    dst_port = DstPort,
    priority = Priority,
    reserved = Reserved
  };
decode_classifier(2, <<ProtocolId:16, Dscp:8, DscpMask:8, SrcIpAddr:32, SrcIpMask:32, DstIpAddr:32, DstIpMask:32, SrcPortStart:16, SrcPortEnd:16, DstPortStart:16,
                       DstPortEnd:16, ClassifierId:16, Priority:8, ActivationState:8, Action:8, Reserved:24>>) ->
  #extended_classifier{
    protocol_id = ProtocolId,
    dscp = Dscp,
    dscp_mask = DscpMask,
    src_ip_adr = SrcIpAddr,
    src_ip_mask = SrcIpMask,
    dst_ip_addr = DstIpAddr,
    dst_ip_mask = DstIpMask,
    src_port_start = SrcPortStart,
    src_port_end = SrcPortEnd,
    dst_port_start = DstPortStart,
    dst_port_end = DstPortEnd,
    classifier_id = ClassifierId,
    priority = Priority,
    activation_state = ActivationState,
    action = Action,
    reserved = Reserved
  };
decode_classifier(3, <<Reserved1:8, Flags:4, TcLow:4, TcHigh:4, TcMask:4, FlowLabel:32, NextHeaderType:16, SrcPrefixLen:8, DstPrefixLen:8, SrcIp:128, DstIp:128, SrcPortStart:16, SrcPortEnd:16, DstPortStart:16,
                       DstPortEnd:16, ClassifierId:16, Priority:8, ActivationState:8,  Action:8, Reserved2:24>>) ->
  #ipv6_classifier{
    reserved_1 = Reserved1,
    flags = Flags,
    tc_low = TcLow,
    tc_high = TcHigh,
    tc_mask = TcMask,
    flow_label = FlowLabel,
    next_header_type = NextHeaderType,
    src_prefix_len = SrcPrefixLen,
    dst_prefix_len = DstPrefixLen,
    src_ip = SrcIp,
    dst_ip = DstIp,
    src_port_start = SrcPortStart,
    src_port_end = SrcPortEnd,
    dst_port_start = DstPortStart,
    dst_port_end = DstPortEnd,
    classifier_id = ClassifierId,
    priority = Priority,
    activation_state = ActivationState,
    action = Action,
    reserved_2 = Reserved2
  }.

%%SType=1: FlowSpec
decode_traffic_profile(1, <<Envelope:8, ServiceNum:8, Reserved:16, Envelopes/bitstring>>) ->
  FS = #flow_spec{envelope = Envelope, service_number = ServiceNum, reserved = Reserved},
  case Envelope of
    1 -> FS#flow_spec{authorized_envelope = decode_flow_spec_envelope(Envelopes)};
    3 -> <<E1:28/binary, E2:28/binary>> = Envelopes,
         FS#flow_spec{authorized_envelope = decode_flow_spec_envelope(E1),
                      reserved_envelope = decode_flow_spec_envelope(E2)};
    7 -> <<E1:28/binary, E2:28/binary, E3:28/binary>> = Envelopes,
         FS#flow_spec{authorized_envelope = decode_flow_spec_envelope(E1),
                      reserved_envelope = decode_flow_spec_envelope(E2),
                      commited_envelope = decode_flow_spec_envelope(E3)};
    _ -> erlang:error(bad_envelope_type)
  end;
%%SType=2: DOCSIS Service Name
decode_traffic_profile(2, _) ->
  erlang:error(not_implemented);
%%SType = 3: Best Effort
decode_traffic_profile(3, _) ->
  erlang:error(not_implemented);
decode_traffic_profile(_, _) ->
  erlang:error(not_implemented).


decode_flow_spec_envelope(<<BucketRate:32/float, BucketSize:32/float, PeackRate:32/float, MinPolicedUnit:32, MaxPacketSize:32, Rate:32/float, SlackTerm:32>>) ->
  #flow_spec_envelope{
    bucket_rate = BucketRate,
    bucket_size = BucketSize,
    peak_rate = PeackRate,
    min_policed_unit = MinPolicedUnit,
    max_packet_size = MaxPacketSize,
    rate = Rate,
    slack_term = SlackTerm
  }.

decode_version_info(<<Major:16, Minor:16>>) ->
  #version_info{
    major = Major,
    minor = Minor
  }.

decode_gate_id(<<GateId:32>>) ->
  #gate_id{gate_id = GateId}.