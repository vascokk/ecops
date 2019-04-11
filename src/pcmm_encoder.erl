-module(pcmm_encoder).
-author("Vasco").

-include("pcmm.hrl").

%% API
-export([encode/1]).

encode(#pcmm_object{s_num = SNum, s_type = SType, content = Content} = Object)->
  ContentBin = case SNum of
                 ?PCMM_VERSION_INFO -> encode_version_info(Content);
                 ?PCMM_TRANSACTION_ID -> encode_transaction_id(Content);
                 ?PCMM_AM_ID -> encode_am_id(Content);
                 ?PCMM_SUBSCRIBER_ID -> encode_subscriber_id(SType, Content);
                 ?PCMM_GATE_SPEC -> encode_gate_spec(Content);
                 ?PCMM_CLASSIFIERS -> encode_classifier(SType, Content);
                 ?PCMM_TRAFFIC_PROFILE -> encode_traffic_profile(SType, Content);
                 ?PCMM_GATE_ID -> encode_gate_id(Content);
                 _ -> Content
               end,
  Len = 4 + size(ContentBin),
  <<Len:16, SNum:8, SType:8, ContentBin/binary>>;
encode(Objects) when is_list(Objects) ->
  list_to_binary( [encode(Obj) || Obj <- Objects] ).

encode_version_info(#version_info{major = Major, minor = Minor}) ->
  <<Major:16, Minor:16>>.

encode_transaction_id(#transaction_id{command_type = CommandType, transaction_id = TransactionId}) ->
  <<TransactionId:16, CommandType:16>>.

encode_am_id(#am_id{app_mgr_tag = AppMgrTag, app_type = AppType}) ->
  <<AppType:16, AppMgrTag:16>>.

encode_subscriber_id(1, #subscriber_id{subscriber_id = SubscriberId}) ->
  <<SubscriberId:32>>;
encode_subscriber_id(2, #subscriber_id{subscriber_id = SubscriberId}) ->
  <<SubscriberId:128>>.

encode_gate_spec(#gate_spec{reserved =  ReservedFlags, dscp_overwrite = DscpOverwrite, gate = Gate,
                            dscp = Dscp, dscp_mask = DscpMask, session_class_id = SessionClassId,
                            t1 = T1, t2 = T2, t3 = T3, t4 = T4}) ->
  <<ReservedFlags:6, DscpOverwrite:1, Gate:1, Dscp:8, DscpMask:8, SessionClassId:8, T1:16, T2:16, T3:16, T4:16>>.

encode_classifier(1, #classifier{protocol_id = ProtocolId,
                                dscp = Dscp,
                                dscp_mask = DscpMask,
                                src_ip_addr = SrcIpAddr,
                                dst_ip_addr = DstIpAddr,
                                src_port = SrcPort,
                                dst_port = DstPort,
                                priority = Priority,
                                reserved = Reserved}) ->
  <<ProtocolId:16, Dscp:8, DscpMask:8, SrcIpAddr:32, DstIpAddr:32, SrcPort:16, DstPort:16, Priority:8, Reserved:24>>;
encode_classifier(2, #extended_classifier{
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
                              }) ->
  <<ProtocolId:16, Dscp:8, DscpMask:8, SrcIpAddr:32, SrcIpMask:32, DstIpAddr:32, DstIpMask:32, SrcPortStart:16, SrcPortEnd:16, DstPortStart:16,
    DstPortEnd:16, ClassifierId:16, Priority:8, ActivationState:8, Action:8, Reserved:24>>;
encode_classifier(3, #ipv6_classifier{
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
                              }) ->
  <<Reserved1:8, Flags:4, TcLow:4, TcHigh:4, TcMask:4, FlowLabel:32, NextHeaderType:16, SrcPrefixLen:8, DstPrefixLen:8, SrcIp:128, DstIp:128, SrcPortStart:16, SrcPortEnd:16, DstPortStart:16,
    DstPortEnd:16, ClassifierId:16, Priority:8, ActivationState:8,  Action:8, Reserved2:24>>.

%%SType=1: FlowSpec
encode_traffic_profile(1, #flow_spec{envelope = Envelope, service_number = ServiceNum, reserved = Reserved, authorized_envelope = AuthEnv, reserved_envelope = ResEnv, commited_envelope = CommEnv}) ->
  Envelopes = list_to_binary([encode_flow_spec_envelope(Env) || Env <- [AuthEnv, ResEnv, CommEnv]]),
  <<Envelope:8, ServiceNum:8, Reserved:16, Envelopes/bitstring>>; %%TODO: check if Envelope value matches the number of envelopes presented
%%SType=2: DOCSIS Service Name
encode_traffic_profile(2, _) ->
  erlang:error(not_implemented);
%%SType = 3: Best Effort
encode_traffic_profile(3, _) ->
  erlang:error(not_implemented);
encode_traffic_profile(_, _) ->
  erlang:error(not_implemented).

encode_flow_spec_envelope({}) ->
  <<>>;
encode_flow_spec_envelope(#flow_spec_envelope{
                              bucket_rate = BucketRate,
                              bucket_size = BucketSize,
                              peak_rate = PeackRate,
                              min_policed_unit = MinPolicedUnit,
                              max_packet_size = MaxPacketSize,
                              rate = Rate,
                              slack_term = SlackTerm
                            }) ->
  <<BucketRate:32/float, BucketSize:32/float, PeackRate:32/float, MinPolicedUnit:32, MaxPacketSize:32, Rate:32/float, SlackTerm:32>>.

encode_gate_id(#gate_id{gate_id = GateId}) when is_binary(GateId) ->
  <<GateId:32/bitstring>>;
encode_gate_id(#gate_id{gate_id = GateId}) when is_integer(GateId) ->
  <<GateId:32>>.