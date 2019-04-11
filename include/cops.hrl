-author("Vasco").

-define(HEADER_LEN, 8).

-define(CLIENT_TYPE_PCMM, 32778).

%% Commands
%%1 = Request                 (REQ)
%%2 = Decision                (DEC)
%%3 = Report State            (RPT)
%%4 = Delete Request State    (DRQ)
%%5 = Synchronize State Req   (SSQ)
%%6 = Client-Open             (OPN)
%%7 = Client-Accept           (CAT)
%%8 = Client-Close            (CC)
%%9 = Keep-Alive              (KA)
%%10= Synchronize Complete    (SSC)
-define(REQ, 1).
-define(DEC, 2).
-define(RPT, 3).
-define(DRQ, 4).
-define(SSQ, 5).
-define(OPN, 6).
-define(CAT, 7).
-define(CC, 8).
-define(KA, 9).
-define(SSC, 10).


%% COPS Objects
-define(HANDLE, 1).
-define(CONTEXT, 2).
-define(IN_INT, 3).
-define(OUT_INT, 4).
-define(REASON_CODE, 5).
-define(DECISION, 6).
-define(LPDP_DECISION, 7).
-define(ERROR, 8).
-define(CLIENT_SPECIFIC_INFO, 9).
-define(KEEP_ALIVE_TIMER, 10).
-define(PEP_IDENTIFICATION, 11).
-define(REPORT_TYPE, 12).
-define(PDP_REDIRECT_ADDRESS, 13).
-define(LAST_PDP_ADDRESS, 14).
-define(ACCOUNTING_TIMER, 15).
-define(MESSAGE_INTEGRITY, 16).

%%CType for Decision objects (CNum=6)
-define(DECISION_FLAGS, 1).
-define(DECISION_STATELESS_DATA, 2).
-define(DECISION_REPLACEMENT_DATA, 3).
-define(DECISION_CLIENT_SPECIFIC, 4).
-define(DECISION_NAMED_DECISION, 5).


-record(common_header, {
  version = 1,
  flags = 0,
  op_code,
  client_type = 0,
  msg_lenght
}).

-record(cops_object, {
  length,
  c_num,
  c_type,
  content
}).

-record(handle,{
  handle
}).

-record(context,{
  r_type,
  m_type
}).

-record(decision_flags,{
  command_code,
  flags
}).

-record(client_specific_data,{
  content
}).

-record(interface,{
  ip,
  ifindex
}).

-record(reason,{
  code,
  sub_code
}).

-record(error,{
  code,
  sub_code
}).

-record(report_type,{
  report_type
}).

-record(pep_id, {
  pep_id
}).

-record(keep_alive_timer,{
  ka_timer_value
}).
