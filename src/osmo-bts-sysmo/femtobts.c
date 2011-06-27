/* sysmocom femtobts L1 API related definitions */

/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "femtobts.h"

const enum l1prim_type femtobts_l1prim_type[GsmL1_PrimId_NUM] = {
	[GsmL1_PrimId_MphInitReq]	= L1P_T_REQ,
	[GsmL1_PrimId_MphCloseReq]	= L1P_T_REQ,
	[GsmL1_PrimId_MphConnectReq]	= L1P_T_REQ,
	[GsmL1_PrimId_MphDisconnectReq]	= L1P_T_REQ,
	[GsmL1_PrimId_MphActivateReq]	= L1P_T_REQ,
	[GsmL1_PrimId_MphDeactivateReq]	= L1P_T_REQ,
	[GsmL1_PrimId_MphConfigReq]	= L1P_T_REQ,
	[GsmL1_PrimId_MphMeasureReq]	= L1P_T_REQ,
	[GsmL1_PrimId_MphInitCnf]	= L1P_T_CONF,
	[GsmL1_PrimId_MphCloseCnf]	= L1P_T_CONF,
	[GsmL1_PrimId_MphConnectCnf]	= L1P_T_CONF,
	[GsmL1_PrimId_MphDisconnectCnf]	= L1P_T_CONF,
	[GsmL1_PrimId_MphActivateCnf]	= L1P_T_CONF,
	[GsmL1_PrimId_MphDeactivateCnf]	= L1P_T_CONF,
	[GsmL1_PrimId_MphConfigCnf]	= L1P_T_CONF,
	[GsmL1_PrimId_MphMeasureCnf]	= L1P_T_CONF,
	[GsmL1_PrimId_MphTimeInd]	= L1P_T_IND,
	[GsmL1_PrimId_MphSyncInd]	= L1P_T_IND,
	[GsmL1_PrimId_PhEmptyFrameReq]	= L1P_T_REQ,
	[GsmL1_PrimId_PhDataReq]	= L1P_T_REQ,
	[GsmL1_PrimId_PhConnectInd]	= L1P_T_IND,
	[GsmL1_PrimId_PhReadyToSendInd]	= L1P_T_IND,
	[GsmL1_PrimId_PhDataInd]	= L1P_T_IND,
	[GsmL1_PrimId_PhRaInd]		= L1P_T_IND,
};

const struct value_string femtobts_l1prim_names[GsmL1_PrimId_NUM+1] = {
	{ GsmL1_PrimId_MphInitReq,	"MPH-INIT.req" },
	{ GsmL1_PrimId_MphCloseReq,	"MPH-CLOSE.req" },
	{ GsmL1_PrimId_MphConnectReq,	"MPH-CONNECT.req" },
	{ GsmL1_PrimId_MphDisconnectReq,"MPH-DISCONNECT.req" },
	{ GsmL1_PrimId_MphActivateReq,	"MPH-ACTIVATE.req" },
	{ GsmL1_PrimId_MphDeactivateReq,"MPH-DEACTIVATE.req" },
	{ GsmL1_PrimId_MphConfigReq,	"MPH-CONFIG.req" },
	{ GsmL1_PrimId_MphMeasureReq,	"MPH-MEASURE.req" },
	{ GsmL1_PrimId_MphInitCnf,	"MPH-INIT.conf" },
	{ GsmL1_PrimId_MphCloseCnf,	"MPH-CLOSE.conf" },
	{ GsmL1_PrimId_MphConnectCnf,	"MPH-CONNECT.conf" },
	{ GsmL1_PrimId_MphDisconnectCnf,"MPH-DISCONNECT.conf" },
	{ GsmL1_PrimId_MphActivateCnf,	"MPH-ACTIVATE.conf" },
	{ GsmL1_PrimId_MphDeactivateCnf,"MPH-DEACTIVATE.conf" },
	{ GsmL1_PrimId_MphConfigCnf,	"MPH-CONFIG.conf" },
	{ GsmL1_PrimId_MphMeasureCnf,	"MPH-MEASURE.conf" },
	{ GsmL1_PrimId_MphTimeInd,	"MPH-TIME.ind" },
	{ GsmL1_PrimId_MphSyncInd,	"MPH-SYNC.ind" },
	{ GsmL1_PrimId_PhEmptyFrameReq,	"PH-EMPTY_FRAME.req" },
	{ GsmL1_PrimId_PhDataReq,	"PH-DATA.req" },
	{ GsmL1_PrimId_PhConnectInd,	"PH-CONNECT.ind" },
	{ GsmL1_PrimId_PhReadyToSendInd,"PH-READY_TO_SEND.ind" },
	{ GsmL1_PrimId_PhDataInd,	"PH-DATA.ind" },
	{ GsmL1_PrimId_PhRaInd,		"PH-RA.ind" },
	{ 0, NULL }
};

const GsmL1_PrimId_t femtobts_l1prim_req2conf[GsmL1_PrimId_NUM] = {
	[GsmL1_PrimId_MphInitReq]	= GsmL1_PrimId_MphInitCnf,
	[GsmL1_PrimId_MphCloseReq]	= GsmL1_PrimId_MphCloseCnf,
	[GsmL1_PrimId_MphConnectReq]	= GsmL1_PrimId_MphConnectCnf,
	[GsmL1_PrimId_MphDisconnectReq]	= GsmL1_PrimId_MphDisconnectCnf,
	[GsmL1_PrimId_MphActivateReq]	= GsmL1_PrimId_MphActivateCnf,
	[GsmL1_PrimId_MphDeactivateReq]	= GsmL1_PrimId_MphDeactivateCnf,
	[GsmL1_PrimId_MphConfigReq]	= GsmL1_PrimId_MphConfigCnf,
	[GsmL1_PrimId_MphMeasureReq]	= GsmL1_PrimId_MphMeasureCnf,
};

const enum l1prim_type femtobts_sysprim_type[FemtoBts_PrimId_NUM] = {
	[FemtoBts_PrimId_SystemInfoReq]		= L1P_T_REQ,
	[FemtoBts_PrimId_SystemInfoCnf]		= L1P_T_CONF,
	[FemtoBts_PrimId_SystemFailureInd]	= L1P_T_IND,
	[FemtoBts_PrimId_ActivateRfReq]		= L1P_T_REQ,
	[FemtoBts_PrimId_ActivateRfCnf]		= L1P_T_CONF,
	[FemtoBts_PrimId_DeactivateRfReq]	= L1P_T_REQ,
	[FemtoBts_PrimId_DeactivateRfCnf]	= L1P_T_CONF,
	[FemtoBts_PrimId_SetTraceFlagsReq]	= L1P_T_REQ,
	[FemtoBts_PrimId_RfClockInfoReq]	= L1P_T_REQ,
	[FemtoBts_PrimId_RfClockInfoCnf]	= L1P_T_CONF,
	[FemtoBts_PrimId_RfClockSetupReq]	= L1P_T_REQ,
	[FemtoBts_PrimId_RfClockSetupCnf]	= L1P_T_CONF,
	[FemtoBts_PrimId_Layer1ResetReq]	= L1P_T_REQ,
	[FemtoBts_PrimId_Layer1ResetCnf]	= L1P_T_CONF,
};

const struct value_string femtobts_sysprim_names[FemtoBts_PrimId_NUM+1] = {
	{ FemtoBts_PrimId_SystemInfoReq,	"SYSTEM-INFO.req" },
	{ FemtoBts_PrimId_SystemInfoCnf,	"SYSTEM-INFO.conf" },
	{ FemtoBts_PrimId_SystemFailureInd,	"SYSTEM-FAILURE.ind" },
	{ FemtoBts_PrimId_ActivateRfReq,	"ACTIVATE-RF.req" },
	{ FemtoBts_PrimId_ActivateRfCnf,	"ACTIVATE-RF.conf" },
	{ FemtoBts_PrimId_DeactivateRfReq,	"DEACTIVATE-RF.req" },
	{ FemtoBts_PrimId_DeactivateRfCnf,	"DEACTIVATE-RF.conf" },
	{ FemtoBts_PrimId_SetTraceFlagsReq,	"SET-TRACE-FLAGS.req" },
	{ FemtoBts_PrimId_RfClockInfoReq,	"RF-CLOCK-INFO.req" },
	{ FemtoBts_PrimId_RfClockInfoCnf,	"RF-CLOCK-INFO.conf" },
	{ FemtoBts_PrimId_RfClockSetupReq,	"RF-CLOCK-SETUP.req" },
	{ FemtoBts_PrimId_RfClockSetupCnf,	"RF-CLOCK-SETUP.conf" },
	{ FemtoBts_PrimId_Layer1ResetReq,	"LAYER1-RESET.req" },
	{ FemtoBts_PrimId_Layer1ResetCnf,	"LAYER1-RESET.conf" },
	{ 0, NULL }
};

const FemtoBts_PrimId_t femtobts_sysprim_req2conf[FemtoBts_PrimId_NUM] = {
	[FemtoBts_PrimId_SystemInfoReq]	= FemtoBts_PrimId_SystemInfoCnf,
	[FemtoBts_PrimId_ActivateRfReq]	= FemtoBts_PrimId_ActivateRfCnf,
	[FemtoBts_PrimId_DeactivateRfReq] = FemtoBts_PrimId_DeactivateRfCnf,
	[FemtoBts_PrimId_RfClockInfoReq] = FemtoBts_PrimId_RfClockInfoCnf,
	[FemtoBts_PrimId_RfClockSetupReq] = FemtoBts_PrimId_RfClockSetupCnf,
	[FemtoBts_PrimId_Layer1ResetReq] = FemtoBts_PrimId_Layer1ResetCnf,
};

const struct value_string femtobts_l1sapi_names[GsmL1_Sapi_NUM+1] = {
	{ GsmL1_Sapi_Fcch,	"FCCH" },
	{ GsmL1_Sapi_Sch,	"SCH" },
	{ GsmL1_Sapi_Sacch,	"SACCH" },
	{ GsmL1_Sapi_Sdcch,	"SDCCH" },
	{ GsmL1_Sapi_Bcch,	"BCCH" },
	{ GsmL1_Sapi_Pch,	"PCH" },
	{ GsmL1_Sapi_Agch,	"AGCH" },
	{ GsmL1_Sapi_Cbch,	"CBCH" },
	{ GsmL1_Sapi_Rach,	"RACH" },
	{ GsmL1_Sapi_TchF,	"TCH/F" },
	{ GsmL1_Sapi_FacchF,	"FACCH/F" },
	{ GsmL1_Sapi_TchH,	"TCH/H" },
	{ GsmL1_Sapi_FacchH,	"FACCH/H" },
	{ GsmL1_Sapi_Nch,	"NCH" },
	{ GsmL1_Sapi_Pdtch,	"PDTCH" },
	{ GsmL1_Sapi_Pacch,	"PACCH" },
	{ GsmL1_Sapi_Pbcch,	"PBCCH" },
	{ GsmL1_Sapi_Pagch,	"PAGCH" },
	{ GsmL1_Sapi_Ppch,	"PPCH" },
	{ GsmL1_Sapi_Pnch,	"PNCH" },
	{ GsmL1_Sapi_Ptcch,	"PTCCH" },
	{ GsmL1_Sapi_Prach,	"PRACH" },
	{ 0, NULL }
};

const struct value_string femtobts_l1status_names[GSML1_STATUS_NUM+1] = {
	{ GsmL1_Status_Success,		"Success" },
	{ GsmL1_Status_Generic,		"Generic error" },
	{ GsmL1_Status_NoMemory,	"Not enough memory" },
	{ GsmL1_Status_Timeout,		"Timeout" },
	{ GsmL1_Status_InvalidParam,	"Invalid parameter" },
	{ GsmL1_Status_Busy,		"Resource busy" },
	{ GsmL1_Status_NoRessource,	"No more resources" },
	{ GsmL1_Status_Uninitialized,	"Trying to use uninitialized resource" },
	{ GsmL1_Status_NullInterface,	"Trying to call a NULL interface" },
	{ GsmL1_Status_NullFctnPtr,	"Trying to call a NULL function ptr" },
	{ GsmL1_Status_BadCrc,		"Bad CRC" },
	{ GsmL1_Status_BadUsf,		"Bad USF" },
	{ GsmL1_Status_InvalidCPS,	"Invalid CPS field" },
	{ GsmL1_Status_UnexpectedBurst,	"Unexpected burst" },
	{ GsmL1_Status_UnavailCodec,	"AMR codec is unavailable" },
	{ GsmL1_Status_CriticalError,	"Critical error" },
	{ GsmL1_Status_OverheatError,	"Overheat error" },
	{ GsmL1_Status_DeviceError,	"Device error" },
	{ GsmL1_Status_FacchError,	"FACCH / TCH order error" },
	{ GsmL1_Status_AlreadyDeactivated, "Lchan already deactivated" },
	{ GsmL1_Status_TxBurstFifoOvrn,	"FIFO overrun" },
	{ GsmL1_Status_TxBurstFifoUndr,	"FIFO underrun" },
	{ GsmL1_Status_NotSynchronized,	"Not synchronized" },
	{ GsmL1_Status_Unsupported,	"Unsupported feature" },
	{ 0, NULL }
};
