
#include <stdafx.h>


/************************************************************************


FrameParser.c



				Data Link Frame
						|
						|
						|
						|
		-------------------------------------
		|									|
		|									|
	IEEE Frames 						Ethernet Frame
	(non-ethernet frames)						|
		|										|
		|										|
	RawIPX										|

									IPv4,  ARP, RARP, IPX
									  |
									  |
									  |
							-----------------------------
							|		|			|		|
							TCP	   UDP		  ICMP	  IGMP




*************************************************************************/

INT ParseFrame(PUCHAR CurrentFrame_p, UINT CurrentFrameLength, PCURRENT_FRAME FrameAttributes_p,PCHAR TestingString/*last parameter is temporary*/)
{
INT DataLinkFrameType,NetworkFrameType,TransportFrameType, RawIPXFrameType,TransportProtocolType;

TransportProtocolType = RawIPXFrameType = DataLinkFrameType = NetworkFrameType = TransportFrameType = UNKNOWN_FRAMETYPE;


DataLinkFrameType = GetIntFromWord(CurrentFrame_p,DATALINKFRAME_IDENTIFICATION_OFFSET);

	if((DataLinkFrameType > 0) && (DataLinkFrameType < IEEE_FRAME_RANGE))
		{
			RawIPXFrameType = GetIntFromWord(CurrentFrame_p,RAWIPXFRAME_IDENTIFICATION_OFFSET);

			if(RawIPXFrameType == RAWIPX_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
				FrameAttributes_p->ProtocolTree.Network_ProtocolID  = NETWORKPROTOCOL_RAWIPX;
			}
			else
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = IEEE_FRAME;
				}
		}
	else
		{

			if(DataLinkFrameType == IPV4_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_IPV4;
				}

			if(DataLinkFrameType == ARP_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_ARP;
				}

			if(DataLinkFrameType == RARP_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_RARP;
				}
//IPX_ETHERNET_PROTOCOL_STAMP
			if(DataLinkFrameType == IPX_ETHERNET_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_IPX_ETHERNET;
				}
//
		}


	if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_IPV4)
	{
		TransportProtocolType = GetIntFromByte(CurrentFrame_p,ETHERNET_DATA_OFFSET+TRANSPORT_PROTOCOL_IDENTIFICATION_OFFSET);
		
		GetIPAddressForIPv4(CurrentFrame_p,FrameAttributes_p);

		if(TransportProtocolType == TCP_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_TCP;

			}

		if(TransportProtocolType == UDP_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_UDP;
			}

		if(TransportProtocolType == ICMP_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_ICMP;
			}

		if(TransportProtocolType == IGMP_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_IGMP;
			}


	}
	



//	wsprintf(TestingString,"\r\n Byte : %02x",GetIntFromByte(CurrentFrame_p,0));
	DebugPrintOutput(TestingString,FrameAttributes_p);
	return 0;
}


INT GetIntFromWord(PUCHAR TmpFrame_p, INT Offset)
{
	INT iValue;

	iValue = (INT) (0xff & (INT)*(TmpFrame_p + Offset)); //(BYTE)(TmpFrame_p + Offset);
	iValue = iValue << 8;
	iValue = iValue + ((INT) (0xff & (INT)*(TmpFrame_p + Offset+1)));

	return iValue;
}

INT GetIntFromByte(PUCHAR TmpFrame_p, INT Offset)
{
	INT iValue;

	iValue = (INT) (0x000000ff & (INT)*(TmpFrame_p + Offset)); //(BYTE)(TmpFrame_p + Offset);
//	iValue = iValue << 8;
//	iValue = iValue + ((INT) (0xff & (INT)*(TmpFrame_p + Offset+1)));

	return iValue;
}


VOID DebugPrintOutput(PCHAR TmpString,PCURRENT_FRAME FrameAttributes_p)
{
CHAR TmpStr[256];

IN_ADDR	tmpAdd;

lstrcpy(TmpString,"   Packet Details\r\n");
	if(FrameAttributes_p->ProtocolTree.DataLink_ProtocolID == ETHERNET_FRAME)
	{
		lstrcat(TmpString,"\r\n Data-Link Layer Frame Type     :	 Ethernet Frame");
		
		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_IPV4)
		{
				lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 IP Packet");
			if(FrameAttributes_p->ProtocolTree.Transport_ProtocolID != UNKNOWN_FRAMETYPE)
			{

				if(FrameAttributes_p->ProtocolTree.Transport_ProtocolID == TRANSPORTPROTOCOL_TCP)
						lstrcat(TmpString,"\r\n Transport Layer Protocol Type  :	 TCP Protocol");

				if(FrameAttributes_p->ProtocolTree.Transport_ProtocolID == TRANSPORTPROTOCOL_UDP)
						lstrcat(TmpString,"\r\n Transport Layer Protocol Type  :	 UDP Protocol");

				if(FrameAttributes_p->ProtocolTree.Transport_ProtocolID == TRANSPORTPROTOCOL_ICMP)
						lstrcat(TmpString,"\r\n Transport Layer Protocol Type  :	 ICMP Protocol");

				if(FrameAttributes_p->ProtocolTree.Transport_ProtocolID == TRANSPORTPROTOCOL_IGMP)
						lstrcat(TmpString,"\r\n Transport Layer Protocol Type  :	 IGMP Protocol");
			
			tmpAdd.S_un.S_addr = FrameAttributes_p->ulSourceAddress;
			wsprintf(TmpStr,"\r\n Source IP Address		:	 %s",inet_ntoa(tmpAdd));
			lstrcat(TmpString,TmpStr);

			tmpAdd.S_un.S_addr = FrameAttributes_p->ulDestinationAddress;
			wsprintf(TmpStr,"\r\n Destination IP Address		:	 %s",inet_ntoa(tmpAdd));
			lstrcat(TmpString,TmpStr);

			}
			else
				lstrcat(TmpString,"\r\n Transport Layer Protocol Type  :   Unknown Type");
		}

		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_ARP)
					lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 ARP Packet");

		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_RARP)
					lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 RARP Packet");

		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == IPX_ETHERNET_PROTOCOL_STAMP)
					lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 IPX Packet");

	}
		else
		{
		if(FrameAttributes_p->ProtocolTree.DataLink_ProtocolID == IEEE_FRAME)
			lstrcat(TmpString,"\r\n Data-Link Layer Frame Type  :    Non Ethernet Frame");
		}
	


	return;
}


INT GetIPAddressForIPv4(PUCHAR CurrentFrame_p,PCURRENT_FRAME FrameAttributes_p)
{

PIP_HEADER TmpIPHeader;

TmpIPHeader = (IP_HEADER *) (CurrentFrame_p+ETHERNET_DATA_OFFSET);

FrameAttributes_p->ulSourceAddress = TmpIPHeader->ulSourceIP;
FrameAttributes_p->ulDestinationAddress = TmpIPHeader->ulDestinationIP;

return 0;
}

