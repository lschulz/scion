package idint

// ID-INT verifier types
const (
	VfThirdParty = 0
	VfDst        = 1
	VfSrc        = 2
)

// ID-INT aggregation modes
const (
	AgOff = 0
	AgAS  = 1
	AgBR  = 2
	AgRtr = 3
)

// ID-INT aggregation functions
const (
	AfFirst = 0
	AfLast  = 1
	AfMin   = 2
	AfMax   = 3
	AfSum   = 4
)

// ID-INT instruction bitmap
const (
	NodeId  uint8 = 0x08
	NodeCnt uint8 = 0x04
	IgPort  uint8 = 0x02
	EgPort  uint8 = 0x01
)

// ID-INT instructions
const (
	InNop              = 0x00
	InIsd              = 0x01
	InBrLinkType       = 0x02
	InDeviceTypeRole   = 0x03
	InCpuMemUsage      = 0x04
	InCpuTemp          = 0x05
	InAsicTemp         = 0x06
	InFanSpeed         = 0x07
	InTotalPower       = 0x08
	InEnergyMix        = 0x09
	InDeviceVendor     = 0x41
	InDeviceModel      = 0x42
	InSoftwareVersion  = 0x43
	InNodeIpv4Addr     = 0x44
	InIngressPortSpeed = 0x45
	InEgressPortSpeed  = 0x46
	InGpsLat           = 0x47
	InGpsLong          = 0x48
	InUptime           = 0x49
	InRttNextBr        = 0x4A
	InRttPrevBr        = 0x4B
	InIngressLinkRx    = 0x4C
	InIngressLinkTx    = 0x4D
	InEgressLinkRx     = 0x4E
	InEgressLinkTx     = 0x4F
	InQueueId          = 0x50
	InInstQueueLen     = 0x51
	InAvgQueueLen      = 0x52
	InBufferId         = 0x53
	InInstBufferOcc    = 0x54
	InAvgBufferOcc     = 0x55
	InFwdEnergy        = 0x56
	InCo2Emission      = 0x57
	InAsn              = 0x81
	InIngressTstamp    = 0x82
	InEgressTstamp     = 0x83
	InIgBrIfRxPkts     = 0x84
	InIgBrIfRxBytes    = 0x85
	InIgBrIfRxDropped  = 0x86
	InIgBrIfTxPkts     = 0x87
	InIgBrIfTxBytes    = 0x88
	InIgBrIfTxDropped  = 0x89
	InEgBrIfRxPkts     = 0x8A
	InEgBrIfRxBytes    = 0x8B
	InEgBrIfRxDropped  = 0x8C
	InEgBrIfTxPkts     = 0x8D
	InEgBrIfTxBytes    = 0x8E
	InEgBrIfTxDropped  = 0x8F
	InIgPortRxPkts     = 0x90
	InIgPortRxBytes    = 0x91
	InIgPortRxDropped  = 0x92
	InIgPortTxPkts     = 0x93
	InIgPortTxBytes    = 0x94
	InIgPortTxDropped  = 0x95
	InEgPortRxPkts     = 0x96
	InEgPortRxBytes    = 0x97
	InEgPortRxDropped  = 0x98
	InEgPortTxPkts     = 0x99
	InEgPortTxBytes    = 0x9A
	InEgPortTxDropped  = 0x9B
	InNodeIpv6AddrH    = 0xC1
	InNodeIpv6AddrL    = 0xC2
)
