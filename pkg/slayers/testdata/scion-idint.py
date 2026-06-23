from pathlib import Path
from datetime import datetime
from scapy_scion.layers.scion import UDP, SCION, SCIONPath, InfoField, HopField, HopByHopExt
from scapy_scion.layers.idint import IdIntOption, IdIntEntry

keys = [
    "byql+EpU2czJMKtRSH8ybA==",
    "6kWxcoeOx7QXW5Ydt9p6Ng==",
    "lE8KhaYBJy5xHIYPdQCLMQ==",
    "lE8KhaYBJy5xHIYPdQCLMQ==",
    "aKlN2XehHJwdhxWv/wbw0A==",
]

scion = SCION(
    qos=32,
    fl=0xf_ffff,
    dst_isd=1,
    dst_asn="ff00:0:1",
    src_isd=2,
    src_asn="ff00:0:2",
    dst_host="10.0.0.1",
    src_host="fd00::2",
    path=SCIONPath(
        curr_inf=1,
        curr_hf=4,
        seg0_len=3,
        seg1_len=2,
        seg2_len=0,
        info_fields=[
            InfoField(flags="", segid=1,
                      timestamp=datetime.fromisoformat("2025-03-25T12:00:00Z")),
            InfoField(flags="C", segid=2,
                      timestamp=datetime.fromisoformat("2025-03-25T12:00:00Z")),
        ],
        hop_fields=[
            HopField(exp_time=0, cons_ingress=0, cons_egress=1),
            HopField(exp_time=0, cons_ingress=2, cons_egress=3),
            HopField(exp_time=0, cons_ingress=4, cons_egress=0),
            HopField(exp_time=255, cons_ingress=0, cons_egress=5),
            HopField(exp_time=255, cons_ingress=6, cons_egress=0),
        ],
    )
)
scion.path.init_path(keys, seeds=[b"\x9d\x53", b"\x69\x91"])

hbh = HopByHopExt(options=[
    IdIntOption(
        flags="encrypted",
        aggregation="border",
        verifier="third_party",
        inst_flags="node_id",
        af1="last",
        af2="last",
        af3="last",
        af4="last",
        inst1="ingress_tstamp",
        inst2="device_type_role",
        source_ts=1000,
        source_port=10,
        vl=3,
        verif_isd=1,
        verif_asn="ff00:0:1",
        verif_host="fd00::1",
        stack_len=30,
        stack=[
            IdIntEntry(flags="source+egress+encrypted", hop=0, nonce=1, mac=4 * b"\xff"),
            IdIntEntry(flags="ingress+egress+encrypted", hop=1, mask="node_id",
                       nonce=2, mac=4 * b"\xff",
                       node_id=2, md1=(3).to_bytes(4, 'big'), md2=(4).to_bytes(2, 'big')),
            IdIntEntry(flags="ingress+encrypted", hop=2, mask="node_id",
                       nonce=3, mac=4 * b"\xff",
                       node_id=1, md1=(1).to_bytes(4, 'big'), md2=(2).to_bytes(2, 'big')),
        ]
    )
])

udp = UDP(
    sport=43000,
    dport=1200,
)

payload = bytes([i % 256 for i in range(1024)])

pkt = scion / hbh / udp / payload
with open(Path(__file__).with_name("scion-idint.bin"), 'wb') as file:
    file.write(bytes(pkt))

hbh_update = HopByHopExt(options=[
    IdIntOption(
        flags="encrypted",
        aggregation="border",
        verifier="third_party",
        inst_flags="node_id",
        af1="last",
        af2="last",
        af3="last",
        af4="last",
        inst1="ingress_tstamp",
        inst2="device_type_role",
        source_ts=1000,
        source_port=10,
        vl=3,
        verif_isd=1,
        verif_asn="ff00:0:1",
        verif_host="fd00::1",
        stack_len=30,
        stack=[
            IdIntEntry(flags="source+egress+encrypted", hop=0, nonce=1, mac=4 * b"\xff"),
            IdIntEntry(flags="ingress+egress+encrypted", hop=1, mask="node_id",
                       nonce=2, mac=4 * b"\xff",
                       node_id=2, md1=(3).to_bytes(4, 'big'), md2=(4).to_bytes(2, 'big')),
            IdIntEntry(flags="ingress+encrypted", hop=2, mask="node_id",
                       nonce=3727165692135864801209549313,
                       mac=(0x79c3515b).to_bytes(4, 'big'),
                       node_id=2298196092,
                       md1=b'\xb33\x0c\xb3',
                       md2=b'Oj')
        ]
    )
])
pkt = scion / hbh_update / udp / payload
with open(Path(__file__).with_name("scion-idint-update.bin"), 'wb') as file:
    file.write(bytes(pkt))

hbh_append = HopByHopExt(options=[
    IdIntOption(
        flags="encrypted",
        aggregation="border",
        verifier="third_party",
        inst_flags="node_id",
        af1="last",
        af2="last",
        af3="last",
        af4="last",
        inst1="ingress_tstamp",
        inst2="device_type_role",
        source_ts=1000,
        source_port=10,
        vl=3,
        verif_isd=1,
        verif_asn="ff00:0:1",
        verif_host="fd00::1",
        stack_len=30,
        stack=[
            IdIntEntry(flags="source+egress+encrypted", hop=0, nonce=1, mac=4 * b"\xff"),
            IdIntEntry(flags="ingress+egress+encrypted", hop=1, mask="node_id",
                       nonce=2, mac=4 * b"\xff",
                       node_id=2, md1=(3).to_bytes(4, 'big'), md2=(4).to_bytes(2, 'big')),
            IdIntEntry(flags="ingress+encrypted", hop=2, mask="node_id",
                       nonce=3, mac=4 * b"\xff",
                       node_id=1, md1=(1).to_bytes(4, 'big'), md2=(2).to_bytes(2, 'big')),
            IdIntEntry(flags="egress+encrypted", hop=3, mask="node_id",
                       nonce=3727165692135864801209549313,
                       mac=(0x9c51d64b).to_bytes(4, 'big'),
                       node_id=2298196093,
                       md1=b'\xb33\x0c\xad',
                       md2=b'Ot')
        ]
    )
])
pkt = scion / hbh_append / udp / payload
with open(Path(__file__).with_name("scion-idint-append.bin"), 'wb') as file:
    file.write(bytes(pkt))

hbh_stack_full = HopByHopExt(options=[
    IdIntOption(
        flags="encrypted+size_exceeded",
        aggregation="border",
        verifier="third_party",
        inst_flags="node_id",
        af1="last",
        af2="last",
        af3="last",
        af4="last",
        inst1="ingress_tstamp",
        inst2="device_type_role",
        source_ts=1000,
        source_port=10,
        vl=3,
        verif_isd=1,
        verif_asn="ff00:0:1",
        verif_host="fd00::1",
        stack_len=30,
        stack=[
            IdIntEntry(flags="source+egress+encrypted", hop=0, nonce=1, mac=4 * b"\xff"),
            IdIntEntry(flags="ingress+egress+encrypted", hop=1, mask="node_id",
                       nonce=2, mac=4 * b"\xff",
                       node_id=2, md1=(3).to_bytes(4, 'big'), md2=(4).to_bytes(2, 'big')),
            IdIntEntry(flags="ingress+encrypted", hop=2, mask="node_id",
                       nonce=3, mac=4 * b"\xff",
                       node_id=1, md1=(1).to_bytes(4, 'big'), md2=(2).to_bytes(2, 'big'))
        ]
    )
])
pkt = scion / hbh_stack_full / udp / payload
with open(Path(__file__).with_name("scion-idint-stack-full.bin"), 'wb') as file:
    file.write(bytes(pkt))
