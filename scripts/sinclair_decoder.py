#!/usr/bin/env python3
"""Sinclair Gree AC packet decoder for TX and RX frames.

Usage:
  python scripts/sinclair_decoder.py "7E 7E 2F 01 ..."
  python scripts/sinclair_decoder.py --file log.txt

The script accepts a single hex frame or a file with multiple lines containing
hex dumps (it will try to extract frames from each line).
"""
from __future__ import annotations
import sys
import re
from typing import List, Tuple


def parse_hex_bytes(s: str) -> List[int]:
    # accept 7E.7E.2F.01 or 7E 7E 2F 01 or 7E7E2F01 etc
    s = s.strip()
    # remove common prefixes
    s = s.replace('.', ' ').replace(',', ' ')
    # find hex byte sequences
    parts = re.findall(r"[0-9A-Fa-f]{2}", s)
    return [int(p, 16) for p in parts]


# Protocol constants (copied/adapted from esppac_cnt.h)
class Protocol:
    SYNC = 0x7E
    CMD_IN_UNIT_REPORT = 0x31
    CMD_OUT_PARAMS_SET = 0x01
    SET_PACKET_LEN = 45

    REPORT_PWR_BYTE = 4
    REPORT_PWR_MASK = 0b10000000
    REPORT_MODE_BYTE = 4
    REPORT_MODE_MASK = 0b01110000
    REPORT_MODE_POS = 4
    REPORT_MODE_AUTO = 0
    REPORT_MODE_COOL = 1
    REPORT_MODE_DRY = 2
    REPORT_MODE_FAN = 3
    REPORT_MODE_HEAT = 4

    REPORT_FAN_SPD1_BYTE = 18
    REPORT_FAN_SPD1_MASK = 0b00001111
    REPORT_FAN_SPD1_POS = 0
    REPORT_FAN_SPD2_BYTE = 4
    REPORT_FAN_SPD2_MASK = 0b00000011
    REPORT_FAN_SPD2_POS = 0
    REPORT_FAN_QUIET_BYTE = 16
    REPORT_FAN_QUIET_MASK = 0b00001000
    REPORT_FAN_TURBO_BYTE = 6
    REPORT_FAN_TURBO_MASK = 0b00000001

    REPORT_TEMP_SET_BYTE = 5
    REPORT_TEMP_SET_MASK = 0b11110000
    REPORT_TEMP_SET_POS = 4
    REPORT_TEMP_SET_OFF = 16

    REPORT_TEMP_ACT_BYTE = 42
    REPORT_TEMP_ACT_OFF = 16
    REPORT_TEMP_ACT_DIV = 2.0

    REPORT_HSWING_BYTE = 8
    REPORT_HSWING_MASK = 0b00000111
    REPORT_HSWING_POS = 0

    REPORT_VSWING_BYTE = 8
    REPORT_VSWING_MASK = 0b11110000
    REPORT_VSWING_POS = 4

    REPORT_DISP_ON_BYTE = 6
    REPORT_DISP_ON_MASK = 0b00000010
    REPORT_DISP_MODE_BYTE = 9
    REPORT_DISP_MODE_MASK = 0b00110000
    REPORT_DISP_MODE_POS = 4
    REPORT_DISP_F_BYTE = 7
    TEMREC_MASK = 0b01000000
    REPORT_DISP_F_MASK = 0b10000000

    REPORT_PLASMA1_BYTE = 6
    REPORT_PLASMA1_MASK = 0b00000100
    REPORT_PLASMA2_BYTE = 0
    REPORT_PLASMA2_MASK = 0b00000100

    REPORT_SLEEP_BYTE = 4
    REPORT_SLEEP_MASK = 0b00001000
    REPORT_XFAN_BYTE = 6
    REPORT_XFAN_MASK = 0b00001000
    REPORT_SAVE_BYTE = 11
    REPORT_SAVE_MASK = 0b01000000

    REPORT_BEEPER_BYTE = 40
    REPORT_BEEPER_MASK = 0b00000001


TEMREC0 = [15.5555555555556,16.6666666666667,17.7777777778,18.8888888889,20,20.5555555556,21.6666666667,22.7777777778,23.8888888889,25,25.5555555556,26.6666666666667,27.7777777778,28.8888888889,30,30.5555555556]
TEMREC1 = [16.1111111111111,17.2222222222222,18.3333333333333,19.4444444444444,0,21.1111111111,22.2222222222222,23.3333333333,24.4444444444,0,26.1111111111111,27.2222222222222,28.3333333333,29.4444444444,0,31.1111111111111]


def checksum_ok(bytes_list: List[int]) -> Tuple[bool,int]:
    # checksum is sum of all bytes except the 2 sync bytes and the checksum itself (uint8_t wrap)
    if len(bytes_list) < 4:
        return False, 0
    total = 0
    # include length and following bytes (including cmd and payload)
    for b in bytes_list[2:]:
        total = (total + b) & 0xFF
    # the last byte is checksum; total should equal checksum
    return total == 0, total


def parse_frame(raw_bytes: List[int]):
    if len(raw_bytes) < 5:
        raise ValueError("Frame too short")
    # find sync
    if raw_bytes[0] != Protocol.SYNC or raw_bytes[1] != Protocol.SYNC:
        raise ValueError("Frame does not start with 0x7E 0x7E")
    length = raw_bytes[2]
    cmd = raw_bytes[3]
    # total expected length including sync = 2 + length
    expected = 2 + length
    if expected != len(raw_bytes):
        # sometimes logs include formatting; still try to proceed if possible
        pass
    # payload is after cmd, length bytes = (length - 2) -> because length includes cmd and checksum
    payload_len = Protocol.SET_PACKET_LEN if cmd == Protocol.CMD_OUT_PARAMS_SET else (length - 2)
    payload = raw_bytes[4:4+payload_len]
    checksum = raw_bytes[4+payload_len]
    # verify checksum: sum(length + cmd + payload) % 256 == checksum
    s = (raw_bytes[2] + raw_bytes[3] + sum(payload)) & 0xFF
    ok = (s == checksum)
    return {
        'length': length,
        'cmd': cmd,
        'payload': payload,
        'checksum': checksum,
        'checksum_ok': ok,
    }


def decode_payload(payload: List[int], direction: str = 'TX') -> dict:
    # payload is the 45-byte array for SET packets, or similar for reports
    p = payload
    out = {}
    # mode and power
    mode_val = (p[Protocol.REPORT_MODE_BYTE] & Protocol.REPORT_MODE_MASK) >> Protocol.REPORT_MODE_POS
    power = (p[Protocol.REPORT_PWR_BYTE] & Protocol.REPORT_PWR_MASK) != 0
    modes = {0: 'AUTO', 1: 'COOL', 2: 'DRY', 3: 'FAN', 4: 'HEAT'}
    out['mode'] = modes.get(mode_val, f'UNKNOWN({mode_val})')
    out['power_bit_raw'] = int(power)

    # target temperature
    temset = (p[Protocol.REPORT_TEMP_SET_BYTE] & Protocol.REPORT_TEMP_SET_MASK) >> Protocol.REPORT_TEMP_SET_POS
    temrec = (p[Protocol.REPORT_DISP_F_BYTE] & Protocol.TEMREC_MASK) != 0
    if temset < 0 or temset > 15:
        out['target_temperature'] = None
    else:
        out['target_temperature'] = TEMREC1[temset] if temrec else TEMREC0[temset]
    out['temset_index'] = temset
    out['temrec_flag'] = int(temrec)

    # fan
    fan1 = (p[Protocol.REPORT_FAN_SPD1_BYTE] & Protocol.REPORT_FAN_SPD1_MASK) >> Protocol.REPORT_FAN_SPD1_POS
    fan2 = (p[Protocol.REPORT_FAN_SPD2_BYTE] & Protocol.REPORT_FAN_SPD2_MASK) >> Protocol.REPORT_FAN_SPD2_POS
    fan_quiet = (p[Protocol.REPORT_FAN_QUIET_BYTE] & Protocol.REPORT_FAN_QUIET_MASK) != 0
    fan_turbo = (p[Protocol.REPORT_FAN_TURBO_BYTE] & Protocol.REPORT_FAN_TURBO_MASK) != 0
    out.update({'fan_spd1': fan1, 'fan_spd2': fan2, 'fan_quiet': int(fan_quiet), 'fan_turbo': int(fan_turbo)})

    # swing
    vmode = (p[Protocol.REPORT_VSWING_BYTE] & Protocol.REPORT_VSWING_MASK) >> Protocol.REPORT_VSWING_POS
    hmode = (p[Protocol.REPORT_HSWING_BYTE] & Protocol.REPORT_HSWING_MASK) >> Protocol.REPORT_HSWING_POS
    out['vertical_swing_index'] = vmode
    out['horizontal_swing_index'] = hmode

    # display
    disp_mode = (p[Protocol.REPORT_DISP_MODE_BYTE] & Protocol.REPORT_DISP_MODE_MASK) >> Protocol.REPORT_DISP_MODE_POS
    disp_on = (p[Protocol.REPORT_DISP_ON_BYTE] & Protocol.REPORT_DISP_ON_MASK) != 0
    disp_f = (p[Protocol.REPORT_DISP_F_BYTE] & Protocol.REPORT_DISP_F_MASK) != 0
    disp_modes = {0: 'AUTO', 1: 'SET', 2: 'ACT', 3: 'OUT'}
    out.update({'display_mode': disp_modes.get(disp_mode, f'UNK({disp_mode})'), 'display_on': int(disp_on), 'display_unit_F': int(disp_f)})

    # boolean flags
    out['plasma'] = int((p[Protocol.REPORT_PLASMA1_BYTE] & Protocol.REPORT_PLASMA1_MASK) != 0 or (p[Protocol.REPORT_PLASMA2_BYTE] & Protocol.REPORT_PLASMA2_MASK) != 0)
    out['sleep'] = int((p[Protocol.REPORT_SLEEP_BYTE] & Protocol.REPORT_SLEEP_MASK) != 0)
    out['xfan'] = int((p[Protocol.REPORT_XFAN_BYTE] & Protocol.REPORT_XFAN_MASK) != 0)
    out['save'] = int((p[Protocol.REPORT_SAVE_BYTE] & Protocol.REPORT_SAVE_MASK) != 0)

    # beeper is inconsistent between TX and RX in firmware: for outgoing SET the implementation sets the bit when beeper_state == false
    beeper_raw = (p[Protocol.REPORT_BEEPER_BYTE] & Protocol.REPORT_BEEPER_MASK) != 0
    out['beeper_raw'] = int(beeper_raw)
    if direction.upper() == 'TX':
        out['beeper_effective'] = 'OFF if raw=1 (firmware sets mask when beeper_state==false)'
    else:
        out['beeper_effective'] = 'ON if raw=1 (reported state)'

    # current (AC) temperature
    act_temp_raw = p[Protocol.REPORT_TEMP_ACT_BYTE]
    out['ac_indoor_temperature'] = (act_temp_raw - Protocol.REPORT_TEMP_ACT_OFF) / 1.0

    return out


def format_frame_info(info: dict) -> str:
    lines = []
    lines.append(f"CMD=0x{info['cmd']:02X}, LEN={info['length']}, checksum_ok={info['checksum_ok']}")
    payload = info['payload']
    lines.append('PAYLOAD: ' + ' '.join(f"{b:02X}" for b in payload))
    decoded = decode_payload(payload, direction='TX' if info['cmd'] == Protocol.CMD_OUT_PARAMS_SET else 'RX')
    lines.append('Decoded:')
    for k, v in decoded.items():
        lines.append(f"  {k}: {v}")
    return "\n".join(lines)


def extract_frames_from_line(line: str) -> List[List[int]]:
    # find sequences containing 7E 7E and subsequent hex bytes
    # simple approach: parse all hex bytes and then locate 7E 7E occurrences
    bytes_all = parse_hex_bytes(line)
    frames = []
    for i in range(len(bytes_all)-1):
        if bytes_all[i] == Protocol.SYNC and bytes_all[i+1] == Protocol.SYNC:
            # There is a candidate. Need at least length byte at i+2
            if i+2 < len(bytes_all):
                length = bytes_all[i+2]
                total_len = 2 + length
                if i + total_len <= len(bytes_all):
                    frames.append(bytes_all[i:i+total_len])
    return frames


def main(argv):
    if len(argv) >= 2 and argv[1] == '--file':
        if len(argv) < 3:
            print('Usage: --file <logfile>')
            return
        fname = argv[2]
        with open(fname, 'r', encoding='utf-8') as f:
            for line in f:
                for frame in extract_frames_from_line(line):
                    try:
                        info = parse_frame(frame)
                        print(format_frame_info(info))
                        print('---')
                    except Exception as e:
                        print('Failed to parse frame:', e)
    else:
        # accept a hex string on the command line or from stdin
        if len(argv) >= 2:
            raw = ' '.join(argv[1:])
        else:
            raw = sys.stdin.read().strip()
        bytes_list = parse_hex_bytes(raw)
        if not bytes_list:
            print('No hex bytes found')
            return
        try:
            info = parse_frame(bytes_list)
            print(format_frame_info(info))
        except Exception as e:
            # try to extract frames
            frames = extract_frames_from_line(raw)
            if frames:
                for frame in frames:
                    info = parse_frame(frame)
                    print(format_frame_info(info))
                    print('---')
            else:
                print('Failed to parse:', e)


if __name__ == '__main__':
    main(sys.argv)
