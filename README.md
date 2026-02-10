# Universal RF Reverse Engineering Framework
## Complete Multi-Device Analysis & Exploitation Tool

**"Kepada Tuhan Kita Berserah"** - For Education & Authorized Research Only

---

## 🌟 What Makes This Universal?

Unlike the car-specific RollBack tool, this framework analyzes **ANY** wireless device operating on common ISM bands (315/433/868/915 MHz):

| Device Category | Examples | Supported |
|----------------|----------|-----------|
| **Automotive** | Car keys, garage doors, gate controllers | ✅ |
| **Home Security** | Wireless alarms, sensors, door contacts | ✅ |
| **Consumer** | Remote controls (TV, AC, fan), doorbells | ✅ |
| **Smart Home** | Power outlets, light switches, thermostats | ✅ |
| **Communication** | Pagers, one-way transmitters | ✅ |
| **Access Control** | Key fobs, proximity cards (125kHz needs different HW) | ⚠️ |

---

## 🔍 Core Capabilities

### 1. **Automatic Signal Analysis**
```bash
python3 universal_rf.py --capture --freq 433.92 --explain
```

**Automatically detects:**
- ✅ Device type (car key, garage door, remote, etc.)
- ✅ Signal type (fixed code, rolling code, encrypted)
- ✅ Modulation (ASK/OOK, FSK, PSK)
- ✅ Encoding (Manchester, PWM, NRZ)
- ✅ Baud rate (symbols/second)
- ✅ Signal components (preamble, address, command, counter)
- ✅ Security vulnerabilities
- ✅ Attack recommendations

**Output Example:**
```
PROTOCOL IDENTIFIED: ev1527_learning
Confidence: 90%
Device Type: remote_control
Signal Type: learning_code
Notes: EV1527 chip - common in cheap remotes, can be learned

BIT-BY-BIT BREAKDOWN:
🔹 PREAMBLE (12 bits)
   Binary: 101010101010
   Purpose: Synchronization pattern

🔹 ADDRESS/ID (20 bits)
   Binary: 11001100110011001100
   Hex: CCCC
   Decimal: 838860
   Purpose: Unique device identifier
   Note: This is the "house code"

🔹 COMMAND/DATA (4 bits)
   Binary: 1010
   Hex: A
   Decimal: 10
   Purpose: Button pressed
   Possible meanings:
      10 = Button C

SECURITY ASSESSMENT:
🔓 VULNERABLE: Learning Mode Exploitation
   1. Simple Replay Attack
   2. Brute Force Possible (only 16 commands)
```

### 2. **Interactive Bit Explanation**
```bash
python3 universal_rf.py --capture --freq 315.0 --explain
```

Walks you through **each bit field** with explanations:
- What it represents
- How it's used
- Security implications
- Press Enter to continue through each section

### 3. **Signal Replay**
```bash
python3 universal_rf.py --replay mysignal.iq --freq 433.92 --repeat 3
```

Simple replay attack - transmit captured signal 1-N times.

### 4. **Signal Cloning**
```bash
python3 universal_rf.py --capture --freq 433.92 --clone
```

**Recreates signal from decoded bits** - doesn't need original capture!

Benefits:
- Clean signal (no noise)
- Can modify before transmitting
- Portable (just store the bits, not huge IQ file)

### 5. **Signal Modification**
```bash
python3 universal_rf.py --capture --freq 433.92 --modify
```

**Interactive menu:**
```
Modification Options:
  1. Change command code       → Test different buttons
  2. Increment counter         → Bypass rolling code counter
  3. Change address           → Try different device IDs
  4. Bit flip attack          → Test error correction
  5. Cancel
```

**Use Cases:**
- Test button B when you captured button A
- Try incrementing rolling code counter
- Test neighboring addresses (find other devices)
- Fuzzing for protocol weaknesses

### 6. **Brute Force Attack**
```bash
python3 universal_rf.py --capture --freq 433.92 --brute-force
```

For **fixed-code** devices only.

**Automatically:**
- Identifies fixed vs. rolling codes
- Calculates total combinations
- Estimates time required
- Systematically tries all codes

**Example:**
```
BRUTE FORCE ATTACK
Command field: 4 bits
Total combinations: 16
Estimated time: 0.0 minutes

[0/16] Testing code 0000
[1/16] Testing code 0001
...
[15/16] Testing code 1111
```

---

## 📚 Supported Protocols Database

The framework includes intelligence about **common wireless protocols**:

### Garage Door Openers

**12-bit DIP Switch** (very old, fixed code)
```
Total: 12 bits
Structure: CCCCCCCCCCCC (all code bits)
Vulnerability: Simple replay, brute force (4096 codes)
Examples: Old Sears, Craftsman, generic openers
```

**Chamberlain Security+** (rolling code)
```
Total: 66 bits
Preamble: 12 bits (alternating 10)
Serial: 28 bits (transmitter ID)
Counter: 32 bits (encrypted rolling)
Vulnerability: RollBack attack, resync window
Examples: LiftMaster, Chamberlain after 1993
```

### Car Keys

**KeeLoq Standard** (rolling code)
```
Total: 66 bits
Preamble: 12 bits
Function: 4 bits (lock/unlock/trunk/panic)
Encrypted: 32 bits (counter + seed)
Serial: 28 bits (key fob ID)
Vulnerability: RollBack, cryptanalysis
Examples: Honda, Toyota, Chrysler, VW (older models)
```

### Remote Controls

**EV1527** (learning code)
```
Total: 24 bits
Address: 20 bits (device ID)
Data: 4 bits (button code)
Vulnerability: Learning mode, simple replay
Examples: Cheap 433MHz remotes, door bells, outlets
```

**PT2262** (tri-state, fixed)
```
Total: 24 bits (tri-state: 0, 1, F)
Structure: 8 tri-state digits
Vulnerability: Simple replay, brute force
Examples: Very common in Asian market devices
```

### Power Outlets

**1527-based outlets**
```
Total: 24 bits
House Code: 20 bits
Unit Code: 4 bits (A, B, C, D, ON, OFF)
Vulnerability: Learning mode exploitation
Examples: Etekcity, BN-LINK, other 433MHz outlets
```

### Wireless Doorbells

**Simple doorbell**
```
Total: 24 bits
Code: 24 bits fixed
Vulnerability: Simple replay
Examples: Most wireless doorbells
```

### Pagers

**POCSAG** (one-way pager protocol)
```
Preamble: 144 bits (alternating 10)
Batch: Variable (codewords)
Vulnerability: Message sniffing, replay
Examples: Numeric pagers, alphanumeric pagers
```

---

## 🎯 Practical Usage Scenarios

### Scenario 1: Unknown Garage Door Remote

**Problem:** Found old garage remote, don't know protocol.

**Solution:**
```bash
# Step 1: Capture and analyze
python3 universal_rf.py --capture --freq 315.0 --explain

# Output identifies it as:
# Device: garage_door
# Protocol: dip_switch_12bit
# Signal: fixed_code
# Vulnerability: Simple replay works!

# Step 2: Replay
python3 universal_rf.py --replay capture.iq --freq 315.0

# Success! Door opens.
```

### Scenario 2: Wireless Power Outlet

**Problem:** Lost remote for power outlet, need to control it.

**Solution:**
```bash
# Capture ON signal
python3 universal_rf.py --capture --freq 433.92 --output outlet_on.iq --explain

# Output shows:
# Protocol: ev1527_learning
# House Code: 10110011001100110011 (753459)
# Unit: 0001 (Unit 1 ON)

# Modify to create OFF signal
python3 universal_rf.py --replay outlet_on.iq --freq 433.92 --modify

# Select: "1. Change command code"
# Change from 0001 to 0000 (OFF)
# Transmits modified signal - outlet turns off!

# Now you can control outlet without original remote
```

### Scenario 3: Wireless Doorbell Analysis

**Problem:** Doorbell interfering with neighbor's, want to change code.

**Solution:**
```bash
# Capture doorbell signal
python3 universal_rf.py --capture --freq 433.92 --explain

# Output shows:
# Device: doorbell
# Code: 110011001100110011001100 (Fixed 24-bit)

# Clone and modify
python3 universal_rf.py --capture --freq 433.92 --clone

# Manually edit cloned.iq or modify bits
# Program new receiver with modified code
```

### Scenario 4: Car Key Research

**Problem:** Analyzing car key for security research.

**Solution:**
```bash
# Capture 5 unlock signals
for i in {1..5}; do
    python3 universal_rf.py --capture --freq 315.0 --output key_$i.iq
    sleep 3
done

# Analyze first capture
python3 universal_rf.py --replay key_1.iq --freq 315.0 --explain

# Output identifies:
# Protocol: keeloq_standard
# Device: car_key_rolling
# Counter: <encrypted 32 bits>
# Vulnerability: RollBack attack

# Use rollback_advanced.py for actual RollBack attack
# This tool identified the protocol!
```

### Scenario 5: Smart Home Device

**Problem:** Reverse engineer 433MHz smart switch.

**Solution:**
```bash
# Capture ON signal
python3 universal_rf.py --capture --freq 433.92 --explain

# Bit breakdown shows protocol structure
# Clone and create custom controller:

python3 universal_rf.py --capture --freq 433.92 --clone

# Now you have cloned.iq - integrate with:
# - Home Assistant
# - Custom Arduino/ESP8266
# - Raspberry Pi automation
```

### Scenario 6: Testing Alarm System

**Problem:** Security audit of wireless alarm sensors.

**Solution:**
```bash
# Capture door sensor signal
python3 universal_rf.py --capture --freq 433.92 --explain

# Check vulnerabilities:
# - Can signal be replayed? (Jam sensor + replay "door closed")
# - Fixed or rolling code?
# - Any encryption?

# Test replay attack
python3 universal_rf.py --replay capture.iq --freq 433.92

# If replay works → CRITICAL vulnerability!
# Attacker can jam sensor and replay "safe" signal
```

---

## 🔧 Advanced Features

### Automatic Protocol Detection

The framework uses **pattern matching** to identify protocols:

```python
# Checks:
1. Bit length (24 bits → likely EV1527 or PT2262)
2. Preamble pattern (alternating 10 → POCSAG or Chamberlain)
3. Known structures (20+4 bits → EV1527 address+data)
4. Baud rate (400bps → KeeLoq, 1000bps → EV1527)
```

**Confidence Scoring:**
- Exact match on all criteria → 90% confidence
- Partial match → 70% confidence
- Length match only → 50% confidence

### Component Extraction

**Automatically parses bit fields:**

```
Structure string: "PPPPPPPPPPPPAAAAAAAAAAAAAAAADDDD"
                   P=Preamble, A=Address, D=Data

Extracted:
  preamble: "101010101010"
  address: "11001100110011001100"
  command: "1010"
```

### Security Assessment

**Evaluates each signal:**

```python
Fixed Code:
  ✓ Vulnerabilities: [Simple Replay, Brute Force]
  ✓ is_vulnerable: True

Learning Code:
  ✓ Vulnerabilities: [Learning Mode, Replay]
  ✓ is_vulnerable: True

Rolling Code (16-bit counter):
  ✓ Vulnerabilities: [RollBack Attack]
  ✓ is_vulnerable: True

Rolling Code (32-bit + crypto):
  ✓ Vulnerabilities: [Possible RollBack]
  ✓ is_vulnerable: False (harder)
```

### Signal Cloning Technology

**Process:**
```
1. Decode IQ → Bits
2. Store bits + metadata (encoding, baud rate)
3. Re-encode: Bits → IQ using proper encoding
4. Transmit clean signal
```

**Benefits:**
- **99% smaller file size** (bits vs. IQ samples)
- **No noise** - perfect reconstruction
- **Modifiable** - change bits before transmission
- **Portable** - just store bit string

**Example:**
```
Original IQ file: 32 MB
Decoded bits: "110011001100110011001100" (24 bits)
Bit string size: 24 bytes
Compression: 1,333,333x smaller!
```

---

## 📊 Technical Details

### Modulation Detection

**Algorithm:**
```python
mag_variance = var(magnitude)
phase_variance = var(phase_diff)
freq_variance = var(instantaneous_freq)

if mag_variance > 0.05 and phase_variance < 0.5:
    return "ASK/OOK"  # Amplitude changes, phase stable
elif freq_variance > 0.01:
    return "FSK"  # Frequency changes
elif phase_variance > 0.5:
    return "PSK"  # Phase changes
```

### Baud Rate Detection

**Autocorrelation method:**
```
1. Calculate signal envelope
2. Remove DC offset
3. Autocorrelate with itself
4. Find first peak (after zero)
5. Peak position = symbol period
6. Baud rate = sample_rate / symbol_period
```

### Encoding Detection

**Pattern analysis:**
```
Manchester:
  - Transition rate ≈ 1 per bit
  - Every bit has mid-bit transition

PWM:
  - Variable pulse widths
  - High variance in run lengths
  - 0 = short pulse, 1 = long pulse

NRZ:
  - Low transition rate
  - Direct level encoding
```

### Component Extraction

**Template matching:**
```
Protocol template: "PPPPSSSSSSCC"
                    P=Preamble (4 bits)
                    S=Serial (6 bits)
                    C=Command (2 bits)

Extracts:
  preamble = bits[0:4]
  address = bits[4:10]
  command = bits[10:12]
```

---

## 🛡️ Security Research Applications

### Testing Access Control

**Scenario:** Security audit of building access

```bash
# 1. Capture legitimate key fob
python3 universal_rf.py --capture --freq 433.92 --explain

# 2. Identify protocol
# Output: "fixed_code" or "rolling_code"

# 3. Test replay
python3 universal_rf.py --replay capture.iq --freq 433.92

# 4. Report findings
# - If replay works → FAIL
# - If rolling code → Test RollBack
# - If learning mode → Test spoofing
```

### IoT Device Security

**Scenario:** Smart home device testing

```bash
# Capture all device commands
python3 universal_rf.py --capture --freq 433.92 --output light_on.iq
python3 universal_rf.py --capture --freq 433.92 --output light_off.iq

# Analyze for weaknesses
python3 universal_rf.py --replay light_on.iq --freq 433.92 --explain

# Test modifications
python3 universal_rf.py --replay light_on.iq --freq 433.92 --modify
# Try changing device ID - can you control neighbor's device?
```

### Wireless Alarm Testing

**Scenario:** Penetration test of alarm system

```bash
# 1. Capture sensor signals
python3 universal_rf.py --capture --freq 433.92 --output door_closed.iq

# 2. Analyze
# Is it fixed code? Rolling code? Encrypted?

# 3. Jam and replay attack
# Jam actual sensor, replay "door_closed" signal
# If alarm doesn't trigger → CRITICAL VULNERABILITY

# 4. Document for client
```

---

## 🔬 Research Mode

### Adding New Protocols

**Edit** `universal_rf.py` to add your discovered protocol:

```python
"my_device": {
    "device_type": DeviceType.REMOTE_CONTROL,
    "signal_type": SignalType.FIXED_CODE,
    "pattern": {
        "total_bits": 32,
        "structure": "PPPPPPPPAAAAAAAAAAAAAAAADDDDDDDD",
        "preamble": "10101010",
    },
    "notes": "Custom device found during research"
},
```

### Contribution to Database

If you reverse engineer a new protocol:

1. Capture multiple samples
2. Identify bit structure
3. Document findings
4. Submit pull request with protocol details

---

## ⚠️ Common Issues & Solutions

### Issue: "Protocol: Unknown"

**Cause:** Signal doesn't match known patterns

**Solution:**
```bash
# Still get full bit breakdown:
# - Bits are decoded
# - Can still replay
# - Can still modify
# - Just no automatic labeling

# Analyze manually:
# - Check bit length
# - Look for repeating patterns
# - Compare multiple captures
```

### Issue: Replay doesn't work

**Possible causes:**
1. **Rolling code** - use RollBack attack instead
2. **Wrong frequency** - try ±0.5 MHz
3. **Low signal** - increase TX gain
4. **Jam protection** - device detects replay

### Issue: Brute force too slow

**Solutions:**
```bash
# Reduce delay between codes
# Edit code: time.sleep(0.05)  # Faster

# Only try likely codes
# For 4-bit command, focus on 0-3 (common button codes)

# Use multiple HackRFs in parallel
```

---

## 🎓 Learning Path

### Beginner
1. Capture and replay simple devices (doorbell, remote)
2. Understand bit breakdown explanation
3. Practice with fixed-code devices

### Intermediate
4. Modify signals (change commands)
5. Clone signals from bits
6. Identify protocols manually

### Advanced
7. Add new protocols to database
8. Implement custom encoding schemes
9. Develop automated exploit chains

---

## 📖 References

**Primary sources integrated:**
- Michael Ossmann - Rapid Radio Reversing
- RTL-SDR reverse engineering guides  
- RollBack research paper
- EV1527, PT2262, KeeLoq datasheets
- POCSAG protocol specifications

---

## ⚖️ Ethical Use

### Legal Uses ✅
- Your own devices
- Authorized penetration testing
- Security research with permission
- Educational demonstrations
- Protocol documentation

### Illegal Uses ❌
- Unauthorized access to buildings
- Interfering with others' devices
- Stealing cars or property
- Violating privacy
- Commercial exploitation

---

**"Kepada Tuhan Kita Berserah"**

May this tool serve the cause of knowledge and security improvement.
