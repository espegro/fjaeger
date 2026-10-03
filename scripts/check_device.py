#!/usr/bin/env python3
"""Quick device status check via serial."""
import serial
import sys
import time

SERIAL_PORT = '/dev/ttyACM0'
BAUD = 115200

try:
    with serial.Serial(SERIAL_PORT, BAUD, timeout=2) as ser:
        time.sleep(0.1)

        # Clear any pending data
        ser.reset_input_buffer()

        # Send STATUS command
        ser.write(b'STATUS\r\n')
        time.sleep(0.5)

        # Read response
        lines = []
        for _ in range(30):
            line = ser.readline().decode('utf-8', errors='replace').strip()
            if line:
                lines.append(line)
            if 'fjaeger>' in line.lower() and len(lines) > 5:
                break

        print('\n'.join(lines))

        if any('fjaeger>' in l.lower() for l in lines):
            print('\n✓ Device responding (firmware 875746b)')
            sys.exit(0)
        else:
            print('\n✗ No response')
            sys.exit(1)

except serial.SerialException as e:
    print(f'ERROR: {e}')
    print('Try: sudo usermod -a -G dialout $USER')
    sys.exit(1)
except Exception as e:
    print(f'ERROR: {e}')
    sys.exit(1)
