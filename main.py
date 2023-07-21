"""
8080 emulator
Use: read ROM file
author: hevemiko

Note: Python is very liberal with bit and hex literals:
some_byte = 0x1
other_byte = 0b1
third_byte = 0xFFFF
They are actually all integers
This is a bit mask:
third_byte & some_byte == 0x01
Python has variable integer bit length, so many usually straightforward bit operations, like bit-wise not,
become problematic.
"""


class Hemulator:
    """
    WIP Intel 8080 emulator
    """

    def __init__(self, registers=None, flags=None, rom=None):
        self.ram = bytearray(2**16)
        self.registers = {
            # Temporary (internal)
            "W": 0x00,
            "Z": 0x00,
            # General purpose
            "B": 0x00,
            "C": 0x00,
            "D": 0x00,
            "E": 0x00,
            "H": 0x00,
            "L": 0x00,
            # Execution flow
            "SP": 0xFFFF,
            "PC": 0x0000,
            "IDAL": 0x0000,
            # ALU
            "A": 0x00,
            "ACT": 0x00,
            "TMP": 0x00
        }
        self.flags = {"Z": 0, "CY": 0, "S": 0, "P": 0, "AC": 0}
        buses = {
            # ?
        }
        if registers:
            self.registers = registers
        if flags:
            self.flags = flags

    def read_ram(self, address = None):
        """
        Returns RAM location at address contained in HL register if not address
        """
        if not address:
            LSB = self.registers["H"]
            MSB = self.registers["L"]
        else:
            LSB = address[0]
            MSB = address[1]
        return self.ram[int.from_bytes([MSB, LSB])]

    def get_ram(self, address, n_bytes=1):
        return int.from_bytes(self.ram[address:address+n_bytes])
    
    def set_ram(self, value, address = None, n_bytes=1):
        if not address:
            LSB = self.registers["H"]
            MSB = self.registers["L"]
        else:
            LSB = address[0]
            MSB = address[1]
        address = int.from_bytes([MSB, LSB])
        for i in range(n_bytes):
            self.ram[address + i] = (value >> i*8) & 0xFF

    def pc(self):
        return self.registers["pc"]

    def double_register(self, register, value = None):
        if not value:
            LSB = self.registers[register[1]]
            MSB = self.registers[register[0]]
            return int.from_bytes([MSB, LSB])
        else:
            LSB = value & 0xFF
            MSB = value >> 8 & 0xFF
            self.registers[register[1]] = LSB
            self.registers[register[0]] = MSB



    def r(self, pattern, value = None):
        """
        Decode register
        """
        if not value:
            match pattern:
                case 0x07:
                    return self.registers["A"]
                case 0x00:
                    return self.registers["B"]
                case 0x01:
                    return self.registers["C"]
                case 0x02:
                    return self.registers["D"]
                case 0x03:
                    return self.registers["E"]
                case 0x04:
                    return self.registers["H"]
                case 0x05:
                    return self.registers["L"]
        else:
            match pattern:
                case 0x07:
                    self.registers["A"] = value
                case 0x00:
                    self.registers["B"] = value
                case 0x01:
                    self.registers["C"] = value
                case 0x02:
                    self.registers["D"] = value
                case 0x03:
                    self.registers["E"] = value
                case 0x04:
                    self.registers["H"] = value
                case 0x05:
                    self.registers["L"] = value

    def rp(self, pattern, value=None):
        """
        Decode register pair 
        """
        if not value:
            match pattern:
                case 0x00:
                    return self.double_register("BC")
                case 0x01:
                    return self.double_register("DE")
                case 0x02:
                    return self.double_register("HL")
                case 0x03:
                    return self.registers["SP"]
        else:
            match pattern:
                case 0x00:
                    self.double_register("BC", value)
                case 0x01:
                    self.double_register("DE", value)
                case 0x02:
                    self.double_register("HL", value)
                case 0x03:
                    "Specified register pair SP"
                    self.halt()

    def next_byte(self):
        tmp = self.ram[self.registers["PC"]]
        self.registers["PC"] += 1
        if self.registers["PC"] > 0xFFFF:
            print("overflow at next_byte") # FIXME

        return tmp


    def complement_8bit(self, value):
        """
        Two's complement for 8 bits
        """
        if value >= 0x80:
            return (value & 0x7F) - 0x80
        else:
            return value
 

    def complement_16bit(self, value):
        """
        Two's complement for 16 bits
        """
        if value >= 0x8000:
            return (value & 0x7FFF) - 0x8000
        else:
            return value

    def not_8bit(self, value):
        return ~value&0xFF
    def not_16bit(self, value):
        return ~value&0xFFFF

    def set_flags(self, value):
        if value == 0:
            self.flags["Z"] = 1
        else:
            self.flags["Z"] = 0
        if value & 0x80 == 0x80:
            self.flags["S"] = 1
        else:
            self.flags["S"] = 0
        if value > 0xFF:
            self.flags["CY"] = 1
        else:
            self.flags["CY"] = 0
        
        #Parity
        s = bin(0xFF ^ value)[2:]
        if s.count('1') % 2 == 0:
            self.flags["P"] = 1
        else:
            self.flags["P"] = 0
        #Aux carry ?? FIXME

    def add_8bit(self, st, nd):
        tmp = st + nd
        self.set_flags(tmp)
        tmp = 0xFF & tmp
        return tmp

    def add_16bit(st, nd):
        pass

    def sub_8bit(self, st, nd):
        tmp = st - nd
        self.set_flags(tmp)
        tmp = 0xFF & tmp
        return tmp
    
    def halt(self):
        exit()

    def add_acc(self, value:int):
        self.registers["A"] = self.add_8bit(self.registers["A"], value)

    def adc_acc(self, value:int):
        #Possibly incorrect
        tmp = self.flags["CY"]
        self.add_acc(value)
        self.add_acc(tmp)

    def sub_acc(self, value:int):
        self.registers["A"] = self.sub_8bit(self.registers["A"], value)
    
    def suc_acc(self, value:int):
        #Possibly incorrect
        tmp = self.flags["CY"]
        self.sub_acc(value)
        self.sub_acc(tmp)

    def compare(self, value: int):
        tmp = value
        self.set_flags(tmp)
        if tmp < 0:
            self.flags["CY"] = 1
        else:
            self.flags["CY"] = 0
        if tmp == 0:
            self.flags["Z"] = 1
        else:
            self.flags["Z"] = 0

    def rotate_8bit(self, value: int):
        MSB = (value >> 7) & 0b1
        tmp = ((value << 1) & 0xFF) | MSB #FIXME: check precedence
        return tmp
    def rotate_w_carry_8bit(self, value: int):
        MSB = (value >> 7) & 0b1
        tmp = ((value << 1) & 0xFF) | self.flags["CY"] #FIXME: check precedence
        self.flags["CY"] = MSB
        return tmp
    def rotate_8bit_right(self, value: int):
        LSB = value & 0b1
        tmp = ((value >> 1) & 0xFF) | (LSB << 7) #FIXME: check precedence
        return tmp
    def rotate_w_carry_8bit_right(self, value: int):
        LSB = value & 0b1
        tmp = ((value >> 1) & 0xFF) | (self.flags["CY"] << 7) #FIXME: check precedence
        self.flags["CY"] = LSB
        return tmp

    def cond(self, pattern: int):
        """
        Decode condition codes, return boolean
        """
        match pattern:
            case 0b000:
                return self.flags["Z"] == 0
            case 0b001:
                return self.flags["Z"] == 1
            case 0b010:
                return self.flags["CY"] == 0
            case 0b011:
                return self.flags["CY"] == 1
            case 0b100:
                return self.flags["P"] == 0
            case 0b101:
                return self.flags["P"] == 1
            case 0b110:
                return self.flags["S"] == 0
            case 0b111:
                return self.flags["S"] == 1
            case _:
                print("Incorrect condition code")
                self.halt()
    def jump(self, address: int = None):
        if not address:
            LSB = self.next_byte()
            MSB = self.next_byte()
            address = int.from_bytes([MSB, LSB])
        self.registers["PC"] = address

    def call(self):
        next_instr = self.registers["PC"] + 3
        pc_LSB = next_instr & 0xFF
        pc_MSB = next_instr >> 8 & 0xFF
        self.ram[self.registers["SP"] -1] = pc_MSB 
        self.ram[self.registers["SP"] -2] = pc_LSB 
        self.registers["SP"] -= 2
        self.jump()

    def ret(self):
        LSB = self.get_ram(self.registers["SP"])
        MSB = self.get_ram(self.registers["SP"] + 1)
        self.registers["PC"] = int.from_bytes([MSB, LSB])
        self.registers["SP"] += 2

    def status_word(self):
        CY = self.registers["CY"]
        P = self.registers["P"] << 2
        AC = self.registers["AC"] << 4
        Z = self.registers["Z"] << 6
        S = self.registers["S"] << 7
        #Bits 3 and 5 are zeroes
        word = S | Z | AC | P | 0b10 | CY
        return word
    def decode(self, instr):
        if instr > 0xFF:
            print("Instruction too large!")
            self.halt()

        match instr:
            case 0b0:
                    #NOP 
                    pass
            case 0b00110110:
                #Move to memory immediate
                self.set_ram(self.next_byte())
            case 0b00111010:
                #Load Accumulator direct
                self.registers["A"] = self.read_ram((self.next_byte(), self.next_byte()))
            case 0b00110010:
                #Store Accumulator direct
                self.set_ram(self.registers["A"], (self.next_byte(), self.next_byte()))
            case 0b00101010:
                #Load H and L direct
                LSB = self.next_byte()
                MSB = self.next_byte()
                addr = int.from_bytes([MSB,LSB])
                if addr == 0xFFFF:
                    print("Overflow in instr 0b00101010")
                    #FIXME
                self.registers["L"] = self.ram(addr)
                self.registers["H"] = self.ram(addr+1)
            case 0b00100010:
                #Store H and L direct
                LSB = self.next_byte()
                MSB = self.next_byte()
                addr = int.from_bytes([MSB,LSB])
                if addr == 0xFFFF:
                    print("Overflow in instr 0b00100010")
                    #FIXME
                self.ram[addr] = self.registers["L"]
                self.ram[addr+1] = self.registers["H"]
            case 0b00110100:
                #Increment memory
                tmp = self.flags["CY"]
                self.set_ram(self.add_8bit(self.read_ram(), 1))
                self.flags["CY"] = tmp
            case 0b00110101:
                #Decrement memory
                tmp = self.flags["CY"]
                self.set_ram(self.sub_8bit(self.read_ram(), 1))
                self.flags["CY"] = tmp
            case 0b00100111:
                #Decimal adjust accumulator
                #1
                # !?!?
                #2
                if self.registers["A"] & 0b1111 > 9:
                    self.registers["A"] += 0x0600
                self.set_flags(self.registers["A"])
                print("Decimal adjust accumulator - halting")
                self.halt()
                # FIXME
            case 0b00000111:
                #Rotate left
                self.registers["A"] = self.rotate_8bit(self.registers["A"])
            case 0b00001111:
                #Rotate right
                self.registers["A"] = self.rotate_8bit_right(self.registers["A"])
            case 0b00010111:
                #Rotate left through carry
                self.registers["A"] = self.rotate_w_carry_8bit(self.registers["A"])
            case 0b00011111:
                #Rotate right through carry
                self.registers["A"] = self.rotate_w_carry_8bit_right(self.registers["A"])
            case 0b00101111:
                #Complement accumulator
                self.registers["A"] = self.not_8bit(self.registers["A"])
            case 0b00111111:
                #Complement carry
                if self.flags["CY"] == 0:
                    tmp = 1
                else:
                    tmp = 0
                self.flags["CY"] = tmp
            case 0b00110111:
                #Set carry
                self.flags["CY"] = 1
            case 0b10000110:
                #Add memory
                self.add_acc(self.read_ram())
            case 0b10001110:
                #Add memory with carry
                self.adc_acc(self.read_ram())
            case 0b10010110:
                #Subtract memory
                self.sub_acc(self.read_ram())
            case 0b10011110:
                #Subtract memory with borrow
                self.suc_acc(self.read_ram())
            case 0b10100110:
                #And memory
                tmp = self.registers["A"] & self.read_ram()
                self.set_flags(tmp)
                self.flags["CY"] = 0
                self.registers["A"] = tmp
            case 0b10101110:
                #Exclusive or memory
                tmp = self.registers["A"] ^ self.read_ram()
                self.set_flags(tmp)
                self.flags["CY"] = 0
                self.flags["AC"] = 0
                self.registers["A"] = tmp
            case 0b10101110:
                #Or memory
                tmp = self.registers["A"] | self.read_ram()
                self.set_flags(tmp)
                self.flags["CY"] = 0
                self.flags["AC"] = 0
                self.registers["A"] = tmp
            case 0b10111110:
                #Compare memory
                self.compare(self.read_ram())
            case 0b11101011:
                #Exchange H and L with D and E
                old_H, old_L = self.registers["H"], self.registers["L"]
                self.registers["H"] = self.registers["D"]
                self.registers["L"] = self.registers["E"]
                self.registers["D"] = old_H
                self.registers["E"] = old_L
            case 0b11000110:
                #Add immediate
                tmp = self.next_byte()
                self.add_acc(tmp)
            case 0b11001110:
                #Add immediate with carry
                tmp = self.next_byte()
                self.adc_acc(tmp)
            case 0b11010110:
                #Subtract immediate
                tmp = self.next_byte()
                self.sub_acc(tmp)
            case 0b11011110:
                #Subtract immediate with borrow
                tmp = self.next_byte()
                self.suc_acc(tmp)
            case 0b11100110:
                #And immediate
                tmp = self.registers["A"] & self.next_byte()
                self.set_flags(tmp)
                self.flags["CY"] = 0
                self.flags["AC"] = 0
                self.registers["A"] = tmp
            case 0b11101110:
                #Exclusive or immediate
                tmp = self.registers["A"] ^ self.next_byte()
                self.set_flags(tmp)
                self.flags["CY"] = 0
                self.flags["AC"] = 0
                self.registers["A"] = tmp
            case 0b11101110:
                #Or immediate
                tmp = self.registers["A"] | self.next_byte()
                self.set_flags(tmp)
                self.flags["CY"] = 0
                self.flags["AC"] = 0
                self.registers["A"] = tmp
            case 0b10111110:
                #Compare immediate
                self.compare(self.next_byte())
            case 0b11000011:
                #Jump
                self.jump()
            case 0b11001101:
                #Call
                self.call()
            case 0b11001001:
                #Return
                self.ret()
            case 0b11101001:
                #Jump H and L indirect
                self.registers["PC"] = self.double_register("HL")
            case 0b11111001:
                #Move HL to SP
                self.registers["SP"] = self.double_register("HL")
            case 0b11110101:
                #Push processor status word
                self.set_ram(self.registers["A"], self.registers["SP"]-1)
                self.set_ram(self.status_word(), self.registers["SP"]-2)
                self.registers["SP"] -= 2
            case 0b11110001:
                #Pop processor status word
                self.registers["A"] = self.get_ram(self.registers["SP"]+2)
                status_word = self.get_ram(self.registers["SP"]+1)
                self.flags["CY"] = status_word & 0b1
                self.flags["P"] = status_word >> 2 & 0b1
                self.flags["AC"] = status_word >> 4 & 0b1
                self.flags["Z"] = status_word >> 6 & 0b1
                self.flags["S"] = status_word >> 7 & 0b1
                self.registers["SP"] += 2
            case 0b11100011:
                #Exchange stack top with H and L
                old_H, old_L = self.registers["H"], self.registers["L"]
                self.registers["H"] = self.get_ram(self.registers["SP"] + 1)
                self.registers["L"] = self.get_ram(self.registers["SP"])
                self.set_ram(old_L, self.registers["SP"])
                self.set_ram(old_H, self.registers["SP"] +1)
            case 0b11011011:
                #Input
                pass
            case 0b11010011:
                #Output
                pass
            case 0b11111011:
                #Enable interrupts
                pass
            case 0b11110011:
                #Disable interrupts
                pass
            case _:

                match instr >> 6:
                    case 1:
                        #Mixing match/case with if/else to allow for further expressions
                        if instr == 0b01110110:
                            #Halt
                            self.halt()
                        elif instr & 0b00111000 == 0b00110000:
                            #Move to memory: RAM address @HL set to register r
                            self.set_ram(self.r(instr & 0b111))
                        elif instr & 0b00000111 == 0b110:
                            #Move from memory
                            self.r(instr >> 3 & 0b111, self.read_ram())
                        else:
                            #Move register
                            self.r(instr >> 3 & 0b111, self.r(instr & 0b111))
                    case 0:
                        if instr & 0b111 == 0b110:
                            #Move immediate
                            self.r(instr >> 3, self.next_byte())
                        elif instr & 0b1111 == 1:
                            #Load register pair immediate
                            self.rp(instr >> 4, (self.next_byte(), self.next_byte()))
                        elif instr & 0b1111 == 0b1010:
                            #Load accumulator indirect
                            rp = instr >> 4
                            if not (rp == 0 | rp == 1):
                                self.halt()
                            self.registers["A"] = self.ram[self.rp(rp)]
                        elif instr & 0b1111 == 0b0010:
                            #Store accumulator indirect
                            rp = instr >> 4
                            if not (rp == 0 | rp == 1):
                                self.halt()
                            self.ram[self.rp(rp)] = self.registers["A"]
                        elif instr & 0b111 == 0b100:
                            #Increment register
                            tmp = self.flags["CY"]
                            self.r(instr >> 3, self.add_8bit(self.r(instr >> 3),1) )
                            self.flags["CY"] = tmp
                        elif instr & 0b111 == 0b101:
                            #Decrement register
                            tmp = self.flags["CY"]
                            self.r(instr >> 3, self.sub_8bit(self.r(instr >> 3),1) )
                            self.flags["CY"] = tmp
                        elif instr & 0b1111 == 0b0011:
                            #Increment register pair
                            rp = instr >> 4
                            self.rp(rp, self.rp(rp) + 1)
                        elif instr & 0b1111 == 0b1011:
                            #Decrement register pair
                            rp = instr >> 4
                            self.rp(rp, self.rp(rp) - 1)
                        elif instr & 0b1111 == 0b1001:
                            #Add register pair to H and L
                            rp = instr >> 4
                            val = self.rp(rp) + self.rp(0x02)
                            if val > 0xFFFF:
                                self.flags["CY"] = 1
                            else:
                                self.flags["CY"] = 0
                            self.rp(0x02, val & 0xFFFF)
                        print("Unknown instr" + str(instr))
                        self.halt()
                    case 2:
                        if instr & 0b11111000 == 0b10000000:
                            #Add register
                            self.add_acc(self.r(instr & 0b111))
                        elif instr & 0b11111000 == 0b10001000:
                            #Add register with carry
                            self.adc_acc(self.r(instr & 0b111))
                        elif instr & 0b11111000 == 0b10010000:
                            #Subtract register
                            self.sub_acc(self.r(instr & 0b111))
                        elif instr & 0b11111000 == 0b10011000:
                            #Subtract register with borrow
                            self.suc_acc(self.r(instr & 0b111))
                        elif instr & 0b11111000 == 0b10100000:
                            #And register
                            tmp = self.registers["A"] & self.r(instr & 0b111)
                            self.set_flags(tmp)
                            self.flags["CY"] = 0
                            self.registers["A"] = tmp
                        elif instr & 0b11111000 == 0b10101000:
                            #Exclusive or register
                            tmp = self.registers["A"] ^ self.r(instr & 0b111)
                            self.set_flags(tmp)
                            self.flags["CY"] = 0
                            self.flags["AC"] = 0
                            self.registers["A"] = tmp
                        elif instr & 0b11111000 == 0b10111000:
                            #Compare register
                            self.compare(self.r(instr & 0b111))
                        else: 
                            print("Unknown instr" + str(instr))
                            self.halt()
                    case 3:
                        if instr & 0b111 == 2:
                            #Conditional jump
                            if self.cond(instr >> 3 & 0b111):
                                self.jump()
                        elif instr & 0b111 == 4:
                            #Conditional call
                            if self.cond(instr >> 3 & 0b111):
                                self.call()
                        elif instr & 0b111 == 0:
                            #Conditional return
                            if self.cond(instr >> 3 & 0b111):
                                self.ret()
                        elif instr & 0b111 == 7:
                            #Restart
                            next_instr = self.registers["PC"] + 1
                            pc_LSB = next_instr & 0xFF
                            pc_MSB = next_instr >> 8 & 0xFF
                            self.ram[self.registers["SP"] -1] = pc_MSB 
                            self.ram[self.registers["SP"] -2] = pc_LSB 
                            self.registers["PC"] -= 2
                            self.registers["PC"] = instr & 0b111000
                        elif instr & 0b111 == 5:
                            #Push
                            tmp = self.rp(instr >> 4 & 0b11)
                            LSB = tmp & 0xFF
                            MSB = tmp >> 8
                            self.set_ram(MSB, self.registers["SP"] -1)
                            self.set_ram(LSB, self.registers["SP"] -2)
                            self.registers["SP"] -= 2
                        elif instr & 0b111 == 1:
                            #Pop
                            self.rp(instr >> 4 & 0b11, self.get_ram(self.registers["SP"] +1, 2))
                            self.registers["SP"] += 2
                        else:
                            print("Unknown instr" + str(instr))
                            self.halt()
                            

    def run(self):
        while(True):
            self.decode(self.next_byte())                    








if __name__ == "__main__":
    import sys
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-f", "--file", action="store", type="string", dest="filename")
    (options, args) = parser.parse_args(sys.argv)
    ram = None
    if options.filename:
        ram = []
        with open(options.filename, "rb") as rom:
            for line in rom:
                for i in range(len(line)):
                    ram.append(line[i])
    emu = Hemulator(None, None, ram)
    while(True):
        cmd = input()
        match cmd.split():
            case ["stop"]:
                exit()
            case ["register", x, y]:    
                emu.registers[x] = y
            case ["flag", x, y]:
                emu.flags[x] = y
            case ["ram", x, y]:
                emu.ram[int(x)] = int(y,2)
            case _:
                emu.decode(emu.next_byte())
                print(emu.flags)
                print(emu.registers)
                print("IP: " + str(emu.ram[emu.registers["PC"]]))
                print(emu.ram[:20])
 