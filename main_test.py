import unittest

class TestDecode(unittest.TestCase):

    def setUp(self):
        from main import Hemulator
        self.emu = Hemulator()

    def test_move_to_memory(self):
        import random
        rs = ["A", "B", "C", "D", "E"]
        for i in rs:
            a, b, c = random.randbytes(3)
            self.emu.registers["H"] = a
            self.emu.registers["L"] = b
            self.emu.registers[i] = c
            match i:
                case "A":
                    self.emu.decode(0b01110111)
                case "B":
                    self.emu.decode(0b01110000)
                case "C":
                    self.emu.decode(0b01110001)
                case "D":
                    self.emu.decode(0b01110010)
                case "E":
                    self.emu.decode(0b01110011)
                    
            self.assertEqual(self.emu.ram[int.from_bytes([b,a])], c, 'incorrect memory value')


    def test_move_register(self):
        import random
        rs = ["A", "B", "C", "D", "E", "H", "L"]
        for i in rs:
            a, b = random.randbytes(2)
            self.emu.registers[i] = a
            j = random.choice(list(set(rs)-set([i])))
            self.emu.registers[j] = b
            instr = "01"
            match j:
                case "A":
                    instr += "111"
                case "B":
                    instr += "000"
                case "C":
                    instr += "001"
                case "D":
                    instr += "010"
                case "E":
                    instr += "011"
                case "H":
                    instr += "100"
                case "L":
                    instr += "101"
            match i:
                case "A":
                    instr += "111"
                case "B":
                    instr += "000"
                case "C":
                    instr += "001"
                case "D":
                    instr += "010"
                case "E":
                    instr += "011"
                case "H":
                    instr += "100"
                case "L":
                    instr += "101"        
            self.emu.decode(int(instr,2))
            self.assertEqual(self.emu.registers[i], self.emu.registers[j], 'incorrect register value')

    def test_move_from_memory(self):
        import random
        rs = ["A", "B", "C", "D", "E"]
        for i in rs:
            a, b, c, d = random.randbytes(4)
            self.emu.registers["H"] = a
            self.emu.registers["L"] = b
            self.emu.ram[int.from_bytes([b,a])] = c
            self.emu.registers[i] = d
            match i:
                case "A":
                    self.emu.decode(0b01111110)
                case "B":
                    self.emu.decode(0b01000110)
                case "C":
                    self.emu.decode(0b01001110)
                case "D":
                    self.emu.decode(0b01010110)
                case "E":
                    self.emu.decode(0b01011110)
                    
            self.assertEqual(self.emu.ram[int.from_bytes([b,a])], self.emu.registers[i], 'incorrect register value')

    def test_arith_1(self):
        self.assertEqual(self.emu.flags["CY"], 0)
        self.assertEqual(self.emu.add_8bit(0xFF, 0b1), 0x00)
        self.assertEqual(self.emu.flags["CY"], 1)
        


if __name__ == '__main__':
    unittest.main()