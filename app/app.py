import unicorn as uc
import lief
import weakref

class Printf:

  def __init__(self, emu):
    self.emu = emu
  
  def parse(self):
    self.param = 0
    self.sp = self.emu.reg_read(uc.arm_const.UC_ARM_REG_SP)
    r0 = self.emu.reg_read(uc.arm_const.UC_ARM_REG_R0)
    format = self.get_string(r0)
    s = ''
    i = 0
    while i < len(format):
      if format[i]=='%' and i < (len(format)-1):
        i+=1
        t = format[i]
        n = self.next_param()
        if t=='s':
          s += self.get_string(n)
        elif t=='c':
          s += chr(n & 0xff)
        elif t=='d':
          s += str(n)
        elif t=='x' or t=='p':
          s += hex(n)[2:]
        else:
          s += format[i-1:i+1]
      else:
        s += format[i]
      i+=1
    return s

  def next_param(self):
    if self.param == 0:
      p = self.emu.reg_read(uc.arm_const.UC_ARM_REG_R1)
    elif self.param == 1:
      p = self.emu.reg_read(uc.arm_const.UC_ARM_REG_R2)
    elif self.param == 2:
      p = self.emu.reg_read(uc.arm_const.UC_ARM_REG_R3)
    else:
      p = int.from_bytes(self.emu.mem_read(self.sp+(self.param-3)*4, 4), "little")
    self.param += 1
    return p

  def get_string(self, address):
    s = ''
    while(1):
      c = self.emu.mem_read(address,1)[0]
      if c==0:
        break
      address += 1
      s += chr(c)
    return s

class HookWeakMethod:
    """
    Class to pass instance method callbacks to unicorn with weak referencing to
    prevent circular dependencies.

    Circular dependencies blocks the GC to clean the rainbowBase at the correct
    time, and this causes memory troubles...

    We cannot use directly weakref.WeakMethod since __call__ does not execute
    the method, but returns it. This class does call the method when __call__
    is executed.
    """
    def __init__(self, method):
        self.method = weakref.WeakMethod(method)

    def __call__(self, *args, **kwargs):
        self.method()(*args, **kwargs)

class App:

  def __init__(self, elf_file='software_attacks/app/app.elf', RAM_is_executable=True):
    self._functions = {}
    self._function_names = {}
    self._ins_counter = 0
    self._elf_file = elf_file
    self._emu = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_THUMB | uc.UC_MODE_MCLASS)
    #self.emu.mem_map(0x00000000, 0x1000, uc.UC_PROT_ALL) # ugly hack, printf issue ?
    self._emu.mem_map(0x20000000, 0x10000, uc.UC_PROT_ALL) # make RAM executable for now
    self._emu.mem_map(0x08000000, 0x10000, uc.UC_PROT_ALL) # make FLASH writable for now
    self._load()
    self._emu.mem_protect(0x08000000, 0x10000, uc.UC_PROT_READ | uc.UC_PROT_EXEC)  # make flash non writable
    if not RAM_is_executable:
      self._emu.mem_protect(0x20000000, 0x10000, uc.UC_PROT_READ | uc.UC_PROT_WRITE)  # make RAM not executable
    self._set_hook('puts', HookWeakMethod(self._hook_puts))
    self._set_hook('putchar', HookWeakMethod(self._hook_putchar))
    self._set_hook('getchar', HookWeakMethod(self._hook_getchar))
    self._set_hook('printf', HookWeakMethod(self._hook_printf))
    #self.set_hook('__sfputc_r', HookWeakMethod(self.hook_))
    #self.emu.hook_add(uc.UC_HOOK_MEM_WRITE, HookWeakMethod(self.hook_write_mem))
    #self.emu.hook_add(uc.UC_HOOK_CODE, HookWeakMethod(self.hook_code), begin=self.functions['receive_command']-1, end=0x08000278)
    self._emu.hook_add(uc.UC_HOOK_CODE, HookWeakMethod(self._hook_code_count), begin=0x08000000, end=0x08010000)
    self.reset()

  def _set_hook(self, function, hook):
    add = self._functions[function]
    self._emu.hook_add(uc.UC_HOOK_CODE, hook, begin=add-1, end=add)

  def _load(self, verbose=False):
    """ Load an .elf file into emu's memory using LIEF """
    elffile = lief.parse(self._elf_file)
    if verbose:
        print(f"[x] Loading .elf ...")

    if len(list(elffile.segments)) > 0:
        for segment in elffile.segments:
            if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                for section in segment.sections:
                    if verbose:
                        print(
                            f"[=] Writing {section.name} on {section.virtual_address:x} - {section.virtual_address+section.size:x}"
                        )
                    self._emu.mem_write(section.virtual_address, bytes(section.content))

    # lief > 0.10
    try:
        for f in elffile.exported_functions:
            tmpn = f.name
            c = 0
            while tmpn in self._functions:
                c += 1
                tmpn = f.name + str(c)
            self._functions[tmpn] = f.address
    except:
        pass

    ## TODO: when the ELF has relocated functions exported, LIEF fails on get_function_address
    for i in elffile.symbols:
        if i.type == lief.ELF.SYMBOL_TYPES.FUNC:
            try:
                tmpn = i.name
                addr = i.value
                if self._functions[tmpn] != addr:
                    c = 0
                    while tmpn in self._functions.keys():
                        c += 1
                        tmpn = i.name + str(c)
                    self._functions[tmpn] = addr
            except Exception as e:
                if verbose:
                    print(e, i)

    self._function_names = {self._functions[x]: x for x in self._functions.keys()}


  def _read32(self, address):
    return int.from_bytes(self._emu.mem_read(address, 4), "little")

  def _get_pc(self):
    return self._emu.reg_read(uc.arm_const.UC_ARM_REG_PC)

  def reset(self):
    self._ins_counter = 0
    self._emu.reg_write(uc.arm_const.UC_ARM_REG_SP, self._read32(0x08000000))
    self._emu.reg_write(uc.arm_const.UC_ARM_REG_PC, self._read32(0x08000004))

  def _hook_puts(self, emu, address, size, user_data):
    r0 = emu.reg_read(uc.arm_const.UC_ARM_REG_R0)
    s = ''
    while(1):
      c = emu.mem_read(r0,1)[0]
      if c==0:
        break
      r0 += 1
      s += chr(c)
    print(s)
    self._answer += s
    self._ret()

  def _hook_putchar(self, emu, address, size, user_data):
    r0 = emu.reg_read(uc.arm_const.UC_ARM_REG_R0)
    c = chr(r0 & 0xff)
    print(c, end='')
    self._answer += c
    self._ret()


  def _hook_write(self, emu, address, size, user_data):
    #r0 = emu.reg_read(uc.arm_const.UC_ARM_REG_R0)
    #while(1):
    #  c = emu.mem_read(r0,1)[0]
    #  if c==0:
    #    break
    #  r0 += 1
    #  print(chr(c), end='')
    #print('')
    print('WRITE')
    self._ret()

  def _hook_getchar(self, emu, address, size, user_data):
    if self._cmd_idx < len(self._cmd_buf):
      c = self._cmd_buf[self._cmd_idx]
    else:
      raise NameError('Finished')
    emu.reg_write(uc.arm_const.UC_ARM_REG_R0, c)
    self._cmd_idx += 1
    self._ret()

  def _hook_printf(self, emu, address, size, user_data):
    a = Printf(emu).parse()
    print(a, end='')
    self._answer += a
    self._ret()


  def _hook_code(self, emu, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

  def _hook_code_count(self, emu, address, size, user_data):
      self._ins_counter += 1


  def _hook_write_mem(self, emu, access, address, size, value, user_data):
    if access == uc.UC_MEM_WRITE:
      print(">>> Writing 0x%x at 0x%x" %(value, address))


  def _ret(self):
    self._emu.reg_write(uc.arm_const.UC_ARM_REG_PC, self._emu.reg_read(uc.arm_const.UC_ARM_REG_LR))

  def send(self, *args, timeout=1):
    command = b''
    self._answer = ''
    for arg in args:
      if isinstance(arg, int):
        command += arg.to_bytes(4, 'little')
      elif isinstance(arg, str):
        command += bytes(arg, 'utf-8')
      else:
        command += arg
    if len(command) > 0xFF:
       raise OverflowError("command not sent: %d bytes exceed maximum of 255" % (len(command),))
    self._cmd_buf = len(command).to_bytes(1, 'little') + command
    self._cmd_idx = 0
    self._ins_counter = 0
    try:
      self._emu.emu_start(self._emu.reg_read(uc.arm_const.UC_ARM_REG_PC)|1, 0x08000295, timeout=timeout*1000000)
      self._ins_counter = 'timeout'
    except NameError:
      pass
    except uc.UcError as e:
      print('------CRASHED--------')
      print(e)
      print('PC =', hex(self._emu.reg_read(uc.arm_const.UC_ARM_REG_PC)))
    return self._ins_counter

  def get_answer(self):
    return self._answer
  
  def _int2ascii(self, value):
    return (ord('0') + value).to_bytes(1, 'little')

  def send_read_slot(self, slot):
    self.send('r', self._int2ascii(slot))

  def send_write_slot(self, slot, value):
    self.send('w', self._int2ascii(slot),  str(value))
  
  def send_increment_slot(self, slot):
    self.send('i', self._int2ascii(slot))

