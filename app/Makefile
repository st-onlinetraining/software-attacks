ARMGCC = arm-none-eabi-gcc
ARMOBJDUMP = arm-none-eabi-objdump

all: app.elf app.txt app.map

app.elf: startup.s main.c slots.c 
	$(ARMGCC) -O1 -g -march=armv7-m $^ --specs=nosys.specs -T flash.ld -o $@

app.txt: app.elf
	$(ARMOBJDUMP) -S $^ > $@

app.map: app.elf
	$(ARMOBJDUMP) -x $^ > $@

clean:
	$(RM) app.elf
	$(RM) app.txt
	$(RM) app.map

