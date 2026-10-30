# TrustGate firmware - plain GNU make build (arm-none-eabi-gcc + STM32Cube F1 HAL).
# CUBE must point at a folder laid out like STM32CubeF1/Drivers (HAL + CMSIS device + CMSIS core).
CUBE   ?= ../STM32CubeF1
PORT   ?= COM5
HAL     = $(CUBE)/Drivers/STM32F1xx_HAL_Driver
DEV     = $(CUBE)/Drivers/CMSIS/Device/ST/STM32F1xx
CORE    = $(CUBE)/Drivers/CMSIS/Core
CC      = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
SIZE    = arm-none-eabi-size
EXTRA  ?=

CPU     = -mcpu=cortex-m3 -mthumb
DEFS    = -DSTM32F103xB -DUSE_HAL_DRIVER $(EXTRA)
INCS    = -Iinclude -I$(HAL)/Inc -I$(DEV)/Include -I$(CORE)/Include
CFLAGS  = $(CPU) -Os -g -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable \
          -ffunction-sections -fdata-sections $(DEFS) $(INCS)
LDFLAGS = $(CPU) -TSTM32F103_32K_10K.ld --specs=nano.specs --specs=nosys.specs -Wl,--gc-sections \
          -Wl,-Map=build/trustgate.map

HAL_SRCS = stm32f1xx_hal.c stm32f1xx_hal_cortex.c stm32f1xx_hal_rcc.c stm32f1xx_hal_rcc_ex.c stm32f1xx_hal_gpio.c \
           stm32f1xx_hal_gpio_ex.c stm32f1xx_hal_dma.c stm32f1xx_hal_spi.c stm32f1xx_hal_tim.c stm32f1xx_hal_tim_ex.c \
           stm32f1xx_hal_uart.c stm32f1xx_hal_iwdg.c stm32f1xx_hal_pwr.c stm32f1xx_hal_flash.c stm32f1xx_hal_flash_ex.c

NS_SRCS  = $(wildcard src/*.c)
SEC_SRCS = secure/secure_core.c secure/secure_passage.c secure/secure_hw.c
SYS_SRCS = $(DEV)/Source/Templates/system_stm32f1xx.c
STARTUP  = $(DEV)/Source/Templates/gcc/startup_stm32f103xb.s

NS_OBJS  = $(NS_SRCS:%.c=build/%.o)
SEC_OBJS = $(SEC_SRCS:%.c=build/%.o)
HAL_OBJS = $(HAL_SRCS:%.c=build/hal/%.o) build/sys.o build/startup.o
OBJS     = $(NS_OBJS) $(SEC_OBJS) $(HAL_OBJS)

all: build/trustgate.bin
	$(SIZE) build/trustgate.elf

build/trustgate.elf: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@
build/trustgate.bin: build/trustgate.elf
	$(OBJCOPY) -O binary $< $@

build/%.o: %.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@
build/hal/%.o: $(HAL)/Src/%.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@
build/sys.o: $(SYS_SRCS) | dirs
	$(CC) $(CFLAGS) -c $< -o $@
build/startup.o: $(STARTUP) | dirs
	$(CC) $(CPU) -x assembler-with-cpp -c $< -o $@
dirs:
	mkdir -p build/src build/secure build/hal

# Flash through the STM32 ROM UART bootloader (BOOT0=1, USB-TTL on PA9/PA10). Needs stm32flash.
flash: build/trustgate.bin
	stm32flash -w build/trustgate.bin -v -g 0x0 $(PORT)

HOST_CC ?= clang

# Host unit tests of the secure core (no hardware needed)
test:
	$(HOST_CC) -std=gnu11 -Wall -Wextra -DTG_HOST_TEST -o build/host_tests test/test_main.c test/hw_stub.c secure/secure_core.c secure/secure_passage.c
	./build/host_tests

# Randomised soak test with invariants + sanitizers (seeds 1..8, dense and quiet traffic, 3 M simulated ms each)
fuzz:
	$(HOST_CC) -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -DTG_HOST_TEST -o build/fuzz test/fuzz.c test/hw_stub.c secure/secure_core.c secure/secure_passage.c
	@for s in 1 2 3 4 5 6 7 8; do ./build/fuzz $$s 3000000 0 || exit 1; ./build/fuzz $$s 3000000 1 || exit 1; done

boundary: all
	sh tools/check_boundary.sh

clean:
	rm -rf build
.PHONY: all dirs flash test fuzz boundary clean
