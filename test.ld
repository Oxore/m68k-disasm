MEMORY {
    ROM(rx) : ORIGIN = 0x00000000, LENGTH = 4M
}

SECTIONS {
    . = ORIGIN(ROM);
    .text : {
        KEEP(*(.text))
        . = ALIGN(2);
        *(.text*)
        . = ALIGN(2);
        KEEP(*(.rodata))
        *(.rodata*)
        . = ALIGN(2);
    } >ROM
}
