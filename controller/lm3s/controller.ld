/******************************************************************************
 *
 * blinky.ld - Linker configuration file for blinky.
 *
 * Copyright (c) 2009 Luminary Micro, Inc.  All rights reserved.
 * Software License Agreement
 * 
 * Luminary Micro, Inc. (LMI) is supplying this software for use solely and
 * exclusively on LMI's microcontroller products.
 * 
 * The software is owned by LMI and/or its suppliers, and is protected under
 * applicable copyright laws.  All rights are reserved.  You may not combine
 * this software with "viral" open-source software in order to form a larger
 * program.  Any use in violation of the foregoing restrictions may subject
 * the user to criminal sanctions under applicable laws, as well as to civil
 * liability for the breach of the terms and conditions of this license.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS".  NO WARRANTIES, WHETHER EXPRESS, IMPLIED
 * OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE APPLY TO THIS SOFTWARE.
 * LMI SHALL NOT, IN ANY CIRCUMSTANCES, BE LIABLE FOR SPECIAL, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, FOR ANY REASON WHATSOEVER.
 * 
 * This is part of revision 32 of the Stellaris CMSIS Package.
 *
 *****************************************************************************/

_STACK_SIZE = 0xFB80;
_FLASH_BUF_SIZE = 0x4000;

MEMORY
{
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 0x00034000
    BUFS  (rx) : ORIGIN = 0x00034000, LENGTH = 0x0000C000
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 0x00010000
}

SECTIONS
{
    .text :
    {
        _text = .;
        KEEP(*(.isr_vector))
        *(.text*)
        *(.rodata*)
        _etext = .;
    } > FLASH

    .ARM.extab :
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > FLASH

    .ARM :
    {
        __exidx_start = .;
        *(.ARM.exidx*)
        __exidx_end = .;
    } > FLASH

    __end_code = .;

    .flashbufs :
    {
        _flash_bufs_start = .;
        _faa_buf_start = .;
        . += _FLASH_BUF_SIZE;
        _dtls_buf_start = .;
        . += _FLASH_BUF_SIZE;
        _scum_buf_start = .;
        . += _FLASH_BUF_SIZE;
        _flash_bufs_end = .;
    } > BUFS

    .data : AT(__end_code)
    {
        _data = .;
        *(vtable)
        *(.data*)
        _edata = .;
    } > SRAM

    .bss :
    {
        _bss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > SRAM

    .stack : AT(ADDR(.bss) + SIZEOF(.bss))
    {
        . = ALIGN(16);
        . += _STACK_SIZE;
        _stack_top = .;
    } > SRAM
}
