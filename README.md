richda (Rich DisAssembler) is an assembler providing rich information.

It provides information of function parameters and variables to make
the result eaiser to read.

NOTICE: x86 only so far.

## USAGE

    richda.py <ELF file> <function>

For example,

    $ ./scripts/richda.py test main
    main @ 0x1169 (size: 122)
    Section: .text (off: 0x1080, virt: 0x1080)
    Section offset: 0xe9
    Frame base: [DWARFExprOp(op=156, op_name='DW_OP_call_frame_cfa', args=[], offset=0)]
      variable: t (size: 5)
      variable: i (size: 4)
    0x1169: endbr64
    0x116d: push    rbp
    0x116e: mov     rbp, rsp
    0x1171: sub     rsp, 0x20
    0x1175: mov     rax, qword ptr fs:[0x28]
    0x117e: mov     qword ptr [rbp - 8], rax
    0x1182: xor     eax, eax
    0x1184: mov     dword ptr [rbp - 0x14], 0       ; [rbp - 0x14] is "i"
    0x118b: jmp     0x119f
    0x118d: mov     eax, dword ptr [rbp - 0x14]     ; [rbp - 0x14] is "i"
    0x1190: mov     edx, eax        ; eax is "i" (D)
    0x1192: mov     eax, dword ptr [rbp - 0x14]     ; [rbp - 0x14] is "i"
    0x1195: cdqe
    0x1197: mov     byte ptr [rbp + rax - 0xd], dl  ; [rbp - 0xd] is "t"
    0x119b: add     dword ptr [rbp - 0x14], 1       ; [rbp - 0x14] is "i"
    0x119f: cmp     dword ptr [rbp - 0x14], 9       ; [rbp - 0x14] is "i"
    0x11a3: jle     0x118d
    0x11a5: movzx   eax, byte ptr [rbp + 1]
    0x11a9: add     eax, 3
    0x11ac: mov     byte ptr [rbp - 9], al  ; [rbp - 0xd] is "t"
    0x11af: movzx   eax, byte ptr [rbp - 0xd]       ; [rbp - 0xd] is "t"
    0x11b3: movsx   eax, al
    0x11b6: mov     esi, eax
    0x11b8: lea     rax, [rip + 0xe45]
    0x11bf: mov     rdi, rax
    0x11c2: mov     eax, 0
    0x11c7: call    0x1070
    0x11cc: mov     eax, 0
    0x11d1: mov     rdx, qword ptr [rbp - 8]
    0x11d5: sub     rdx, qword ptr fs:[0x28]
    0x11de: je      0x11e5
    0x11e0: call    0x1060
    0x11e5: leave
    0x11e6: ret

You see the main function in test is disassembled with variable names
at the right side.
