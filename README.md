richda (Rich DisAssembler) is an assembler providing rich information.

It provides information of function parameters and variables to make
the result eaiser to read.

## USAGE

    richda.py <binary> <function>

For example,

    $ ./scripts/richda.py test main
    main @ 0x1169 (size: 116)
    Section: .text (off: 0x1080, virt: 0x1080)
    Section offset: 0xe9
    Frame base: [DWARFExprOp(op=156, op_name='DW_OP_call_frame_cfa', args=[], offset=0)]
      variable: t
      variable: i
    0x1169: endbr64
    0x116d: push    rbp
    0x116e: mov     rbp, rsp
    0x1171: sub     rsp, 0x10
    0x1175: mov     rax, qword ptr fs:[0x28]
    0x117e: mov     qword ptr [rbp - 8], rax
    0x1182: xor     eax, eax
    0x1184: mov     dword ptr [rbp - 0x10], 0       ; [rbp - 0x10] is "i"
    0x118b: jmp     0x119f
    0x118d: mov     eax, dword ptr [rbp - 0x10]     ; [rbp - 0x10] is "i"
    0x1190: mov     edx, eax        ; eax is "i" (D)
    0x1192: mov     eax, dword ptr [rbp - 0x10]     ; [rbp - 0x10] is "i"
    0x1195: cdqe
    0x1197: mov     byte ptr [rbp + rax - 9], dl
    0x119b: add     dword ptr [rbp - 0x10], 1       ; [rbp - 0x10] is "i"
    0x119f: cmp     dword ptr [rbp - 0x10], 9       ; [rbp - 0x10] is "i"
    0x11a3: jle     0x118d
    0x11a5: movzx   eax, byte ptr [rbp - 9] ; [rbp - 9] is "t"
    0x11a9: movsx   eax, al
    0x11ac: mov     esi, eax
    0x11ae: lea     rax, [rip + 0xe4f]
    0x11b5: mov     rdi, rax
    0x11b8: mov     eax, 0
    0x11bd: call    0x1070
    0x11c2: mov     eax, 0
    0x11c7: mov     rdx, qword ptr [rbp - 8]
    0x11cb: sub     rdx, qword ptr fs:[0x28]
    0x11d4: je      0x11db
    0x11d6: call    0x1060
    0x11db: leave
    0x11dc: ret

You see the main function in test is disassembled with annotation of
variables at the right side.
