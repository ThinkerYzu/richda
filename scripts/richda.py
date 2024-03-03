#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.descriptions import describe_reg_name
import capstone
import argparse
import sys

class CFACtx_X86_RSP_RBP(object):
    '''
    Context for CFA (Canonical Frame Address) computation.

    The CFA is the value of the stack pointer at the call site of the
    function. It is used to compute the location of variables in the
    stack frame.

    For x86_64, the CFA is usually the value of the stack pointer (RSP)
    at the call site. However, the CFA can be relative to the base
    pointer (RBP) if the function uses RBP as the base register.

    This class will parse the code to find out if the CFA is relative to
    RSP or RBP. It will also prepare the patterns for the variables in
    the function.
    '''
    def __init__(self, vars):
        self.rsp_rbp_shift = 8
        self.reg = 'rsp'
        self.vars = vars
        pass

    def _translate_cfa_relative(self, offset):
        off = offset + self.rsp_rbp_shift
        if off == 0:
            return self.reg
        if off > 0:
            if off < 10:
                return '%s + %d' %(self.reg, off)
            return '%s + 0x%x' % (self.reg, off)
        if off > -10:
            return '%s - %d' %(self.reg, -off)
        return '%s - 0x%x' % (self.reg, -off)

    def _translate_exprloc(self, func_die, expr):
        if not expr:
            return None
        deref = False
        if len(expr) == 2 and expr[1].op_name == 'DW_OP_deref':
            expr.pop()
            deref = True
            pass
        if len(expr) == 1:
            op = expr[0]
            result = None
            if op.op_name.startswith('DW_OP_reg'):
                regno = int(op.op_name.strip('DW_OP_reg'))
                result = describe_reg_name(regno, 'x64')
            elif op.op_name == 'DW_OP_addr':
                result = '0x%x' %(op.args[0])
            elif op.op_name == 'DW_OP_fbreg':
                result = self._translate_cfa_relative(op.args[0])
                result = '[%s]' % result
                pass
            if deref and result:
                return '[%s]' %(result)
            return result

        return None

    @staticmethod
    def _compute_location(dwarfinfo, loc_attr, addr, base_addr=0):
        if loc_attr.form == 'DW_FORM_sec_offset':
            off = loc_attr.value
            loclists = dwarfinfo.location_lists()
            loclist = loclists.get_location_list_at_offset(off)
            addr_r = addr - base_addr
            result = None
            for entry in loclist:
                if entry.__class__.__name__ == 'BaseAddressEntry':
                    base_addr = entry.base_address
                    addr_r = addr - base_addr
                    continue
                if addr_r < entry.begin_offset or addr_r >= entry.end_offset:
                    continue
                parser = DWARFExprParser(dwarfinfo.structs)
                return parser.parse_expr(entry.loc_expr)
            pass
        elif loc_attr.form == 'DW_FORM_exprloc':
            parser = DWARFExprParser(dwarfinfo.structs)
            return parser.parse_expr(loc_attr.value)
        return None

    def prepare_var_patterns(self, func_die, addr):
        '''
        Prepare the patterns for the variables in the function.

        The patterns are addresses related to the RSP or RBP.
        '''
        patterns = []
        base_addr = func_die.cu.get_top_DIE().attributes['DW_AT_low_pc'].value
        for var in self.vars:
            if 'DW_AT_location' not in var.attributes:
                continue
            loc_attr = var.attributes['DW_AT_location']
            dwarfinfo = var.dwarfinfo
            expr = self._compute_location(dwarfinfo, loc_attr, addr, base_addr)
            if expr:
                expr = self._translate_exprloc(func_die, expr)
                if expr:
                    patterns.append((var.attributes['DW_AT_name'].value.decode('utf-8'), expr))
                    pass
                pass
            pass
        return patterns

    def parse_code(self, code, start_addr):
        '''
        Parse the code to find out if the CFA is relative to RSP or RBP.
        '''
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for i in md.disasm(code, start_addr):
            if i.mnemonic == 'push' and i.op_str.startswith('r'):
                self.rsp_rbp_shift += 8
            elif i.mnemonic == 'mov' and i.op_str == 'rbp, rsp':
                # Use rbp as the base register
                self.reg = 'rbp'
                break
            elif i.mnemonic == 'sub' and i.op_str.startswith('rsp, 0x'):
                # Use rsp as the base register
                self.rsp_rbp_shift += int(i.op_str[5:], 16)
                break
            elif i.mnemonic.startswith('j') or \
                 (i.mnemonic in ('ret', 'leave')):
                # A call frame should be ready before any branch
                break
            pass
        pass
    pass

def find_function(elffile, func_name):
    '''
    Find the ELF symbol of a function by name.
    '''
    for section in elffile.iter_sections():
        if section.name == '.symtab':
            for symbol in section.iter_symbols():
                if symbol['st_info']['type'] != 'STT_FUNC':
                    continue
                if symbol['st_shndx'] == 0:
                    continue
                if symbol.name != func_name:
                    continue
                return symbol
            pass
        pass
    return None

def get_sec_offset(elffile, symbol):
    '''
    Get the offset of a symbol in its section.
    '''
    section = elffile.get_section(symbol['st_shndx'])
    return symbol['st_value'] - section['sh_addr']

def create_addr2symbol_cache(elffile, code, start_addr):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    tosymcache = set()
    for i in md.disasm(code, start_addr):
        if i.mnemonic == 'call':
            if i.op_str.startswith('0x'):
                addr = int(i.op_str[2:], 16)
                tosymcache.add(addr)
                pass
            pass
        pass

    symcache = {}
    symtab = elffile.get_section_by_name('.symtab')
    for symbol in symtab.iter_symbols():
        if symbol['st_info']['type'] != 'STT_FUNC':
            continue
        for addr in tosymcache:
            if symbol['st_value'] <= addr and \
               addr < symbol['st_value'] + symbol['st_size']:
                symcache[addr] = symbol
                pass
            pass
        pass
    return symcache

def find_basic_blocks(code, start_addr):
    '''Find the basic blocks in the code.

    The basic blocks are separated by the addresses that is the target
    of a jump instruction.

    Return a list of the addresses of the start addresses of the basic
    blocks.

    '''
    bb_starts = set()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in md.disasm(code, start_addr):
        if not i.mnemonic.startswith('j'):
            continue
        if i.op_str.startswith('0x'):
            bb_starts.add(int(i.op_str, 16))
            pass
        pass
    return bb_starts

def disassemble(elffile, func_die, start_addr, code, cfa_ctx):
    cfa_ctx.parse_code(code, start_addr)

    symcache = create_addr2symbol_cache(elffile, code, start_addr)
    bblocks = find_basic_blocks(code, start_addr)
    derived_patterns = {}

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in md.disasm(code, start_addr):
        comment = ''
        if i.mnemonic == 'call':
            if i.op_str.startswith('0x'):
                addr = int(i.op_str[2:], 16)
                if addr in symcache:
                    comment = '\t; %s()' %(symcache[addr].name)
                    pass
                pass
            pass

        if i.address in bblocks:
            derived_patterns.clear()
            pass

        try:
            op_left, op_right = i.op_str.split(', ')
        except ValueError:
            op_left = i.op_str
            op_right = ''
            pass

        var_patterns = [(var, expr, False)
                        for var, expr in cfa_ctx.prepare_var_patterns(func_die, i.address)]
        var_patterns.extend([(var, expr, True)
                             for expr, var in derived_patterns.items()])
        for var, expr, derived in var_patterns:
            if op_left in derived_patterns:
                del derived_patterns[op_left]
                pass
            if i.op_str.find(expr) >= 0:
                if '[' not in expr and op_left.find(expr) >= 0:
                    # Pure registers at left size. Its value is being
                    # replaced. We don't need to annotate it.
                    continue

                if not comment:
                    comment = '\t; '
                else:
                    comment += ', '
                    pass
                comment = comment + '%s is "%s"' % (expr, var)

                if derived:
                    comment += ' (D)'
                    pass

                if i.mnemonic == 'mov' and op_right.find(expr) >= 0 and \
                   (('[' not in op_right) or ('[' in expr)):
                    # The expression matches the right operand fully.
                    # If the expression is only a part of the right
                    # operand, we don't need to add the left operand to
                    # the derived patterns.
                    if '[' not in op_left:
                        # Add to the derived patterns if the left size
                        # operand is a register, not a memory.
                        derived_patterns[op_left] = var
                        pass
                    pass
                break
            pass

        if i.mnemonic == 'call' and 'rax' in derived_patterns:
            # rax is used to store the return value of a function
            # call. Its value is being replaced. Remove it from the
            # derived patterns.
            del derived_patterns['rax']
            pass

        print("0x%x:\t%s\t%s%s" %(i.address, i.mnemonic, i.op_str, comment))
        pass
    pass

def get_func_DIE(elffile, symbol):
    '''
    Get the DIE of the function from DWARF.
    '''
    dwarfinfo = elffile.get_dwarf_info()
    for CU in dwarfinfo.iter_CUs():
        # Over all direct children of the top DIE of the CU
        for DIE in CU.iter_DIE_children(CU.get_top_DIE()):
            if DIE.tag == 'DW_TAG_subprogram':
                if 'DW_AT_name' not in DIE.attributes:
                    continue
                if 'DW_AT_declaration' in DIE.attributes:
                    continue
                if DIE.attributes['DW_AT_name'].value.decode('utf-8') == symbol.name:
                    return DIE
                pass
            pass
        pass
    return None

def iter_func_vars(DIE):
    for child in DIE.iter_children():
        if child.tag == 'DW_TAG_variable':
            yield child
            pass
        if child.tag == 'DW_TAG_lexical_block':
            for grandchild in iter_func_vars(child):
                yield grandchild
                pass
            pass
        pass
    pass

def iter_func_params(DIE):
    for child in DIE.iter_children():
        if child.tag == 'DW_TAG_formal_parameter':
            yield child
            pass
        pass
    pass

def dump_loclist(dwarfinfo, var_die):
    '''
    Dump the location list of a variable.

    A helper function for debugging.
    '''
    if 'DW_AT_location' not in var_die.attributes:
        return
    loc_attr = var_die.attributes['DW_AT_location']
    loclists = dwarfinfo.location_lists()
    loclist = loclists.get_location_list_at_offset(loc_attr.value)
    for entry in loclist:
        if entry.__class__.__name__ == 'BaseAddressEntry':
            continue
        parser = DWARFExprParser(dwarfinfo.structs)
        print(parser.parse_expr(entry.loc_expr))
        pass
    pass

def parse_frame_base(func_die):
    if 'DW_AT_frame_base' not in func_die.attributes:
        return None
    loc_attr = func_die.attributes['DW_AT_frame_base']
    if loc_attr.form == 'DW_FORM_exprloc':
        parser = DWARFExprParser(func_die.dwarfinfo.structs)
        expr = parser.parse_expr(loc_attr.value)
        return expr
    return None

def create_disassemble_report(f, func_name):
    elffile = ELFFile(f)
    symbol = find_function(elffile, func_name)
    if symbol:
        print('%s @ 0x%x (size: %d)' % (func_name,
                                        symbol['st_value'],
                                        symbol['st_size']))
        section = elffile.get_section(symbol['st_shndx'])
        print('Section: %s (off: 0x%x, virt: 0x%x)' % (section.name, section['sh_offset'], section['sh_addr']))
        print('Section offset: 0x%x' % get_sec_offset(elffile, symbol))
        soff = get_sec_offset(elffile, symbol)
        DIE = get_func_DIE(elffile, symbol)
        if not DIE:
            print('No DIE (DWARF) found for %s' % func_name)
            sys.exit(1)
            pass
        print('Frame base: %s' % parse_frame_base(DIE))
        vars = []
        for param in iter_func_params(DIE):
            if 'DW_AT_location' in param.attributes:
                vars.append(param)
                pass
            print('  parameter: %s' % (param.attributes['DW_AT_name'].value.decode('utf-8')))
            pass
        for var in iter_func_vars(DIE):
            if 'DW_AT_location' in var.attributes:
                vars.append(var)
                pass
            print('  variable: %s' % (var.attributes['DW_AT_name'].value.decode('utf-8')))
            pass
        code = section.data()[soff:soff+symbol['st_size']]
        cfa_ctx = CFACtx_X86_RSP_RBP(vars)
        disassemble(elffile, DIE, symbol['st_value'], code, cfa_ctx)
    else:
        print('Function %s not found' % func_name)
        pass
    pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Disassemble a function')
    parser.add_argument('elffile', type=str, help='ELF file')
    parser.add_argument('func', type=str, help='Function name')
    args = parser.parse_args()

    fname = args.elffile
    func_name = args.func

    with open(fname, 'rb') as f:
        create_disassemble_report(f, func_name)
        pass
    pass


