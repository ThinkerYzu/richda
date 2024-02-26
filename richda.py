from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.descriptions import describe_reg_name
import capstone
import sys

def find_function(elffile, func_name):
    for section in elffile.iter_sections():
        if section.name == '.symtab':
            for symbol in section.iter_symbols():
                if symbol['st_info']['type'] != 'STT_FUNC':
                    continue
                if symbol.name != func_name:
                    continue
                return symbol
            pass
        pass
    return None

def get_sec_offset(elffile, symbol):
    section = elffile.get_section(symbol['st_shndx'])
    return symbol['st_value'] - section['sh_addr']

def addr2symbol(elffile, addr):
    symtab = elffile.get_section_by_name('.symtab')
    for symbol in symtab.iter_symbols():
        if symbol['st_info']['type'] != 'STT_FUNC':
            continue
        if symbol['st_value'] <= addr and \
           addr < symbol['st_value'] + symbol['st_size']:
            return symbol
        pass
    return None

def prepare_var_patterns(func_die, addr, vars, cfa_ctx):
    patterns = []
    base_addr = func_die.cu.get_top_DIE().attributes['DW_AT_low_pc'].value
    for var in vars:
        if 'DW_AT_location' not in var.attributes:
            continue
        loc_attr = var.attributes['DW_AT_location']
        dwarfinfo = var.dwarfinfo
        expr = compute_location(dwarfinfo, loc_attr, addr, base_addr)
        if expr:
            expr = translate_exprloc(func_die, expr, cfa_ctx)
            if expr:
                patterns.append((var.attributes['DW_AT_name'].value.decode('utf-8'), expr))
                pass
            pass
        pass
    return patterns

def disassemble(func_die, start_addr, code, vars):
    cfa_ctx = ['rsp', 8]        # CFA is rsp+8 at the entry. The 8 is
                                # for return address.
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    symcache = {}
    rsp_adj = False
    for i in md.disasm(code, start_addr):
        comment = ''
        if i.mnemonic == 'call':
            if i.op_str.startswith('0x'):
                addr = int(i.op_str[2:], 16)
                if addr not in symcache:
                    sym = addr2symbol(elffile, addr)
                    if sym:
                        symcache[addr] = sym
                    else:
                        symcache[addr] = None
                        pass
                    pass
                if symcache[addr]:
                    comment = '\t; %s()' %(symcache[addr].name)
                    pass
                pass
            pass
        elif i.mnemonic == 'push' and i.op_str.startswith('r') and not rsp_adj:
            cfa_ctx[1] = cfa_ctx[1] + 8
            pass
        elif i.mnemonic == 'sub' and i.op_str.startswith('rsp, 0x') and not rsp_adj:
            cfa_ctx[1] += int(i.op_str[4:], 16)
            rsp_adj = True
            pass
        var_patterns = prepare_var_patterns(func_die, i.address, vars, cfa_ctx)
        for var, expr in var_patterns:
            if i.op_str.find(expr) >= 0:
                if not comment:
                    comment = '\t; '
                else:
                    comment += ', '
                    pass
                comment = comment + '%s is "%s"' % (expr, var)
                break
            pass
        print("0x%x:\t%s\t%s%s" %(i.address, i.mnemonic, i.op_str, comment))
        pass
    pass

def get_func_DIE(elffile, symbol):
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

def compute_location(dwarfinfo, loc_attr, addr, base_addr=0):
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

def dump_loclist(dwarfinfo, var_die):
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

def translate_exprloc(func_die, expr, cfa_ctx=None):
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
        elif op.op_name == 'DW_OP_fbreg' and cfa_ctx:
            result = '%s + 0x%x' % (cfa_ctx[0], cfa_ctx[1] + op.args[0])
        if deref and result:
            return '[%s]' %(result)
        return result
        
    return None

def parse_frame_base(func_die):
    if 'DW_AT_frame_base' not in func_die.attributes:
        return None
    loc_attr = func_die.attributes['DW_AT_frame_base']
    if loc_attr.form == 'DW_FORM_exprloc':
        parser = DWARFExprParser(func_die.dwarfinfo.structs)
        expr = parser.parse_expr(loc_attr.value)
        return expr
    return None

fname = sys.argv[1]
func_name = sys.argv[2]
with open(fname, 'rb') as f:
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
        disassemble(DIE, symbol['st_value'], code, vars)
        pass
    pass

