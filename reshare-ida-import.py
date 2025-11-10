from reshare import *
from ida_typeinf import *
from ida_domain import Database
from ida_domain.types import TypeDetails
from ida_name import get_name_ea
from ida_nalt import get_tinfo
from typing import Iterable
import json
import logging
import ida_idaapi
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO, format="[%(levelname)s][%(thread)d](%(asctime)s) %(message)s")
logger=logging.getLogger("reshare-ida-import")

# -------------------------------

IMPORT_PATH = "/tmp/reshare.json"
FUNC_SYM_IMPORT_ALLOW_RE: re.Pattern | None = None
FUNC_SYM_IMPORT_DENY_RE: re.Pattern | None = None
TYPE_IMPORT_ALLOW_RE: re.Pattern | None = None
TYPE_IMPORT_DENY_RE: re.Pattern | None = None

# -------------------------------

class ReshIDAException(Exception):
    pass

# Not being able to roll back IDB state (good luck with Undo!) is quite enough
# let's not litter global structures too :P
# We'll just reinstantiate this class on every run...
@dataclass
class ReshIDAState:
    resh_data_types: dict[str, ReshDataType]
    ida_data_types: dict[str, tinfo_t]

# ...like so:
S=ReshIDAState({},{})

def get_ida_type_by_name(name: str) -> tinfo_t:
    if name in S.resh_data_types:
        return get_ida_type_from_resh_type(S.resh_data_types[name])
    else:
        raise ReshIDAException("Can't find data type '%s'" % (name,))

def get_tinfo_by_ea(ea):
    tif = tinfo_t()
    if get_tinfo(tif, ea):          # ✅ retrieve the stored type【1】
        return tif
    return None

def get_proto_data(tif):
    # `func_type_data_t` describes the calling convention, return type, args, etc【2】
    ftd = func_type_data_t()
    if tif.get_func_type_data(ftd):
        return ftd
    return None

def describe_function(ea):
    tif = get_tinfo_by_ea(ea)
    if not tif:
        print("No type information for 0x%X" % ea)
        return

    ftd = get_proto_data(tif)
    if not ftd:
        print("Type is not a function prototype")
        return

    # ----- calling convention -----
    cc_idx = ftd.get_cc()                     # integer code【3】
    cc_name = get_cc_name(cc_idx)    # e.g. "__stdcall", "__cdecl", ...

    # ----- return type -----
    ret_str = print_tinfo(ftd.rettype)

    # ----- parameters -----
    params = []
    for i, arg in enumerate(ftd.args):
        # arg.type is a tinfo_t; convert to readable form
        type_str = print_tinfo(arg.type)
        name_str = arg.name if arg.name else f"arg{i}"
        params.append(f"{type_str} {name_str}")

    # ----- pretty output -----
    proto = f"{ret_str} {ida_funcs.get_func_name(ea)}({', '.join(params)})"
    print(f"Address: 0x{ea:x}")
    print(f"Calling convention: {cc_name}")
    print(f"Prototype: {proto}")


def set_function_signature(name: str, ida_type: tinfo_t):
    logger.info(f"Function signature '{name}'")
    #resh_type_content: ReshDataTypeContentFunction = resh_type.content # typing:ignore
    func_ea=get_name_ea(ida_idaapi.BADADDR, name)
    if func_ea is None:
        logger.warning(f"Can't find function address for '{name}'")
        return

    # https://gist.github.com/icecr4ck/7a7af3277787c794c66965517199fc9c?permalink_comment_id=5226755#gistcomment-5226755
    if not apply_tinfo(func_ea, ida_type, TINFO_DEFINITE):
        logger.error(f"Failed to apply new type to function at 0x{func_ea:X}")
    else:
        logger.info(f"Successfully applied function prototype to {name}")
    # https://reverseengineering.stackexchange.com/questions/30786/idapython-get-function-parameter-type-name
    # https://reverseengineering.stackexchange.com/questions/18141/ida-changing-type-of-arguments-to-local-type
    #tif = tinfo_t()
    #funcdata = func_type_data_t()
    #if not get_tinfo(tif, func_ea):
    #    logger.warning(f"Can't get type info for {func_ea}")
    #    return
    #if not tif.get_func_details(funcdata):
    #    logger.warning(f"Can't get function type info for {func_ea}")
    #    return
    #for i, resh_arg in enumerate(resh_type_content.arguments):
    #    if i>=len(funcdata):
    #        #TODO
    #        continue
    #    print(funcdata[i].type, resh_arg)

    return

DEBUG_DT=None
def get_ida_type_from_resh_type(resh_type: ReshDataType)->tinfo_t|None:
    global DEBUG_DT
    type_name=resh_type.name.strip()
    #print(type_name)

    # We must give the type a name before caching, otherwise self-references will fail
    # Naturally, tinfo_t(name:str) doesn't name a new type but tries to look up one...
    ret : tinfo_t = tinfo_t()
    ret.get_named_type(None, type_name) # We create a typedef to show in case of recursion
    logger.info(f"get_ida_type_from_resh_type {type_name}")

    if type_name in S.ida_data_types:
        logger.info("IDA Type already cached")
        return S.ida_data_types[type_name]

    # This get_named_type() retrieves the tinfo_t from the default type info DB
    # ida_typeinf.get_named_type() on the other hand checks if a type exists
    # Type info is wrong too...
    local_tif: tinfo_t =get_idati().get_named_type(type_name) # type: ignore
    if local_tif is not None:
        logger.info("Local type found, returning")
        S.ida_data_types[resh_type.name.strip()]=local_tif
        #print(local_tif, type(local_tif))
        return local_tif
    if resh_type.content.type == "PRIMITIVE":
        if resh_type.size == 1:
            ret.create_simple_type(BT_INT8)
        elif resh_type.size == 2:
            ret.create_simple_type(BT_INT16)
        elif resh_type.size == 4:
            ret.create_simple_type(BT_INT32)
        elif resh_type.size == 8:
            ret.create_simple_type(BT_INT64)
        elif resh_type.size == 0:
            return None # T_VOID?
        else:
            atd=array_type_data_t(0,resh_type.size)
            ret.create_array(atd)
        S.ida_data_types[resh_type.name]=ret
    elif resh_type.content.type == "ARRAY":
        array_content: ReshDataTypeContentArray = resh_type.content # type:ignore
        ida_target_type=get_ida_type_by_name(array_content.base_type.type_name)
        #ret=tinfo_t(ida_target_type)
        atd = array_type_data_t()
        atd.base=0
        atd.nelems=array_content.length
        atd.elem_type=ida_target_type
        ret.create_array(atd)
        S.ida_data_types[resh_type.name] = ret
    elif resh_type.content.type == "POINTER":
        ptr_content: ReshDataTypeContentPointer = resh_type.content
        S.ida_data_types[type_name] = ret
        ida_target_type=get_ida_type_by_name(ptr_content.target_type.type_name)
        if ida_target_type is None:
            print(f"Can't create pointer for {ptr_content.target_type.type_name}")
            return None
        else:
            ret.create_ptr(ida_target_type)
        #print(ret, repr(ret.is_ptr()), ret.get_unpadded_size())
    elif resh_type.content.type=="ENUM":
        enum_content: ReshDataTypeContentEnum = resh_type.content # type: ignore
        ret.create_enum()
        S.ida_data_types[type_name] = ret
        #TODO
    elif resh_type.content.type=="UNION":
        #print(resh_type)
        union_content: ReshDataTypeContentUnion = resh_type.content # type: ignore
        udt = udt_type_data_t()
        udt.is_union = True
        for m in union_content.members:
            member_type=get_ida_type_by_name(m.type.type_name)
            if member_type is None:
                raise ReshIDAException(f"Can't find union member type {m.type.type_name}")
            udt_member=udt.add_member(m.name,member_type,m.offset)
            #print(udt_member.name, udt_member.offset, udt_member.size)

        if not ret.create_udt(udt, BTF_UNION):
            # TODO If we can't figure out union offsets we just return empty for now
            udt = udt_type_data_t()
            udt.is_union = True
            ret.create_udt(udt, BTF_UNION)
            #raise ReshIDAException("Can't create UDT for union '%s'" % (type_name))
        S.ida_data_types[type_name] = ret
    elif resh_type.content.type=="STRUCTURE":
        logger.info(f"Creating structure {type_name}")
        struct_content: ReshDataTypeContentStructure = resh_type.content # type: ignore
        udt = udt_type_data_t()
        S.ida_data_types[type_name] = ret # Self-references!
        # IDA freaks out if offsets don't line up so we just add members in order and hope for the best

        udm = udm_t()
        for m in struct_content.members:
            member_type = get_ida_type_by_name(m.type.type_name)
            if member_type is None:
                raise ReshIDAException(f"Can't find member type {m.type.type_name}")
            #udt_member=udt.add_member(m.name, member_type)
            udm.name = m.name
            udm.type = member_type
            logger.info(f"Adding struct member {m.name} to {type_name}")
            udt.push_back(udm)
            #if udt_member is None:
            #    raise ReshIDAException("Can't add UDT member to struct '%s'" % (type_name,))
            #print(udt_member.name, udt_member.offset, udt_member.size)
        logger.info(f"Created members for {type_name}")
        # Do as Romans do: we must check status codes to see where things go wrong
        # See also JPL #7
        if not ret.create_udt(udt):
            raise ReshIDAException("Can't create UDT for struct '%s'" % (type_name))
        logger.info(f"successfully created {type_name}")
        S.ida_data_types[type_name] = ret
        #print("Added structure", ret)
    elif resh_type.content.type == "FUNCTION":
        # https://gist.github.com/icecr4ck/7a7af3277787c794c66965517199fc9c?permalink_comment_id=5226755#gistcomment-5226755
        function_content : ReshDataTypeContentFunction = resh_type.content # type: ignore
        ftd = func_type_data_t()
        ret_type=get_ida_type_by_name(function_content.return_type.type_name)
        if ret_type is None:
            logger.warning(f"Can't find return type {function_content.return_type.type_name} for function prototype")
            ret_type=tinfo_t("void *")
        ftd.rettype=ret_type
        for arg in function_content.arguments:
            fa = funcarg_t()
            fa.name=arg.name
            arg_type=get_ida_type_by_name(arg.type.type_name)
            if arg_type is None:
                logger.warning(f"Can't find argument type {arg.type.type_name} for {arg.name}")
                arg_type=tinfo_t("void*")
            fa.type=arg_type
            ftd.push_back(fa)
        if not ret.create_func(ftd):
            raise ReshIDAException(f"Couldn't create function prototype {type_name}")
        S.ida_data_types[type_name] = ret
    else:
        #ret.get_named_type(type_name)
        ret.create_simple_type(BT_INT8)
        S.ida_data_types[type_name] = ret

    # Apparently this resets everything to a typedef
    #ret.get_named_type(None, type_name)
    if ret is not None:
        try:
            ret.set_named_type(None,type_name, 0x404)
            logger.info(f"Successfully named and saved '{type_name}'")
        except:
            #logger.error(f"Can't add name to type '{type_name}'")
            # We should never end up here since we should have a smol typedef for everything
            raise ReshIDAException(f"Can't add name to type '{type_name}'")
    return ret

def import_data_types(resh: Reshare):
    for dt in resh.data_types:
        S.resh_data_types[dt.name] = dt

    # ... IDA doesn't support transactions :P ...

    default_til=get_idati()
    for dt in resh.data_types:
        if (
            TYPE_IMPORT_ALLOW_RE is not None
            and TYPE_IMPORT_ALLOW_RE.fullmatch(dt.name) is None
        ) or (
            TYPE_IMPORT_DENY_RE is not None
            and TYPE_IMPORT_DENY_RE.fullmatch(dt.name) is not None
        ):
            continue
        logger.info(f"[*] Importing type {dt.name}")
        try:
            ida_dt = get_ida_type_from_resh_type(dt)

        except ReshIDAException as e:
            logger.error("[-] Couldn't import '%s' :(\n>> %s <<" % (dt.name, str(e)))
            #raise


def import_symbols(resh: Reshare):
    for sym in resh.symbols:
        if sym.type is None:
            continue
        resh_type=S.resh_data_types[sym.type.type_name]
        if sym.type.type_name not in S.ida_data_types:
            logger.warning(f"Can't find {sym.type.type_name}")
            continue
        ida_type: tinfo_t = S.ida_data_types[sym.type.type_name]
        if ida_type is None:
            logger.warning(f"Symbols IDA type is None ({sym.type.type_name})")
            continue
        if resh_type.content.type=="FUNCTION":
            if (
                FUNC_SYM_IMPORT_ALLOW_RE is not None
                and FUNC_SYM_IMPORT_ALLOW_RE.fullmatch(sym.name) is None
            ) or (
                FUNC_SYM_IMPORT_DENY_RE is not None
                and FUNC_SYM_IMPORT_DENY_RE.fullmatch(sym.name) is not None
            ):
                continue
            set_function_signature(sym.name, ida_type)
        else:
            pass
            # TODO


def main():
    db = Database()
    logger.info(f"IDA Data Types Size {len(S.ida_data_types)}")
    for t in db.types:
        S.ida_data_types[TypeDetails.from_tinfo_t(t).name]=t
    logger.info(f"IDA Data Types Size {len(S.ida_data_types)}")
    with open(IMPORT_PATH, "r") as input_json:
        data = json.load(input_json)
        resh = Reshare.from_json_data(data)
        import_data_types(resh)
        import_symbols(resh)
    logger.info(f"IDA Data Types Size {len(S.ida_data_types)}")
    #print(repr(ida_data_types))


if __name__ == "__main__":
    main()
