import logging
import json
import os
import sys

import ida_name
import idautils
import ida_funcs

from ida_typeinf import (
    tinfo_t,
    get_idati,
    udt_type_data_t,
    udm_t,
    array_type_data_t,
    enum_type_data_t,
    bitfield_type_data_t, func_type_data_t,
)
from ida_nalt import get_input_file_path, retrieve_input_file_md5
from reshare.helpers import *

# -----------------------------------------------------------------------------

LOG_FILE = None
LOG_LEVEL = logging.DEBUG
EXPORT_PATH = "/tmp/reshare.json"

# -----------------------------------------------------------------------------

resh_void = ReshDataTypePy(
    name="void", size=0, content=ReshDataTypeContentPrimitivePy()
)
resh_pvoid = ReshDataTypePy(
    name="void*",
    size=0,
    content=ReshDataTypeContentPointerPy(target_type=resh_void.name),
)

RESH_TYPE_CACHE: dict[str, ReshDataType] = {
    "void": resh_void,
    "VOID": resh_void,
    "void*": resh_pvoid,
    "PVOID": resh_pvoid,
    "VOID*": resh_pvoid,
}

UNK_ID = 0  # ID for unknown things

logger = logging.getLogger("pyghidra-export")

log_fmt = logging.Formatter("[%(levelname)s](%(asctime)s) %(message)s")
handlers = [
    logging.StreamHandler(sys.stdout),
]

if LOG_FILE is not None:
    handlers.append(logging.FileHandler(LOG_FILE))

logger.handlers.clear()
logger.setLevel(LOG_LEVEL)
for h in handlers:
    h.setFormatter(log_fmt)
    h.setLevel(LOG_LEVEL)
    logger.addHandler(h)

logger.info(f"Starting export {len(RESH_TYPE_CACHE)}...")


class ReshIDAException(Exception):
    pass


def _debug_object(o):
    for a in dir(o):
        if not a.startswith("is_"):
            continue
        method = getattr(o, a)
        try:
            x = method()
            logger.debug(f"{o} {a} = {x}")
        except TypeError:
            pass


def get_unique():
    global UNK_ID
    ret = UNK_ID
    UNK_ID += 1
    return ret


def get_bitfield_range(
    bitfields: list[tuple[int, int]], range: tuple[int, int]
) -> None | tuple[int, int]:
    for start, length in bitfields:
        if start <= range[0] <= start + length:
            # if range[0]+range[1]>start+length:
            #    raise ReshIDAException("Overlapping bitfields!")
            return start, length
    return None


def get_udt_members(T: tinfo_t) -> list[ReshStructureMemberPy]:
    details = udt_type_data_t()
    ret: list[ReshStructureMemberPy] = []
    if not T.get_udt_details(details):
        raise ReshIDAException("Can't retrieve struct UDT details")
    bitfields: dict[tuple[int, int], ReshStructureMember] = {}
    for member in details:
        m: udm_t = member
        logger.info(
            f"  Member {T.get_type_name()}.{m.name}({m.size})"
        )  # Note: member unions have no name?
        byte_offset = int(int(m.offset) / 8)  # Sizes are in bytes, offsets in bits?
        if m.type.is_bitfield():
            r = get_bitfield_range(list(bitfields), (byte_offset, 1))
            if r is not None:
                bitfields[r].name += f"_{m.name}"  # TODO proper bitfield representation
                continue

        resh_member_type = get_resh_data_type_from_ida(m.type)
        if resh_member_type is not None:
            m_name = m.name
            if m.type.is_bitfield():
                m_name = f"resh_bf_{m.name}"

            if len(m_name) == 0:  # Unions don't have names!
                m_name = "resh_member_%08X" % (get_unique())

            # WARNING
            # If we move m out of this scope it gets all messed up!
            resh_member = ReshStructureMemberPy(
                name=m_name, type=resh_member_type.name, offset=byte_offset
            )
            if m.type.is_bitfield():
                bitfields[(byte_offset, resh_member_type.size)] = resh_member
            ret.append(resh_member)
        else:
            raise ReshIDAException(f"Can't create member type for {T.name}.{m.name}")
    return ret


def get_resh_func_content_from_ida(T: tinfo_t) -> ReshDataTypeContentFunctionPy:
    try:
        arguments: list[ReshFunctionArgument] = []
        logger.debug(f"FUNCTION: {T}")

        for i, arg in enumerate(T.iter_func()):
            logger.debug(f"FUCK {i}")
            arg_name = arg.name
            if len(arg.name) == 0:
                arg_name = f"resh_param{i}"
            arg_type = get_resh_data_type_from_ida(arg.type)
            arguments.append(ReshFunctionArgumentPy(type=arg_type.name, name=arg_name))
        ret_type = T.get_rettype()
        if ret_type is None:
            raise ReshIDAException("IDA function prototype doesn't have a return type!")
        resh_ret_type = get_resh_data_type_from_ida(ret_type)
        if resh_ret_type is None:
            raise ReshIDAException("Can't find function return type!")
        return ReshDataTypeContentFunctionPy(
            arguments=arguments, return_type=resh_ret_type.name
        )
    except TypeError:
        logging.error(f"According to IDA this function is not a function: {T}")
        tmp=func_type_data_t()
        logger.debug(f"  is_func: {T.is_func()} details: {T.get_func_details(tmp)}")
        _debug_object(T)
        raise


def get_resh_data_type_from_ida(T: tinfo_t) -> ReshDataType | None:
    content: ReshDataTypeContent = ReshDataTypeContentPrimitivePy()

    T_size = int(T.get_size())
    if T_size == 0xFFFFFFFFFFFFFFFF:  # Checking for -1
        # This usually indicates a typedef or forward declaration
        T_size = 0  # TODO should we use a different indicator value?

    T_name: str = T.get_type_name()

    if T_name is None or len(T_name) == 0:
        if T.is_arithmetic() and T_size > 0:
            # Unnamed primitive types are just sparkly ints
            T_name=f"resh_int%d" % (T_size*8)
        else:
            T_name = "resh_unk_%08X" % (get_unique(),)

    logger.info(
        f"{T_name} ({T.get_size()}) UDT: {T.is_udt()} Typedef: {T.is_typedef()} Typeref: {T.is_typeref()}"
    )
    if T_name in RESH_TYPE_CACHE:
        return RESH_TYPE_CACHE[T_name]


    ret = ReshDataType(name=T_name, size=T_size, content=None, modifiers=[])

    RESH_TYPE_CACHE[T_name] = ret

    if T.is_arithmetic():
        logger.debug(f"Handling {T_name} as arithmentic")
        content = ReshDataTypeContentPrimitivePy()
    elif T.is_ptr() or T.is_funcptr():
        # We handle pointers before the early bail at typedefs
        logger.debug(f"Handling {T_name} as pointer")
        base_type = T.get_pointed_object()
        base_resh_type = get_resh_data_type_from_ida(base_type)
        if T_name.startswith("resh"):
            ret.name = base_resh_type.name + "*"
            del RESH_TYPE_CACHE[T_name]
            RESH_TYPE_CACHE[ret.name] = ret
        if base_resh_type is not None:
            content = ReshDataTypeContentPointerPy(target_type=base_resh_type.name)
        else:
            raise ReshIDAException("Base type not found for pointer")
    elif T.is_func():
        # We handle functions before the early bail at typedefs
        logger.debug(f"Handling {T_name} as function")
        try:
            content = get_resh_func_content_from_ida(T)
        except TypeError:
            content = ReshDataTypeContentFunctionPy(
                arguments=[], return_type=RESH_TYPE_CACHE["void"]
            )
            ret.name += "_idaerr"
            del RESH_TYPE_CACHE[T_name]
            RESH_TYPE_CACHE[ret.name] = ret
    elif T.is_typedef() or T.is_forward_decl():
        logger.debug(f"Handling {T_name} as typedef")
        content = ReshDataTypeContentPrimitivePy()
    elif T.is_bitfield():
        logger.debug(f"Handling {T_name} as bitfield")
        bf_details = bitfield_type_data_t()
        if not T.get_bitfield_details(bf_details):
            raise ReshIDAException("Can't get bitfield details")
        # logger.debug(f"BITFIELD: {T_name}")
        content = ReshDataTypeContentPrimitivePy()
        ret.size = bf_details.nbytes
        ret.name += "_bf"
    elif T.is_struct() or T.is_union():
        logger.debug(f"Handling {T_name} as struct/union")
        members = get_udt_members(T)
        if T.is_struct():
            content = ReshDataTypeContentStructurePy(members=members)
        else:
            content = ReshDataTypeContentUnionPy(members=members)
    elif T.is_array():
        logger.debug(f"Handling {T_name} as array")
        array_details = array_type_data_t()
        if not T.get_array_details(array_details):
            raise ReshIDAException(f"Can't get array details for {T_name}")
        elem_type: tinfo_t = array_details.elem_type  # IDAPython documentation is lies!
        logger.debug(f"ARRAY DETAILS: {T_name} {elem_type} {type(elem_type)}")
        elem_resh_type = get_resh_data_type_from_ida(elem_type)
        content = ReshDataTypeContentArrayPy(
            base_type=elem_resh_type.name, length=array_details.nelems
        )
    elif T.is_enum():
        logger.debug(f"Handling {T_name} as enum")
        enum_details = enum_type_data_t()
        if not T.get_enum_details(enum_details):
            raise ReshIDAException(f"Can't get enum details for {T_name}")
        enum_size = enum_details.size()
        enum_members: list[ReshEnumMember] = []
        for e in T.iter_enum():
            em = ReshEnumMember(name=e.name, value=e.value)
            enum_members.append(em)
        base_type_name = f"{T_name}_enum_base"
        base_type = ReshDataTypePy(
            name=base_type_name,
            content=ReshDataTypeContentPrimitivePy(),
            size=enum_size,
        )
        RESH_TYPE_CACHE[base_type_name] = base_type
        content = ReshDataTypeContentEnumPy(
            base_type=base_type.name, members=enum_members
        )
    elif T_size == 0:
        # If nothing matches but size is 0, let's just scream into the void
        del RESH_TYPE_CACHE[T_name]
        return RESH_TYPE_CACHE["void"]
    else:
        logger.error(f"Can't handle type {T_name}")
        _debug_object(T)
        # raise ReshIDAException("Unhandled type!")

    if content is None:
        logger.error(f"Couldn't create content for {T_name}")

    ret.content = content

    return ret


def get_data_types() -> list[ReshDataType]:
    type_info_lib = get_idati()
    ret = []
    for t in type_info_lib.named_types():
        t: tinfo_t = t
        logger.info(f"{t.get_final_type_name()}")
        get_resh_data_type_from_ida(t)
    for n, r in RESH_TYPE_CACHE.items():
        if r is not None:
            if r.content is None:
                raise ReshIDAException("????????")
            ret.append(r)
    return ret


def address_to_resh(offset: int) -> ReshAddress:
    return ReshAddress(
        list(offset.to_bytes(8, byteorder="little", signed=False)),
        "default_ea",
    )


def get_function_symbols() -> list[ReshSymbol]:
    ret: list[ReshSymbol] = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        prototype = func.prototype
        # https://reverseengineering.stackexchange.com/a/32066
        func_name = ida_name.get_ea_name(
            ea, ida_name.GN_DEMANGLED | ida_name.GN_SHORT
        ).split("(")[0]
        if not prototype:
            logger.error(f"{ea:x}: {func_name} has no prototype.")
            continue

        resh_func_type_content = get_resh_func_content_from_ida(prototype)
        resh_func_type = ReshDataTypePy(
            name=f"func_{get_unique()}_{func_name}",
            size=0,
            content=resh_func_type_content,
        )
        RESH_TYPE_CACHE[resh_func_type.name] = resh_func_type
        resh_sym = ReshSymbolPy(
            name=func_name,
            type=resh_func_type.name,
            address=address_to_resh(ea),
            confidence=ReshSymbolConfidence.GUESS,
            labels=[],
        )
        ret.append(resh_sym)
    return ret


export = ResharePy(
    project_name=os.path.basename(get_input_file_path()),
    target_md5=retrieve_input_file_md5().hex(),
)

export.symbols.extend(get_function_symbols())
export.data_types.extend(get_data_types())

with open(EXPORT_PATH, "w") as out:
    out.write(json.dumps(export.to_json_data(), indent=2))

logger.info(f"{EXPORT_PATH} written ({len(RESH_TYPE_CACHE)})")
