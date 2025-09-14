"""
Author: Milankovo, 2025
License: MIT
"""

import idaapi
import logging

logger = logging.getLogger("EnumsHelper")
logger.setLevel(logging.INFO)


NETNODE_NAME = "$ enums_helper"
last_enum_used: str | None = None


class EnumChooser(idaapi.Choose):
    def __init__(self, title="Please choose enum", values: list[int] | None = None):
        self.values = values or []
        super().__init__(
            title,
            cols=[
                ["#name of the enum#Enumeration", idaapi.Choose.CHCOL_PLAIN | 30],
                ["#Matching member already present in the enum#Members", idaapi.Choose.CHCOL_PLAIN | 20],
                ["#List of number that will be added to the enum#Missing", idaapi.Choose.CHCOL_PLAIN | 30],
                ["#number of matching members#matching", idaapi.Choose.CHCOL_DEC | 5],
                ["#number of missing members#missing", idaapi.Choose.CHCOL_DEC | 5],
            ],
            flags=idaapi.Choose.CH_MODAL,
        )
        self.items = self._get_enum_list()

    def _get_enum_list(self):
        enums = [("<NEW>", "", "", "", "")]

        for i in range(1, idaapi.get_ordinal_limit()):
            if not idaapi.is_type_choosable(None, i):  # type: ignore
                continue

            t = idaapi.tinfo_t(ordinal=i)
            if not t.is_enum():
                continue
            name = t.get_type_name()
            if not name:
                logger.debug(f"Skipping unnamed enum with ordinal {i}: {t.dstr()}")
                continue

            members = []
            missing = []
            for value in self.values:
                idx, item = t.get_edm_by_value(value)
                if idx != -1:
                    members.append(f"{value}={item.name}")
                else:
                    missing.append(str(value))

            members = list(sorted(set(members)))

            members_str = ", ".join(members)
            missing_str = ", ".join(missing)

            enums.append((name, members_str, missing_str, str(len(members)), str(len(missing))))
        return enums

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        return self.items[n][0]

    def OnRefresh(self, n):
        self.items = self._get_enum_list()
        return len(self.items)


def ask_new_enum() -> idaapi.tinfo_t | None:
    new_enum_name = idaapi.ask_ident("", "Enter new enum name:")
    if not new_enum_name:
        logger.warning("No name provided for the new enumeration. Operation aborted.")
        return None

    tid = idaapi.create_enum_type(
        new_enum_name, idaapi.enum_type_data_t(), 0, idaapi.no_sign, False
    )
    if tid == idaapi.BADADDR:
        logger.error(
            f"Error: Unable to create a new enumeration named '{new_enum_name}'."
        )
        return None

    return idaapi.tinfo_t(tid=tid)


def choose_or_create_enum(values: list[int]) -> idaapi.tinfo_t | None:
    chooser = EnumChooser(
        values=values,
        title="Please choose enum",
    )
    selected = chooser.Show(modal=True)
    if selected < 0:
        return None

    selected_enum_name = chooser.items[selected][0]
    if selected_enum_name == "<NEW>":
        return ask_new_enum()
    else:
        return idaapi.tinfo_t(name=selected_enum_name)


class base_action_handler_t(idaapi.action_handler_t):
    action_name: str
    action_label: str
    action_shortcut: str

    @classmethod
    def register(cls: type["base_action_handler_t"]):
        action = idaapi.action_desc_t(
            cls.action_name, cls.action_label, cls(), cls.action_shortcut
        )
        idaapi.register_action(action)

    @classmethod
    def unregister(cls: type["base_action_handler_t"]):
        idaapi.unregister_action(cls.action_name)

    @classmethod
    def register_actions(cls: type["base_action_handler_t"]):
        for action in cls.__subclasses__():
            action.register()

    @classmethod
    def unregister_actions(cls: type["base_action_handler_t"]):
        for action in cls.__subclasses__():
            action.unregister()


def update_number_format_with_enum_name(nf: idaapi.number_format_t, enum_name: str):
    shift = idaapi.get_operand_type_shift(ord(nf.opnum))
    mask = 0xF << shift
    enum = 0x8 << shift
    nf.flags = (nf.flags & ~mask) | enum
    nf.type_name = enum_name


def dump_user_numforms(vu):
    for f, s in vu.cfunc.numforms.items():
        logger.info(
            f"found user numform ({f.ea:x}, {f.opnum}) ({ord(s.opnum)}, {s.flags:x}, {s.type_name})"
        )


def update_number_formats(
    cfunc: idaapi.cfuncptr_t, ea: int, nf: idaapi.number_format_t
):
    # very annoying idapython feature/bug: hexrays.hpp items with type 'char' are mapped to 'str' instead of 'int'
    # so we need to convert it back to int
    opnum = nf.opnum
    if isinstance(opnum, str):
        opnum = ord(opnum)

    loc = idaapi.operand_locator_t(ea, opnum)

    if loc in cfunc.numforms:  # type: ignore
        del cfunc.numforms[loc]  # type: ignore
    cfunc.numforms[loc] = nf  # type: ignore

    cfunc.save_user_numforms()


def add_enum_member(ti: idaapi.tinfo_t, v: int) -> bool:
    idx, edm = ti.get_edm_by_value(v)

    if idx != -1:
        logger.info(
            f"Using existing enum member '{edm.name}' at index {idx} with value {edm.value}."
        )
        return True

    i = 0
    while True:
        default_name = f"val_{v}"
        if i > 0:
            default_name = f"{default_name}_{i}"
        i += 1

        new_name = idaapi.ask_ident(
            default_name,
            f"Name for new enum member of {ti.get_type_name()}",
        )

        if not new_name:
            logger.warning(
                "No name provided for the new enum member. Operation aborted."
            )
            return False

        try:
            ti.add_edm(new_name, v)
            return True
        except ValueError as e:
            if "name is used in another enum" in str(e):
                logger.warning(
                    f"Name '{new_name}' is already used in another enum. Please choose a different name."
                )
                continue
            logger.error(f"Error: Failed to add the enum member. {e}")
            return False


def switch_has_cases_not_covered_by_enum(citem: idaapi.ctree_item_t) -> bool:
    switch = citem_to_switch(citem)
    if switch is None:
        return False

    type_name = switch.mvnf.nf.type_name
    ti = idaapi.tinfo_t(name=type_name)
    if not ti.is_enum():
        return True

    for case in switch.cases:
        for v in case.values:
            idx, edm = ti.get_edm_by_value(v)
            if idx == -1:
                return True
    return False


def is_number(ctx: idaapi.action_ctx_base_t):
    if ctx.widget_type != idaapi.BWN_PSEUDOCODE:
        return idaapi.AST_DISABLE_FOR_WIDGET

    vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
    if vu is None:
        return idaapi.AST_DISABLE

    vu.get_current_item(idaapi.USE_KEYBOARD)

    if not vu.item.is_citem():
        return idaapi.AST_DISABLE

    num = vu.get_number()
    if num is None:
        return idaapi.AST_DISABLE

    if num.nf.is_enum() and not switch_has_cases_not_covered_by_enum(vu.item):
        return idaapi.AST_DISABLE

    return idaapi.AST_ENABLE


def update_cnumber(num: idaapi.cnumber_t, ti: idaapi.tinfo_t, vu: idaapi.vdui_t):
    update_number_format_with_enum_name(num.nf, ti.get_type_name())

    citem: idaapi.ctree_item_t = vu.item
    if not citem.is_citem():
        return

    if not citem.is_citem():  # tail, etc.
        logger.debug("Not a citem")
        return

    it = citem.it

    citem_ea = citem.get_ea()
    if citem_ea != it.ea:
        logger.warning(
            f"inconsistent ea between citem.get_ea()={citem_ea:x} and citem.it.ea={it.ea:x} for {it.to_specific_type.opname}"  # type: ignore
        )

    update_number_formats(vu.cfunc, it.ea, num.nf)
    if it.is_expr():
        citem.e.type = ti

    vu.cfunc.refresh_func_ctext()


def citem_to_switch(citem: idaapi.ctree_item_t) -> idaapi.cswitch_t | None:
    if not citem.is_citem():
        return None

    if citem.it.op != idaapi.cit_switch:
        return None

    switch = citem.it.to_specific_type.cswitch  # type: ignore
    return switch


def gather_values(vu: idaapi.vdui_t) -> list[int]:
    num: idaapi.cnumber_t = vu.get_number()
    if num is None:
        return []

    values = [num._value]

    switch = citem_to_switch(vu.item)
    if switch is None:
        return values

    case: idaapi.ccase_t
    for case in switch.cases:
        values.extend(case.values)

    values = list(sorted(set(values)))  # unique
    return values


class add_number_to_enum_action_handler_t(base_action_handler_t):
    action_name = "milankovo:add_number_to_enum"
    action_label = "Add number to enum"
    action_shortcut = "a"

    def activate(self, ctx: idaapi.action_ctx_base_t):
        vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
        vu.get_current_item(idaapi.USE_KEYBOARD)

        # for switch it returns its cnumber_t that contains the maximum value
        num: idaapi.cnumber_t = vu.get_number()

        if num is None:
            return 0

        values = gather_values(vu)

        ti = choose_or_create_enum(values)
        if ti is None:
            logger.warning("No enumeration selected. Please try again.")
            return 0

        for v in values:
            if not add_enum_member(ti, v):
                return 0

        global last_enum_used
        last_enum_used = ti.get_type_name()

        update_cnumber(num, ti, vu)
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t):
        return is_number(ctx)


class add_number_to_last_enum_action_handler_t(base_action_handler_t):
    action_name = "milankovo:add_number_to_last_enum"
    action_label = "Add number to the last used enum"
    action_shortcut = "shift-a"

    def activate(self, ctx: idaapi.action_ctx_base_t):
        vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
        vu.get_current_item(idaapi.USE_KEYBOARD)

        num: idaapi.cnumber_t = vu.get_number()

        if num is None:
            return 0

        global last_enum_used
        if last_enum_used is None:
            logger.warning("No enumeration selected. Please try again.")
            return 0
        ti = idaapi.tinfo_t(name=last_enum_used)
        if ti is None:
            logger.warning("No enumeration selected. Please try again.")
            return 0

        values = gather_values(vu)
        for v in values:
            if not add_enum_member(ti, v):
                return 0

        update_cnumber(num, ti, vu)
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t):
        global last_enum_used
        if last_enum_used is None:
            return idaapi.AST_DISABLE
        if len(last_enum_used) == 0:
            last_enum_used = None
            return idaapi.AST_DISABLE
        try:
            ti = idaapi.tinfo_t(name=last_enum_used)
            if not ti.is_enum():
                last_enum_used = None
                return idaapi.AST_DISABLE
        except ValueError:
            last_enum_used = None
            return idaapi.AST_DISABLE
        idaapi.update_action_label(
            self.action_name, f"Add number to enum '{last_enum_used}'"
        )
        return is_number(ctx)


class rename_enum_member_action_handler_t(base_action_handler_t):
    action_name = "milankovo:rename_enum_member"
    action_label = "Rename enum member"
    action_shortcut = "n"

    def activate(self, ctx: idaapi.action_ctx_base_t):
        vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
        vu.get_current_item(idaapi.USE_KEYBOARD)

        parent = idaapi.tinfo_t()
        idx: int = vu.item.get_edm(parent)
        if idx == -1:
            return 0

        (idx2, edm) = parent.get_edm(idx)

        if idx2 == -1:
            old_name = "???"
        else:
            old_name = edm.name

        new_name = idaapi.ask_str(old_name, idaapi.HIST_IDENT, "New name:")
        if not new_name:
            return 0
        parent.rename_edm(idx, new_name, idaapi.ETF_FORCENAME)
        # vu.refresh_ctext(False)
        vu.cfunc.refresh_func_ctext()
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t):
        if ctx.widget_type != idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_DISABLE_FOR_WIDGET

        vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
        vu.get_current_item(idaapi.USE_KEYBOARD)

        parent = idaapi.tinfo_t()
        idx: int = vu.item.get_edm(parent)
        if idx == -1:
            return idaapi.AST_DISABLE
        return idaapi.AST_ENABLE


class EnumsHelperPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = ""
    help = ""
    wanted_name = "enums helper"

    def init(self):
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        load_last_enum_used()

        addon = idaapi.addon_info_t()
        addon.id = "milankovo.enums_helper"
        addon.name = "enums helper"
        addon.producer = "Milánek"
        addon.url = "https://github.com/milankovo/ida_enums_helper"
        addon.version = "1.0.0"
        idaapi.register_addon(addon)

        base_action_handler_t.register_actions()

        # Initialize and hook EnumsHelperHooks
        self.hooks = EnumsHelperHooks()
        self.hooks.hook()

        return idaapi.PLUGIN_KEEP

    def term(self):
        base_action_handler_t.unregister_actions()

        # Unhook EnumsHelperHooks
        if hasattr(self, "hooks"):
            self.hooks.unhook()

        save_last_enum_used()

    def run(self, arg):
        pass


class EnumsHelperHooks(idaapi.Hexrays_Hooks):
    def __init__(self):
        super().__init__()

    def populating_popup(self, widget, phandle, vu):
        # Attach actions to the popup menu
        idaapi.attach_action_to_popup(
            vu.ct, None, add_number_to_enum_action_handler_t.action_name
        )
        idaapi.attach_action_to_popup(
            vu.ct, None, add_number_to_last_enum_action_handler_t.action_name
        )
        idaapi.attach_action_to_popup(
            vu.ct, None, rename_enum_member_action_handler_t.action_name
        )
        return 0


def PLUGIN_ENTRY():
    return EnumsHelperPlugin()


def save_last_enum_used():
    logger.debug("Saving last_enum_used")
    global last_enum_used
    if not last_enum_used:
        return

    n = idaapi.netnode()
    if not n.create(NETNODE_NAME):
        logger.debug("netnode exists, clearing")
        n.kill()
        n.create(NETNODE_NAME)

    n = idaapi.netnode(NETNODE_NAME, 0, True)
    n.setblob(last_enum_used.encode(), 0, "I")
    logger.debug(f"Saved last_enum_used: {last_enum_used}")


def load_last_enum_used():
    global last_enum_used
    logger.debug("Loading last_enum_used")
    n = idaapi.netnode(NETNODE_NAME, 0, False)
    v = n.getblob(0, "I")
    if not v:
        logger.debug("netnode load failed or does not exist")
        return

    last_enum_used = v.decode()
    logger.debug(f"Loaded last_enum_used: {last_enum_used}")
