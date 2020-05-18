#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
# Copyright 2020 slyara Maintainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import enum
import re
from hashlib import sha256
from typing import List, Union, Callable
from ordered_set import OrderedSet


# TODO - Validate for names of identifiers
# TODO - Validate identifiers used in rules


IDENTIFIER_REGEXP = re.compile(r'(?i)[a-z_][a-z_0-9]{0,127}\Z')
RESERVED_KEYWORDS = {
    'all', 'and', 'any', 'ascii', 'at', 'base64', 'base64wide', 'condition', 'contains',
    'entrypoint', 'false', 'filesize', 'for', 'fullword', 'global', 'import', 'in', 'include',
    'int16', 'int16be', 'int32', 'int32be', 'int8', 'int8be', 'matches', 'meta', 'nocase',
    'not', 'of', 'or', 'private', 'rule', 'strings', 'them', 'true', 'uint16', 'uint16be',
    'uint32', 'uint32be', 'uint8', 'uint8be', 'wide', 'xor',
    }


class MetaTypes(enum.Enum):
    """
    Metadata types found in a YARA rule.
    """
    TEXTSTRING = enum.auto()
    NUMBER = enum.auto()
    BOOLEAN = enum.auto()


class Meta:
    def __init__(self, identifier: str, meta_type: MetaTypes, value: Union[str, int, bool]):
        self.identifier = identifier
        self.meta_type = meta_type
        self.value = value

    @property
    def identifier(self):
        return self.__identifier

    @identifier.setter
    def identifier(self, identifier):
        if IDENTIFIER_REGEXP.match(identifier):
            self.__identifier = identifier
        else:
            raise ValueError('Invalid metadata identifier, {!s}'.format(identifier))

    def __str__(self):
        if self.meta_type is MetaTypes.BOOLEAN:
            return '{!s} = {!s}'.format(self.__identifier, str(self.value).lower())
        elif self.meta_type is MetaTypes.NUMBER:
            return '{!s} = {!s}'.format(self.__identifier, self.value)
        else:
            return '{!s} = "{!s}"'.format(self.__identifier, self.value)

    def __repr__(self):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__, self.__identifier, self.value)


class MetaSection:
    def __init__(self, meta_list: List[Meta] = None,
                 sort_key: Callable = lambda meta: (meta.meta_type.value, meta.identifier, meta.value)):
        self._section_name = 'meta'
        self.sort_key = sort_key
        self.meta_list = meta_list if meta_list is not None else list()
        self.indent = '\t'

    def __getitem__(self, k):
        if isinstance(k, int):
            return self.meta_list[k]
        ret_vals = []
        for li in self.meta_list:
            if li.identifier == k:
                ret_vals.append(li)
            return ret_vals
        if ret_vals:
            return ret_vals
        raise KeyError(f'Metadata with key {k!r} not found')

    def __len__(self):
        return len(self.meta_list)

    def get_meta(self):
        meta_list = self.sorted()
        return [(li.identifier, li.value) for li in meta_list]

    def get_meta_as_kv(self):
        meta_list = self.sorted()
        meta_kv = {}
        if meta_list:
            for li in meta_list:
                meta_kv[li.identifier] = li.value
        return meta_kv

    def append(self, meta):
        if isinstance(meta, Meta):
            self.meta_list.append(meta)
        elif isinstance(meta, dict):
            for k, v in meta.items():
                if isinstance(v, bool):
                    t = MetaTypes.BOOLEAN
                elif isinstance(v, int):
                    t = MetaTypes.NUMBER
                else:
                    t = MetaTypes.TEXTSTRING
                self.meta_list.append(Meta(k, t, v))
                break
        else:
            raise ValueError

    def items(self):
        self.meta_list = self.sorted()
        for meta in self.meta_list:
            yield meta

    def sorted(self):
        return sorted(self.meta_list, key=self.sort_key)

    def sort(self):
        self.meta_list = sorted(self.meta_list, key=self.sort_key)

    def __str__(self):
        if not self.meta_list:
            return ''
        out_lines = []
        for line in self.meta_list:
            out_lines.append('{0!s}{0}{1}\n'.format(self.indent, line))
        return '\n{!s}{!s}:\n{!s}\n'.format(self.indent, self._section_name, ''.join(out_lines))


class StringTypes(enum.Enum):
    """
    String types found in a YARA rule.
    """
    HEXSTRING = enum.auto()
    TEXTSTRING = enum.auto()
    REGEXP = enum.auto()
    CONDITION_REGEXP = enum.auto()


class Modifiers(enum.Flag):
    """
    String name types found in a YARA rule.
    """
    NONE = 0
    i = enum.auto()
    s = enum.auto()
    nocase = enum.auto()  # cannot use with xor, base64
    wide = enum.auto()
    ascii = enum.auto()
    xor = enum.auto()  # cannot use with nocase, base64
    base64 = enum.auto()  # cannot use with fullword, xor, nocase
    base64wide = enum.auto()  # cannot use with fullword, xor, nocase
    fullword = enum.auto()  # Cannot use with base64
    private = enum.auto()
    ALL = i | s | nocase | wide | ascii | xor | base64 | base64wide | fullword | private | i | s

    def check_compatibility(self, string_type: StringTypes):
        """
        Check compatibility between multiple Modifiers
        """
        if not isinstance(string_type, StringTypes):
            raise TypeError('Must provide valid type from StringTypes')
        if self is Modifiers.NONE:
            return True
        if string_type is StringTypes.TEXTSTRING:
            if self & (Modifiers.ALL ^ (Modifiers.nocase | Modifiers.wide | Modifiers.ascii | Modifiers.xor |
                                        Modifiers.base64 | Modifiers.base64wide | Modifiers.fullword |
                                        Modifiers.private)):
                return False
            else:
                if self & Modifiers.nocase and self & (Modifiers.xor | Modifiers.base64 | Modifiers.base64wide):
                    print('Invalid modifier used with nocase')
                    return False
                elif self & Modifiers.xor and self & (Modifiers.base64 | Modifiers.base64wide):
                    print('Invalid modifier used with xor')
                    return False
                elif self & (Modifiers.base64 | Modifiers.base64wide) and self & Modifiers.fullword:
                    print('Invalid modifier used with base64 or base64wide')
                    return False
        elif string_type is StringTypes.REGEXP:
            if self in (Modifiers.ALL ^ (Modifiers.nocase | Modifiers.wide | Modifiers.ascii | Modifiers.fullword |
                                         Modifiers.i | Modifiers.s | Modifiers.private)):
                return False
        elif string_type is StringTypes.HEXSTRING:
            if self in (Modifiers.ALL ^ Modifiers.private):
                return False
        elif string_type is StringTypes.CONDITION_REGEXP:
            if self in (Modifiers.ALL ^ (Modifiers.i | Modifiers.s)):
                return False
        else:
            raise NotImplementedError('No known compatibility checks for {!r}'.format(string_type))
        return True

    def get_str(self, modifier_args=None):
        if self is Modifiers.NONE:
            return ''
        mod_str = ''
        for mod in Modifiers:
            if mod is Modifiers.ALL or mod is Modifiers.NONE:
                continue
            if mod in self:
                if mod & (Modifiers.i | Modifiers.s):
                    mod_str += mod.name
                elif modifier_args is not None and mod is Modifiers.xor:
                    mod_args = '({!s})'.format('-'.join(["{0:#0{1}x}".format(x, 4) for x in modifier_args]))
                    mod_str += f' {mod.name}{mod_args}'
                elif modifier_args is not None and mod & (Modifiers.base64 | Modifiers.base64wide):
                    mod_args = '("{!s}")'.format(modifier_args)
                    mod_str += f' {mod.name}{mod_args}'
                else:
                    mod_str += f' {mod.name}'
        return mod_str


class String:
    def __init__(self, string_identifier: str, string_type: StringTypes, value: str,
                 modifiers: Modifiers = None, mod_args: Union[list, str] = None):
        """
        Defines a string for a YARA rule
        """
        self.string_identifier = string_identifier
        self.string_type = string_type
        self.value = value
        self.modifiers = modifiers
        self.mod_args = mod_args

    @property
    def name(self):
        return str(self.string_identifier)

    @property
    def string_identifier(self):
        return self.__string_identifier

    @string_identifier.setter
    def string_identifier(self, identifier):
        if identifier == '$':
            self.__private = True
            self.__string_identifier = identifier
        elif re.match(r'(?i)\$[a-z0-9_]+$', identifier):
            self.__private = False
            self.__string_identifier = identifier
        else:
            raise ValueError("Invalid metadata identifier, {!s}".format(identifier))

    @property
    def string_type(self):
        return self.__string_type

    @string_type.setter
    def string_type(self, string_type):
        if string_type not in StringTypes:
            raise ValueError('Invalid string type, {!r}'.format(string_type))
        else:
            self.__string_type = string_type

    @property
    def mod_args(self):
        return self.__mod_args

    @mod_args.setter
    def mod_args(self, modifier_args):
        if isinstance(modifier_args, str):
            self.__mod_args = self.__check_base64_mod(modifier_args)
        elif isinstance(modifier_args, list):
            self.__mod_args = self.__check_xor_mod(modifier_args)
        else:
            self.__mod_args = None

    @staticmethod
    def __check_base64_mod(alphabet):
        b64_data = alphabet.encode('ascii').decode('unicode-escape')
        for c in b64_data:
            if ord(c) >= 255:
                message = 'Invalid character {!r} in base64 alphabet'.format(c)
                raise ValueError(message)
        if len(b64_data) != 64:
            message = 'base64 dictionary length {!s}, must be 64 characters'.format(len(b64_data))
            raise ValueError(message)
        elif re.search(r'(.).*\1', b64_data):
            message = 'Duplicate character in base64 dictionary'
            raise ValueError(message)
        else:
            return alphabet

    @staticmethod
    def __check_xor_mod(args):
        xor_range = args[:2]
        if xor_range[0] > xor_range[-1]:
            message = 'xor modification lower bound exceeds upper bound'
            raise ValueError(message)
        mod_int_list = []
        for x in xor_range:
            if 0 <= x <= 255:
                if x not in mod_int_list:
                    mod_int_list.append(x)
            else:
                message = 'bound for xor range exceeded (min: 0, max: 255)'
                raise ValueError(message)
        return mod_int_list

    def __str__(self):
        assert self.modifiers.check_compatibility(self.string_type)
        if self.string_type is StringTypes.TEXTSTRING:
            return '{!s} = "{!s}"{!s}'.format(self.__string_identifier, self.value,
                                              self.modifiers.get_str(self.mod_args))
        elif self.string_type is StringTypes.REGEXP:
            return '{!s} = /{!s}/{!s}'.format(self.__string_identifier, self.value,
                                              self.modifiers.get_str(self.mod_args))
        else:
            return '{!s} = {!s}{!s}'.format(self.__string_identifier, self.value,
                                            self.modifiers.get_str(self.mod_args))

    def __repr__(self):
        if self.modifiers:
            return '{!s}({!r}, {!s}, {!r}, {!r})'.format(
                self.__class__.__name__, self.__string_identifier, self.string_type, self.value, self.modifiers
            )
        else:
            return '{!s}({!r}, {!s}, {!r})'.format(
                self.__class__.__name__, self.__string_identifier, self.string_type, self.value
            )


class StringsSection:
    def __init__(self, string_list: List[String] = None):
        if string_list is None:
            self.string_list = []
        else:
            self.string_list = string_list
        self._section_name = 'strings'
        self.indent = '\t'

    def append(self, string_obj):
        self.string_list.append(string_obj)

    @property
    def public_names(self):
        all_names = set(x.string_identifier for x in self.string_list)
        if '$' in all_names:
            all_names.remove('$')

        return all_names

    def __len__(self):
        return len(self.string_list)

    def __getitem__(self, k):
        if isinstance(k, int):
            return self.string_list[k]
        if k is Keywords.them:
            return self.string_list
        ret_vals = []
        for li in self.string_list:
            if re.match(k.lstrip('!@#$').replace('*', '.*') + r'\Z',
                        li.string_identifier.lstrip('!@#$')):
                ret_vals.append(li)
        if ret_vals:
            return ret_vals
        raise KeyError(f'String matching identifier "{k}" not found')

    def __str__(self):
        if not self.string_list:
            return ''
        out_lines = []
        for line in self.string_list:
            out_lines.append('{0}{0}{1}\n'.format(self.indent, line))
        return '{0}{1}:\n{2}\n'.format(self.indent, self._section_name, ''.join(out_lines))

    def __repr__(self):
        return '{!s}({!r})'.format(self.__class__.__name__, self.string_list)


class IntegerFuctions(enum.Enum):
    """
    Integer functions for condition statements
    """
    int8 = 0
    int16 = 1
    int32 = 2
    uint8 = 3
    uint16 = 4
    uint32 = 5
    int8be = 6
    int16be = 7
    int32be = 8
    uint8be = 9
    uint16be = 10
    uint32be = 11


class Keywords(enum.Enum):
    """
    Keywords functions for condition statements
    """
    false = enum.auto()
    true = enum.auto()
    all = enum.auto()
    any = enum.auto()
    them = enum.auto()
    filesize = enum.auto()
    entrypoint = enum.auto()


class Keyword:
    def __init__(self, keyword):
        if keyword in Keywords:
            self.keyword = keyword
        else:
            message = 'Invalid keyword, {!r}'.format(keyword)
            raise ValueError(message)

    def __str__(self):
        return '{!s}'.format(self.keyword.name)

    def __repr__(self):
        return '{!s}({!s})'.format(self.__class__.__name__, self.keyword)

    def dump(self, strings_section: StringsSection = None, sort=True):
        if self.keyword is Keywords.them:
            return Enum([Expression(StringIdentifier(Identifier('$*')))]).dump(strings_section, sort)
        return '{!s}({!s})'.format(self.__class__.__name__, self.keyword)


class Expression:
    def __init__(self, expr: Union['Expression', Keyword]):
        self.expr = expr

    def __str__(self):
        return '{!s}'.format(self.expr)

    def __repr__(self):
        return '{!s}({!r})'.format(self.__class__.__name__, self.expr)

    def dump(self, strings_section: StringsSection = None, sort=True):
        try:
            if hasattr(self.expr, 'dump'):
                return '{!s}({!s})'.format(self.__class__.__name__, self.expr.dump(strings_section, sort))
            a = '{!s}({!r})'.format(self.__class__.__name__, self.expr)
            return '{!s}({!r})'.format(self.__class__.__name__, self.expr)
        except Exception as e:
            print('Method dump missing for {}'.format(type(self)))
            return repr(self)


class Group(Expression):
    def __init__(self, expr: Expression):
        self.expr = expr

    def __str__(self):
        return '({!s})'.format(self.expr)

    def __repr__(self):
        return '{!s}({!r})'.format(self.__class__.__name__, self.expr)

    def dump(self, strings_section: StringsSection = None, sort=True):
        return '{!s}({!r})'.format(self.__class__.__name__, self.expr.dump(strings_section, sort))


class LiteralTypes(enum.Enum):
    float = 1
    string = 2
    regexp = 3
    oct_integer = 8
    dec_integer = 10
    hex_integer = 16


class Literals(Expression):
    def __init__(self, expr: Union[int, float, str], literal_type: LiteralTypes = None, flags: Modifiers = None):
        self.expr = expr
        if literal_type is LiteralTypes.regexp:
            if flags.check_compatibility(StringTypes.CONDITION_REGEXP):
                self.flags = flags
        else:
            self.flags = None
        self.type = literal_type

    def __str__(self):
        if self.type is LiteralTypes.string:
            return '"{!s}"'.format(self.expr)
        elif self.type is LiteralTypes.regexp:
            mod_str = ''
            if self.flags:
                if self.flags.check_compatibility(StringTypes.CONDITION_REGEXP):
                    mod_str = ''.join(
                        flag.name for flag in Modifiers if flag & self.flags and flag is not Modifiers.ALL)
            return '/{!s}/{}'.format(self.expr, mod_str)
        elif self.type is LiteralTypes.float:
            return '{!s}'.format(self.expr)
        elif self.type is LiteralTypes.oct_integer:
            return '0o{:o}'.format(self.expr)
        elif self.type is LiteralTypes.hex_integer:
            return '0x{:x}'.format(self.expr)
        else:
            if self.expr and (self.expr >> 20) << 20 == self.expr:
                return '{!s}MB'.format(self.expr >> 20)
            elif self.expr and (self.expr >> 10) << 10 == self.expr:
                return '{!s}KB'.format(self.expr >> 10)
            return '{!s}'.format(self.expr)

    def __repr__(self):
        return '{!s}({!r}, {!s})'.format(self.__class__.__name__, self.expr, self.type)

    def dump(self, strings_section: StringsSection = None, sort=True):
        a = '{!s}({!s})'.format(self.__class__.__name__, self.expr)
        return '{!s}({!s})'.format(self.__class__.__name__, self.expr)


class BinaryOperators(enum.Enum):
    multiply = '*'
    divide = '\\'
    remainder = '%'
    add = '+'
    subtract = '-'
    shift_left = '<<'
    shift_right = '>>'
    bitwise_and = '&'
    bitwise_xor = '^'
    bitwise_or = '|'
    less_than = '<'
    less_than_eq = '<='
    greater_than = '>'
    greater_than_eq = '>='
    equal = '=='
    not_equal = '!='
    contains = 'contains'
    matches = 'matches'
    logical_and = 'and'
    logical_or = 'or'

    def __repr__(self):
        return str(self)


class UnaryOperators(enum.Enum):
    unary_minus = '-'
    bitwise_not = '~'
    logical_not = 'not'


class UnaryOperation(Expression):
    def __init__(self, unary_operator, expr):
        self.expr = expr
        if isinstance(unary_operator, UnaryOperators):
            self.operator = unary_operator
        else:
            self.operator = UnaryOperators[unary_operator]

    def __str__(self):
        return '{!s} {!s}'.format(self.operator.value, self.expr)

    def __repr__(self):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__, self.operator, self.expr)

    def dump(self, strings_section: StringsSection = None, sort=True):
        if isinstance(self.expr, UnaryOperation) and self.expr.operator is self.operator:
            return self.expr.expr.dump(strings_section, sort)
        return '{!s}({!s})'.format(self.__class__.__name__, self.expr)


class Range:
    def __init__(self, start_expr, end_expr):
        self.start_expr = start_expr
        self.end_expr = end_expr

    def __str__(self):
        return '({!s}..{!s})'.format(self.start_expr, self.end_expr)

    def __repr__(self):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__, self.start_expr, self.end_expr)

    def dump(self, strings_section: StringsSection = None, sort=True):
        return '{!s}({!s})'.format(self.__class__.__name__,
                                   self.start_expr.dump(strings_section, sort),
                                   self.end_expr.dump(strings_section, sort))


class Enum:
    def __init__(self, expr_list: List[Expression]):
        self.expr_list = expr_list

    def __str__(self):
        return '({!s})'.format(', '.join(str(x) for x in self.expr_list))

    def __repr__(self):
        return '{!s}({!r})'.format(self.__class__.__name__, self.expr_list)

    def append(self, expr):
        self.expr_list.append(expr)

    def dump(self, strings_section: StringsSection = None, sort=True):
        dl = []
        for expr in self.expr_list:
            dl.append(expr.dump(strings_section, sort))
        if sort is True:
            dl.sort()
        return '{!s}({!s})'.format(self.__class__.__name__, ' | '.join(dl))


class Identifier(Expression):
    def __init__(self, expr: str):
        if isinstance(expr, str):
            self.expr = expr
        else:
            message = 'Identifiers must be strings, {!r} was provided'.format(type(expr))
            raise ValueError(message)

    def __str__(self):
        return '{!s}'.format(self.expr)

    def __repr__(self):
        return '{!s}({!r})'.format(self.__class__.__name__, self.expr)


class StringIdentifier(Expression):
    def __init__(self, str_id: Identifier, index: Union[Expression, Range, Keyword] = None):
        self.str_id = str_id
        assert index is None or isinstance(index, (Expression, Range, Keyword))
        if isinstance(index, Keyword):
            assert index.keyword is Keywords.entrypoint
        self.index = index

    def __str__(self):
        if isinstance(self.index, Range):
            return '{!s} in {!s}'.format(self.str_id, self.index)
        elif isinstance(self.index, Expression):
            return '{!s} at {!s}'.format(self.str_id, self.index)
        return '{!s}'.format(self.str_id)

    def __repr__(self):
        if self.index is not None:
            return '{!s}({!r}, {!s})'.format(self.__class__.__name__, self.str_id, self.index)
        return '{!s}({!r})'.format(self.__class__.__name__, self.str_id)

    def dump(self, strings_section: StringsSection = None, sort=True):
        if strings_section is None:
            raise KeyError('No string section provided for dump of string identifier')
        if self.str_id.expr in ('!', '@', '#', '$'):
            return '{!s}(Anonymous({!s}))'.format(self.__class__.__name__, self.str_id)
        s_s = strings_section[self.str_id.expr]
        if s_s:
            dl = []
            for s in s_s:
                dl.append('{!s}, {!r}, {!s}, {!r}'.format(s.string_type.name, s.value, s.modifiers, s.mod_args))
            if sort is True:
                dl.sort()
            if hasattr(self.index, 'dump'):
                index = self.index.dump() if self.index is not None else repr(None)
                return '{!s}({!s}, {!s})'.format(self.__class__.__name__, ' | '.join(dl), index)
            return '{!s}({!s})'.format(self.__class__.__name__, ' | '.join(dl))
        raise KeyError('String identifier not found in string section')


class StringCount(Expression):
    def __init__(self, str_id: Identifier):
        self.str_id = str_id

    def __str__(self):
        return '{!s}'.format(self.str_id)

    def __repr__(self):
        return '{!s}({!r})'.format(self.__class__.__name__, self.str_id)

    def dump(self, strings_section: StringsSection = None, sort=True):
        if strings_section is None:
            raise KeyError('No string section provided for dump of string identifier')
        s_s = strings_section[self.str_id.expr]
        if s_s:
            dl = []
            for s in s_s:
                dl.append('{!s}, {!r}, {!s}, {!r}'.format(s.string_type.name, s.value, s.modifiers, s.mod_args))
            if sort is True:
                dl.sort()
            return '{!s}({!s})'.format(self.__class__.__name__, ' | '.join(dl))
        raise KeyError('String identifier not found in string section')


class StringOffset(Expression):
    def __init__(self, str_id: Identifier, index: Union[Identifier, Expression] = None):
        self.str_id = str_id
        assert index is None or isinstance(index, Expression)
        self.index = index

    def __str__(self):
        if self.index is not None:
            return '{!s}[{!s}]'.format(self.str_id, self.index)
        return '{!s}'.format(self.str_id)

    def __repr__(self):
        if self.index is not None:
            return '{!s}({!r}, {!r})'.format(self.__class__.__name__, self.str_id, self.index)
        return '{!s}({!r})'.format(self.__class__.__name__, self.str_id)

    def dump(self, strings_section: StringsSection = None, sort=True):
        if strings_section is None:
            raise KeyError('No string section provided for dump of string identifier')
        s_s = strings_section[self.str_id.expr]
        if s_s:
            dl = []
            for s in s_s:
                dl.append('{!s}, {!r}, {!s}, {!r}'.format(s.string_type.name, s.value, s.modifiers, s.mod_args))
            if sort is True:
                dl.sort()
            if hasattr(self.index, 'dump'):
                index = self.index.dump()
            else:
                index = repr(self.index)
            return '{!s}({!s}, {!s})'.format(self.__class__.__name__, ' | '.join(dl), index)
        raise KeyError('String identifier not found in string section')


class StringLength(Expression):
    def __init__(self, str_id: Identifier, index: Union[Identifier, Expression] = None):
        self.str_id = str_id
        assert index is None or isinstance(index, Expression)
        self.index = index

    def __str__(self):
        if self.index is not None:
            return '{!s}[{!s}]'.format(self.str_id, self.index)
        return '{!s}'.format(self.str_id)

    def __repr__(self):
        if self.index is not None:
            return '{!s}({!r}, {!r})'.format(self.__class__.__name__, self.str_id, self.index)
        return '{!s}({!r})'.format(self.__class__.__name__, self.str_id)

    def dump(self, strings_section: StringsSection = None, sort=True):
        if strings_section is None:
            raise KeyError('No string section provided for dump of string identifier')
        s_s = strings_section[self.str_id.expr]
        if s_s:
            dl = []
            for s in s_s:
                dl.append('{!s}, {!r}, {!s}, {!r}'.format(s.string_type.name, s.value, s.modifiers, s.mod_args))
            if sort is True:
                dl.sort()
            if hasattr(self.index, 'dump'):
                index = self.index.dump()
            else:
                index = repr(self.index)
            return '{!s}({!s}, {!s})'.format(self.__class__.__name__, ' | '.join(dl), index)
        raise KeyError('String identifier not found in string section')


class FunctionCall(Expression):
    def __init__(self, func: Expression, args: List[Expression]):
        self.func = func
        self.args = args

    def __str__(self):
        return '{!s}({!s})'.format(self.func, ', '.join(str(x) for x in self.args))

    def __repr__(self):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__, self.func, self.args)

    def dump(self, strings_section: StringsSection = None, sort=True):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__,
                                         self.func.dump(strings_section, sort),
                                         ', '.join(x.dump(strings_section, sort) for x in self.args))


class MemberAccess(Expression):
    def __init__(self, container: Expression, member: str):
        self.container = container
        self.member = member

    def __str__(self):
        return '{!s}.{!s}'.format(self.container, self.member)

    def __repr__(self):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__, self.container, self.member)

    def dump(self, strings_section: StringsSection = None, sort=True):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__,
                                         self.container.dump(strings_section, sort),
                                         self.member)


class Subscripting(Expression):
    def __init__(self, array: Expression, index: Expression):
        self.array = array
        self.index = index

    def __str__(self):
        return '{!s}[{!s}]'.format(self.array, self.index)

    def __repr__(self):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__, self.array, self.index)

    def dump(self, strings_section: StringsSection = None, sort=True):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__,
                                         self.array.dump(strings_section, sort),
                                         self.index.dump(strings_section, sort))


class Quantifier(Expression):
    def __init__(self, expr: Union[Keyword, Expression]):
        super().__init__(expr)


class ForIn(Expression):
    def __init__(self, quantifier: Quantifier, varlist: List[str],
                 iterator: Union[Identifier, Enum], condition: Expression):
        self.quantifier = quantifier
        self.varlist = varlist
        self.iterator = iterator
        self.condition = condition

    def __str__(self):
        return 'for {!s} {!s} in {!s} : ( {!s} )'.format(
            self.quantifier, ', '.join(str(x) for x in self.varlist), self.iterator, self.condition)

    def __repr__(self):
        return '{!s}({!r}, {!r}, {!r}, {!r})'.format(
            self.__class__.__name__, self.quantifier, self.varlist, self.iterator, self.condition)

    def dump(self, strings_section: StringsSection = None, sort=True):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__,
                                         self.quantifier.dump(strings_section, sort),
                                         ', '.join(repr(x) for x in self.varlist),
                                         self.iterator.dump(strings_section, sort),
                                         self.condition.dump(strings_section, sort),
                                         )


class ForOf(Expression):
    def __init__(self, quantifier: Quantifier,
                 string_set: Union[Enum, Keyword], condition: Expression):
        self.quantifier = quantifier
        self.strings = string_set
        self.condition = condition

    def __str__(self):
        if isinstance(self.strings, Keyword):
            return 'for {!s} of {!s} : ( {!s} )'.format(self.quantifier, self.strings, self.condition)
        return 'for {!s} of ({!s}) : ( {!s} )'.format(self.quantifier, self.strings, self.condition)

    def __repr__(self):
        return '{!s}({!r}, {!r}, {!r})'.format(self.__class__.__name__, self.quantifier, self.strings, self.condition)

    def dump(self, strings_section: StringsSection = None, sort=True):
        return '{!s}({!s}, {!s}, {!s})'.format(self.__class__.__name__,
                                               self.quantifier.dump(strings_section, sort),
                                               self.strings.dump(strings_section, sort),
                                               self.condition.dump(strings_section, sort),
                                               )


class Of(Expression):
    def __init__(self, quantifier: Quantifier, string_set: Union[Enum, Keyword]):
        self.quantifier = quantifier
        self.string_set = string_set

    def __str__(self):
        if isinstance(self.string_set, Keyword):
            return '{!s} of {!s}'.format(self.quantifier, self.string_set)
        return '{!s} of {!s}'.format(self.quantifier, self.string_set)

    def __repr__(self):
        return '{!s}({!r}, {!r})'.format(self.__class__.__name__, self.quantifier, self.string_set)

    def dump(self, strings_section: StringsSection = None, sort=True):
        return '{!s}({!s}, {!s})'.format(self.__class__.__name__,
                                         self.quantifier.dump(strings_section, sort),
                                         self.string_set.dump(strings_section, sort))


class Operation(Expression):
    """
    List of operations joined by the same operator, like '$this and $that',
    '$this or $that or $theother', or 1 + 2 + 3
    """

    def __init__(self, operator: BinaryOperators, *expr: Expression):
        self.operator = operator
        self.expr_list = list(expr)

    def __str__(self):
        return ' {!s} '.format(self.operator.value).join(str(x) for x in self.expr_list)

    def __repr__(self):
        return '{!s}({!r}, {!s})'.format(self.__class__.__name__, self.operator,
                                         ', '.join(repr(x) for x in self.expr_list))

    def append(self, expr: Expression):
        self.expr_list.append(expr)

    def sorted(self):
        if self.operator.name in ('logical_and', 'logical_or', 'add', 'multiply'):
            try:
                return sorted(self.expr_list, key=lambda expr: str(expr))
            except Exception as e:
                print('Could not sort Operation, {!s}'.format(e))
        return self.expr_list

    def dump(self, strings_section=None, sort=True):
        if sort is True:
            expr_list = self.sorted()
        else:
            expr_list = self.expr_list
        for i in expr_list:
            if isinstance(i, str):
                print(i)
        a = '{!s}({!s}, {!s})'.format(self.__class__.__name__, self.operator,
                                      ', '.join(x.dump(strings_section, sort) for x in expr_list))
        return '{!s}({!s}, {!s})'.format(self.__class__.__name__, self.operator,
                                         ', '.join(x.dump(strings_section, sort) for x in expr_list))


class ConditionSection:
    def __init__(self, expression=None):
        self.bool_expr = expression if expression is not None else Expression(Keyword(Keywords.false))
        self._section_name = 'condition'
        self.indent = '\t'
        self.imports = IdentifierSet()  # TODO - Generate from walk through condition nodes
        self.externals = IdentifierSet()  # TODO - Generate from walk through condition nodes

    def __str__(self):
        if not self.bool_expr:
            return '{0}{1}:\n{0}{0}{2}\n'.format(self.indent, self._section_name, 'false')
        cond_str = '{0}{0}{1}'.format(self.indent, self.bool_expr)
        return '{0}{1}:\n{2}\n'.format(self.indent, self._section_name, cond_str)

    def __repr__(self):
        if not self.bool_expr:
            return '{!r}({!r})'.format(self.__class__.__name__, None)
        return '{!s}({!s})'.format(self.__class__.__name__, '{!r}'.format(self.bool_expr))

    def dump(self, strings_section=None, sort=True):
        if not self.bool_expr:
            return '{!r}'.format(None)
        return '{!s}'.format(self.bool_expr.dump(strings_section, sort))


class RuleModifiers(enum.Flag):
    """
    Flags for a YARA rule
    global_flag rule matches impose restrictions on all the rules in the file
    private_flag rule matches are not reported
    """
    NONE = 0
    global_flag = enum.auto()
    private_flag = enum.auto()
    ALL = global_flag | private_flag

    def get_str(self):
        if self is RuleModifiers.NONE:
            return ''
        mod_list = []
        for mod in RuleModifiers:
            if mod is RuleModifiers.ALL or mod is RuleModifiers.NONE:
                continue
            elif mod & self:
                mod_str = mod.name.replace('_flag', '')
                mod_list.append(f'{mod_str}')
        return ' '.join(mod_list)


class IdentifierSet(OrderedSet):
    def _add(self, elem):
        super().add(elem)

    def add(self, elem):
        if elem in RESERVED_KEYWORDS:
            raise ValueError('Identifier value of {} is in YARA reserved keywords'.format(elem))
        if not IDENTIFIER_REGEXP.match(elem):
            raise ValueError('Identifier value {} does not match YARA identifier requirements'.format(elem[:20]))
        self._add(elem)

    def __str__(self):
        return ' '.join(self)


class YaraRule:
    def __init__(self, name: str, flags: RuleModifiers = RuleModifiers.NONE, tags: IdentifierSet = IdentifierSet(),
                 meta_section: MetaSection = None, string_section: StringsSection = None,
                 condition_section: ConditionSection = None):
        self.name = name
        if tags is None:
            tags = []
        self.flags = flags
        self.tags = tags
        self.meta = MetaSection() if meta_section is None else meta_section
        self.strings = StringsSection() if string_section is None else string_section
        self.condition = ConditionSection() if condition_section is None else condition_section
        assert isinstance(self.meta, MetaSection)
        assert isinstance(self.strings, StringsSection)
        assert isinstance(self.condition, ConditionSection)
        self.indent = '\t'
        # self.start_line = None
        # self.end_line = None
        # self.comments = list()

    @property
    def indent(self):
        return self.__indent

    @indent.setter
    def indent(self, value):
        if not re.match(r'^([ ]+|[\t]+)\Z', value):
            raise ValueError('Indentation characters must be spaces or tabs')
        for section in (self.meta, self.strings, self.condition):
            section.indent = value
        self.__indent = value

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, name):
        if name in RESERVED_KEYWORDS:
            raise ValueError('Rule name cannot be reserved word, {}'.format(name))
        if IDENTIFIER_REGEXP.match(name):
            self.__name = name
        else:
            raise ValueError('Rule name must be a valid identifier')

    def __str__(self):
        rule_hdr = 'rule {!s}'.format(self.name)
        if self.flags:
            rule_hdr = '{1} {0}'.format(rule_hdr, self.flags.get_str())
        if self.tags:
            rule_hdr = rule_hdr + ' : {!s}'.format(' '.join(self.tags))
        rule_body = ''
        for section in (self.meta, self.strings, self.condition):
            section.indent = self.indent
            rule_body += str(section)
        rule_str = '{!s}\n{{\n{!s}}}\n'.format(rule_hdr, rule_body)
        return rule_str

    def generate_hash(self, hash_function=None):
        """Create hash of logic in the rule using the rule's condition and strings"""
        if hash_function is None:
            hash_function = sha256
        hash_obj = hash_function()
        assert hasattr(hash_obj, 'update') and hasattr(hash_obj, 'hexdigest'), 'Missing secure hash methods'

        condition_dump = self.condition.dump(self.strings, sort=True)
        hash_obj.update(condition_dump.encode('utf8', errors='surrogate_escape'))
        return hash_obj.hexdigest()


class Import:
    def __init__(self, imported_module):
        self.imported_module = imported_module

    def __str__(self):
        return '{!s} "{!s}"'.format(self.__class__.__name__.lower(), self.imported_module)

    def __repr__(self):
        return '{!s}({!r})'.format(self.__class__.__name__, self.imported_module)


class Include:
    def __init__(self, included_file):
        self.included_file = included_file

    def __str__(self):
        return '{!s} "{!s}"'.format(self.__class__.__name__.lower(), self.included_file)

    def __repr__(self):
        return '{!s}({!r})'.format(self.__class__.__name__, self.included_file)


class YaraRuleSet:
    def __init__(self, filename: str = '', imports: IdentifierSet = None, includes: OrderedSet = None,
                 rules: List[YaraRule] = None):
        self.filename = filename
        if imports is None:
            imports = IdentifierSet()
        if includes is None:
            includes = OrderedSet()
        if rules is None:
            rules = []
        self.imports = imports
        self.includes = includes
        self.rules = rules
        self.externals = []

    def __getitem__(self, item):
        if isinstance(item, int):
            return self.rules[item]
        if item in ('imports', 'includes',):
            return getattr(self, item)
        elif item in RESERVED_KEYWORDS:
            raise ValueError(f'Reserved keyword, {item}, cannot be a rule name.')
        else:
            for rule in self.rules:
                if rule.name == 'item':
                    return rule
        raise KeyError(f'Rule named {item} not found')

    def __iter__(self):
        for rule in self.rules:
            yield rule

    def __len__(self):
        return len(self.rules)

    def __str__(self):
        out_list = []
        if self.includes:
            out_list.append('\n'.join(str(x) for x in self.includes))
        if self.imports:
            out_list.append('\n'.join(str(x) for x in self.imports))
        if self.rules:
            out_list.append('\n'.join(str(x) for x in self.rules))
        return '\n\n'.join(out_list)

    def __repr__(self):
        return '{!s}({!r}, {!r}, {!r}, {!r})'.format(
            self.__class__.__name__, self.filename, self.imports, self.includes, self.rules
        )
