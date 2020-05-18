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
"""
Parse YARA rules

slyara is a library that creates Python objects that represent YARA rules with sly.
The Python objects can be converted back to YARA rules after sorting, inspection, or validation.

The parser and lexer are based on the official YARA parsers and lexers at https://github.com/VirusTotal
"""

from distutils.version import StrictVersion

from sly import Lexer
from sly import Parser

from slyara.objects import *


class BaseLexer(Lexer):
    tokens = {
        INCLUDE, IMPORT, PRIVATE, GLOBAL, RULE,
        META, STRINGS, CONDITION, TRUE, FALSE,
        ASCII, WIDE, XOR, BASE64, BASE64_WIDE, FULLWORD, NOCASE,
        NOT, AND, OR, AT, IN, OF, THEM, FOR, ALL,
        ANY, ENTRYPOINT, FILESIZE, MATCHES, CONTAINS,
        STRING_COUNT, STRING_OFFSET, STRING_LENGTH, INTEGER_FUNCTION,
        SL_COMMENT, COMMENT,
    }

    IDENTIFIER['import'] = IMPORT
    IDENTIFIER['include'] = INCLUDE
    IDENTIFIER['private'] = PRIVATE
    IDENTIFIER['global'] = GLOBAL
    IDENTIFIER['rule'] = RULE
    IDENTIFIER['meta'] = META
    IDENTIFIER['strings'] = STRINGS
    IDENTIFIER['condition'] = CONDITION
    IDENTIFIER['true'] = TRUE
    IDENTIFIER['false'] = FALSE
    IDENTIFIER['not'] = NOT
    IDENTIFIER['and'] = AND
    IDENTIFIER['or'] = OR
    IDENTIFIER['at'] = AT
    IDENTIFIER['in'] = IN
    IDENTIFIER['of'] = OF
    IDENTIFIER['them'] = THEM
    IDENTIFIER['for'] = FOR
    IDENTIFIER['all'] = ALL
    IDENTIFIER['any'] = ANY
    IDENTIFIER['entrypoint'] = ENTRYPOINT
    IDENTIFIER['filesize'] = FILESIZE
    IDENTIFIER['matches'] = MATCHES
    IDENTIFIER['contains'] = CONTAINS
    IDENTIFIER['private'] = PRIVATE
    IDENTIFIER['global'] = GLOBAL
    IDENTIFIER['ascii'] = ASCII
    IDENTIFIER['wide'] = WIDE
    IDENTIFIER['xor'] = XOR
    IDENTIFIER['base64'] = BASE64
    IDENTIFIER['base64wide'] = BASE64_WIDE
    IDENTIFIER['fullword'] = FULLWORD
    IDENTIFIER['nocase'] = NOCASE

    @_(r'[A-Z_a-z][0-9A-Z_a-z]*')
    def IDENTIFIER(self, t):
        if len(t.value) > 128:
            message = 'Identifier on line {} too long, starts with {!r}'.format(self.lineno, t.value[:20])
            raise ValueError(message)
        t.value = t.value
        return t

    @_(r'(//[^\n]*)')
    def ignore_SL_COMMENT(self, t):
        return t

    @_(r'/\*(.|\n|\r|\r\n)*?\*/')
    def ignore_COMMENT(self, t):
        if '\r\n' in t.value:
            self.lineno += t.value.count('\r\n')
        elif '\r' in t.value:
            self.lineno += t.value.count('\r')
        else:
            self.lineno += t.value.count('\n')
        return t


class TextStringLexer(Lexer):

    _COLLECT = ''

    tokens = {TEXT_CHAR, TEXT_ESC_TAB, TEXT_ESC_NEWLINE,
              TEXT_ESC_QUOTE, TEXT_ESC_BACKSLASH, TEXT_ESC_BYTE, }

    @_(r'[^\x00-\x1F"\\]')
    def TEXT_CHAR(self, t):
        self._COLLECT += t.value

    @_(r'\\t')
    def TEXT_ESC_TAB(self, t):
        self._COLLECT += t.value

    @_(r'\\n')
    def TEXT_ESC_NEWLINE(self, t):
        self._COLLECT += t.value

    @_(r'\\"')
    def TEXT_ESC_QUOTE(self, t):
        self._COLLECT += t.value

    @_(r'\\\\')
    def TEXT_ESC_BACKSLASH(self, t):
        self._COLLECT += t.value

    @_(r'\\x[0-9a-fA-F]{2}')
    def TEXT_ESC_BYTE(self, t):
        self._COLLECT += t.value

    @_(r'\"')
    def TEXT_STRING(self, t):
        t.value = self._COLLECT
        self._COLLECT = ''
        self.pop_state()
        return t


class HexStringLexer(Lexer):

    _COLLECT = ''
    _HEX_ALT = 0

    tokens = {HEX_PAIR, HEX_JUMP, }

    literals = {'(', ')', '|'}

    ignore = '\t '

    @_(r'\r?[\n]|\r')
    def ignore_newline(self, t):
        self.lineno += 1

    @_(r'\(')
    def HEX_ALT_START(self, t):
        self._HEX_ALT += 1
        self._COLLECT += ' {} '.format(t.value)

    @_(r'\)')
    def HEX_ALT_END(self, t):
        self._HEX_ALT -= 1
        self._COLLECT += ' {} '.format(t.value)

    @_(r'\|')
    def HEX_ALT_OPTION(self, t):
        self._COLLECT += ' {} '.format(t.value)

    @_(r'[a-fA-F0-9?]{2}')
    def HEX_PAIR(self, t):
        self._COLLECT += ' {} '.format(t.value)

    @_(r'\[\s*([0-9]*)\s*-?\s*([0-9]*)\s*\]')
    def HEX_JUMP(self, t):
        if '-' in t.value:
            val0, val1 = t.value.strip(' \t[]').split('-')
            if val0 and val1 and int(val0) > int(val1):
                raise ValueError(f'Invalid byte jump range on line {t.lineno}')
        val = re.sub(r'(?<=[\[-])\s*0+|\s+', r'', t.value)
        self._COLLECT += ' {} '.format(val)

    @_(r'\}')
    def HEX_STRING_end(self, t):
        t.type = 'HEX_STRING'
        t.value = '{{{}}}'.format(re.sub(r'\s+', r' ', self._COLLECT).upper())
        self._COLLECT = ''
        if self._HEX_ALT != 0:
            raise ValueError(f'Unmatched hex string alternation before line {t.lineno}')
        self._HEX_ALT = 0
        self.pop_state()
        return t

    # Can't use BaseLexer because of IDENTIFIER
    @_(r'(//[^\n]*)')
    def ignore_SL_COMMENT(self, t):
        return t

    @_(r'/\*(.|\n|\r|\r\n)*?\*/')
    def ignore_COMMENT(self, t):
        if '\r\n' in t.value:
            self.lineno += t.value.count('\r\n')
        elif '\r' in t.value:
            self.lineno += t.value.count('\r')
        else:
            self.lineno += t.value.count('\n')
        return t


class RegExpLexer(Lexer):

    _COLLECT = ''

    tokens = {REGEXP_ESC_SLASH, REGEXP_CHARS, REGEXP_ESC_META,
              REGEXP_CHAR_CLASS, REGEXP_ZERO_WIDTH_ASSERTION, REGEXP_DOT,
              REGEXP_ANY, REGEXP_META, }

    @_(r'\\/')
    def REGEXP_ESC_SLASH(self, t):
        self._COLLECT += t.value

    @_(r'[0-9A-Za-z]+',
       r'[- !"#%&\',:;<=>@_`~]+')
    def REGEXP_CHARS(self, t):
        self._COLLECT += t.value

    @_(r'\\[\\^$|()\[\]*+?]')
    def REGEXP_ESC_META(self, t):
        self._COLLECT += t.value

    @_(r'\\[tnrfa]',
       r'\\x[0-9a-fA-F]{2}')
    def REGEXP_ESC_SEQ(self, t):
        self._COLLECT += t.value

    @_(r'\\[wWsSdD]')
    def REGEXP_CHAR_CLASS(self, t):
        self._COLLECT += t.value

    @_(r'\\[bB]')
    def REGEXP_ZERO_WIDTH_ASSERTION(self, t):
        self._COLLECT += t.value

    @_(r'\\.')
    def REGEXP_DOT(self, t):
        self._COLLECT += t.value

    @_(r'\.')
    def REGEXP_ANY(self, t):
        self._COLLECT += t.value

    @_(r'[\\^$|()\[\]*+?]')
    def REGEXP_META(self, t):
        self._COLLECT += t.value

    @_(r'[*+?]\??',
       r'\{[0-9]+\}\??',
       r'\{[0-9]+\,}\??',
       r'\{,[0-9]+\}\??',
       r'\{[0-9]+,[0-9]+\}\??')
    def REGEXP_QUANTIFIER(self, t):
        self._COLLECT += t.value

    @_(r'/i?s?')
    def REGEXP_end(self, t):
        t.type = 'REGEXP'
        mods = Modifiers.NONE
        for flag in ('i', 's', ):
            if flag in t.value:
                mods = mods | Modifiers[flag]
        t.value = self._COLLECT, mods
        self._COLLECT = ''
        self.pop_state()
        return t


class ConditionLexer(BaseLexer):
    tokens = {
        DOT_DOT, LT, GT, LE, GE, EQ, NEQ, SHIFT_LEFT, SHIFT_RIGHT,
        STRING_IDENTIFIER_WITH_WILDCARD, STRING_IDENTIFIER,
        STRING_COUNT, STRING_OFFSET, STRING_LENGTH, INTEGER_FUNCTION,
        NUMBER, DOUBLE, BITWISE_NOT,
        BITWISE_OR, BITWISE_XOR, BITWISE_AND, PLUS, MINUS, MULTIPLY, DIVIDE, REMAINDER,
    }

    ignore = '\t '

    literals = {'(', ')', '[', ']', ':', '-', '.', ',', }

    @_(r'\r?[\n]|\r')
    def ignore_newline(self, t):
        self.lineno += 1

    DOT_DOT = r'\.\.'
    SHIFT_LEFT = r'<<'
    SHIFT_RIGHT = r'>>'
    LE = r'<='
    GE = r'>='
    EQ = r'=='
    NEQ = r'!='
    LT = r'<'
    GT = r'>'
    BITWISE_OR = r'\|'
    BITWISE_XOR = r'\^'
    BITWISE_AND = r'&'
    PLUS = r'\+'
    MINUS = r'-'
    MULTIPLY = r'\*'
    DIVIDE = r'\\'
    REMAINDER = r'%'
    BITWISE_NOT = r'~'

    @_(r'[A-Z_a-z][0-9A-Z_a-z]*')
    def IDENTIFIER(self, t):
        if len(t.value) > 128:
            message = 'Identifier on line {} too long, starts with {!r}'.format(self.lineno, t.value[:20])
            raise ValueError(message)
        t.value = t.value
        return t

    @_(r'\$[0-9a-zA-Z\-_]*[*]')
    def STRING_IDENTIFIER_WITH_WILDCARD(self, t):
        t.value = t.value
        return t

    @_(r'\$[0-9a-zA-Z\-_]*')
    def STRING_IDENTIFIER(self, t):
        t.value = t.value
        return t

    @_(r'\#([a-z][0-9a-zA-Z\-_]*)?')
    def STRING_COUNT(self, t):
        t.value = t.value
        return t

    @_(r'@[0-9a-zA-Z\-_]*')
    def STRING_OFFSET(self, t):
        t.value = t.value
        return t

    @_(r'![0-9a-zA-Z\-_]*')
    def STRING_LENGTH(self, t):
        t.value = t.value
        return t

    @_(r'u?int(8|16|32)(be)?')
    def INTEGER_FUNCTION(self, t):
        t.value = IntegerFuctions[t.value]
        return t

    @_(r'[0-9]+\.[0-9]+')
    def DOUBLE(self, t):
        t.value = float(t.value)
        return t

    @_(r'0x[A-Fa-f0-9]+',
       '0o[0-7]+',
       '[0-9]+(MB|KB){0,1}')
    def NUMBER(self, t):
        max_int_64 = 9223372036854775807
        base = 10

        if t.value.endswith('KB'):
            t_int = int(t.value[:-2]) << 10
        elif t.value.endswith('MB'):
            t_int = int(t.value[:-2]) << 20
        elif t.value.startswith('0x'):
            t_int = int(t.value, 16)
            base = 16
        elif t.value.startswith('0o'):
            t_int = int(t.value, 8)
            base = 8
        else:
            t_int = int(t.value)
        if t_int > max_int_64:
            message = 'Found {!r} on line {}; Max: {!r}'.format(t.value, self.lineno, max_int_64)
            raise OverflowError(message)
        t.value = t_int, base
        return t

    @_(r'"')
    def TEXT_STRING(self, t):
        self.push_state(TextStringLexer)

    @_(r'/')
    def REGEXP(self, t):
        self.push_state(RegExpLexer)

    @_(r'}')
    def RULE_END(self, t):
        self.index -= 1
        self.pop_state()


class RuleLexer(BaseLexer):

    tokens = {
        PRIVATE, GLOBAL, META, STRINGS,
        TEXT_STRING, REGEXP, HEX_STRING,
        STRING_IDENTIFIER, NUMBER, TRUE, FALSE
        # COMMENT, SL_COMMENT,
    }

    literals = {'=', '(', ')', '{', '}', '[', ']', '-', ':', }

    ignore = '\t '

    @_(r'\r?[\n]|\r')
    def ignore_newline(self, t):
        self.lineno += 1

    def error(self, t):
        print('Line {}: Bad character{!r}'.format(self.lineno, t.value[0]))
        self.index += 1

    @_(r'(\n|\r|\r\n)')
    def NEWLINE(self, t):
        self.lineno += 1

    @_(r'condition')
    def CONDITION(self, t):
        self.push_state(ConditionLexer)
        return t

    @_(r'\$[0-9a-zA-Z\-_]*')
    def STRING_IDENTIFIER(self, t):
        t.value = t.value
        return t

    @_(r'0x[A-Fa-f0-9]+',
       '0o[0-7]+',
       '[0-9]+(MB|KB){0,1}')
    def NUMBER(self, t):
        base = 10
        max_int_64 = 9223372036854775807

        if t.value.endswith('KB'):
            t_int = int(t.value[:-2]) << 10
        elif t.value.endswith('MB'):
            t_int = int(t.value[:-2]) << 20
        elif t.value.startswith('0x'):
            t_int = int(t.value, 16)
            base = 16
        elif t.value.startswith('0o'):
            t_int = int(t.value, 8)
            base = 8
        else:
            t_int = int(t.value)
        if t_int > max_int_64:
            message = 'Found {!r} on line {}; Max: {!r}'.format(t.value, self.lineno, max_int_64)
            raise OverflowError(message)
        t.value = t_int, base
        return t

    @_(r'"')
    def TEXT_STRING(self, t):
        self.push_state(TextStringLexer)

    @_(r'/')
    def REGEXP(self, t):
        self.push_state(RegExpLexer)

    @_(r'\{')
    def HEX_STRING(self, t):
        self.push_state(HexStringLexer)

    @_(r'}')
    def RULE_END(self, t):
        self.pop_state()
        return t


class YaraLexer(BaseLexer):
    tokens = {IMPORT, INCLUDE, PRIVATE, GLOBAL,
              RULE, IDENTIFIER, RULE_START, RULE_END, }

    literals = {'{', '}', ':', }

    ignore = '\t '

    @_(r'\r?[\n]|\r')
    def ignore_newline(self, t):
        self.lineno += 1

    @_(r'[A-Z_a-z][0-9A-Z_a-z]*')
    def IDENTIFIER(self, t):
        if len(t.value) > 128:
            message = 'Identifier on line {} too long, starts with {!r}'.format(self.lineno, t.value[:20])
            raise ValueError(message)
        t.value = t.value
        return t

    @_(r'\{')
    def RULE_START(self, t):
        self.push_state(RuleLexer)
        return t

    @_(r'\"')
    def TEXT_STRING_begin(self, t):
        self.push_state(TextStringLexer)


class YaraParser(Parser):

    YARA_VERSION = StrictVersion('4.0.0')

    # debugfile = 'debug.log'

    def __init__(self, externals=None):
        self.externals = [] if externals is None else externals
        self.yara_ruleset = YaraRuleSet()
        self._temp_mod_args = None

    tokens = (
            BaseLexer.tokens |
            YaraLexer.tokens |
            RuleLexer.tokens |
            ConditionLexer.tokens
    )

    precedence = (
        ('left', OR, ),
        ('left', AND, ),
        ('left', EQ, NEQ, CONTAINS, MATCHES, ),
        ('left', LT, LE, GT, GE, ),
        ('left', BITWISE_OR, ),
        ('left', BITWISE_XOR, ),
        ('left', BITWISE_AND, ),
        ('left', SHIFT_LEFT, SHIFT_RIGHT, ),
        ('left', PLUS, MINUS, ),
        ('left', MULTIPLY, DIVIDE, REMAINDER, ),
        ('right', NOT, BITWISE_NOT, UNARY_MINUS),
    )

    @_('rules rule')
    def rules(self, p):
        self.yara_ruleset.rules.append(p.rule)

    @_('empty',
       'rules import_',
       'rules include')
    def rules(self, p):
        pass

    @_('IMPORT TEXT_STRING')
    def import_(self, p):
        self.yara_ruleset.imports.append(p.TEXT_STRING)

    @_('INCLUDE TEXT_STRING')
    def include(self, p):
        self.yara_ruleset.includes.append(p.TEXT_STRING)

    @_('rule_modifiers RULE IDENTIFIER tags RULE_START meta strings condition RULE_END')
    def rule(self, p):
        # TODO - prevent duplicate rule names and other identifiers - imports and externals?
        return YaraRule(p.IDENTIFIER, p.rule_modifiers, p.tags, p.meta, p.strings, p.condition)

    @_('empty')
    def meta(self, p):
        pass

    @_('META ":" meta_declarations')
    def meta(self, p):
        return MetaSection(p.meta_declarations)

    @_('empty')
    def strings(self, p):
        pass

    @_('STRINGS ":" string_declarations')
    def strings(self, p):
        return StringsSection(p.string_declarations)

    @_('CONDITION ":" boolean_expression')
    def condition(self, p):
        return ConditionSection(p.boolean_expression)

    @_('empty')
    def rule_modifiers(self, p):
        return RuleModifiers.NONE

    @_('rule_modifiers rule_modifier')
    def rule_modifiers(self, p):
        if p.rule_modifier & p.rule_modifiers:
            message = 'Duplicated rule modifier, {}'.format(p.rule_modifier.name)
            raise ValueError(message)
        return p.rule_modifiers | p.rule_modifier

    @_('PRIVATE')
    def rule_modifier(self, p):
        return RuleModifiers.private_flag

    @_('GLOBAL')
    def rule_modifier(self, p):
        return RuleModifiers.global_flag

    @_('empty')
    def tags(self, p):
        return []

    @_('":" tag_list')
    def tags(self, p):
        return p.tag_list

    @_('IDENTIFIER')
    def tag_list(self, p):
        return [p.IDENTIFIER]

    @_('tag_list IDENTIFIER')
    def tag_list(self, p):
        if p.IDENTIFIER in p.tag_list:
            message = 'Duplicate tag, {}'.format(p.IDENTIFIER)
            raise ValueError(message)
        p.tag_list.append(p.IDENTIFIER)
        return p.tag_list

    @_('meta_declaration')
    def meta_declarations(self, p):
        return [p.meta_declaration]

    @_('meta_declarations meta_declaration')
    def meta_declarations(self, p):
        p.meta_declarations.append(p.meta_declaration)
        return p.meta_declarations

    @_('IDENTIFIER "=" TEXT_STRING')
    def meta_declaration(self, p):
        return Meta(p.IDENTIFIER, MetaTypes.TEXTSTRING, p.TEXT_STRING)

    @_('IDENTIFIER "=" NUMBER')
    def meta_declaration(self, p):
        return Meta(p.IDENTIFIER, MetaTypes.NUMBER, p.NUMBER[0])

    @_('IDENTIFIER "=" "-" NUMBER')
    def meta_declaration(self, p):
        return Meta(p.IDENTIFIER, MetaTypes.NUMBER, - p.NUMBER[0])

    @_('IDENTIFIER "=" TRUE')
    def meta_declaration(self, p):
        return Meta(p.IDENTIFIER, MetaTypes.BOOLEAN, True)

    @_('IDENTIFIER "=" FALSE')
    def meta_declaration(self, p):
        return Meta(p.IDENTIFIER, MetaTypes.BOOLEAN, False)

    @_('string_declaration')
    def string_declarations(self, p):
        return [p.string_declaration]

    @_('string_declarations string_declaration')
    def string_declarations(self, p):
        p.string_declarations.append(p.string_declaration)
        return p.string_declarations

    @_('STRING_IDENTIFIER "=" TEXT_STRING string_modifiers')
    def string_declaration(self, p):
        mod_args = None
        if hasattr(self, '_temp_mod_args'):
            mod_args = self._temp_mod_args
            self._temp_mod_args = None
        return String(p.STRING_IDENTIFIER, StringTypes.TEXTSTRING, p.TEXT_STRING, p.string_modifiers, mod_args)

    @_('STRING_IDENTIFIER "=" REGEXP regexp_modifiers')
    def string_declaration(self, p):
        mod_args = None
        if hasattr(self, '_temp_mod_args'):
            mod_args = self._temp_mod_args
            self._temp_mod_args = None
        regexp_mods = p.REGEXP[1] | p.regexp_modifiers
        if regexp_mods.check_compatibility(StringTypes.REGEXP):
            return String(p.STRING_IDENTIFIER, StringTypes.REGEXP, p.REGEXP[0], regexp_mods, mod_args)

    @_('STRING_IDENTIFIER "=" HEX_STRING hex_modifiers')
    def string_declaration(self, p):
        mod_args = None
        if hasattr(self, '_temp_mod_args'):
            mod_args = self._temp_mod_args
            self._temp_mod_args = None
        return String(p.STRING_IDENTIFIER, StringTypes.HEXSTRING, p.HEX_STRING, p.hex_modifiers, mod_args)

    @_('empty')
    def string_modifiers(self, p):
        return Modifiers.NONE

    @_('string_modifiers string_modifier')
    def string_modifiers(self, p):
        if p.string_modifiers & p.string_modifier:
            raise ValueError('Duplicated text string modifier, {}'.format(p.string_modifier))
        mods = p.string_modifiers | p.string_modifier
        if mods.check_compatibility(StringTypes.TEXTSTRING):
            return mods
        else:
            raise ValueError('Invalid text string modifier combination')

    @_('WIDE',
       'ASCII',
       'NOCASE',
       'FULLWORD',
       'PRIVATE',
       'XOR',
       'BASE64',
       'BASE64_WIDE')
    def string_modifier(self, p):
        return Modifiers[p[0]]

    @_('XOR "(" NUMBER ")"')
    def string_modifier(self, p):
        mod = Modifiers[p[0]]
        if mod.check_compatibility(StringTypes.TEXTSTRING):
            self._temp_mod_args = [p.NUMBER[0]]
            return mod
        else:
            message = 'Invalid modifier {} for text string'.format(p[0])
            raise ValueError(message)

    @_('XOR "(" NUMBER "-" NUMBER ")"')
    def string_modifier(self, p):
        mod = Modifiers[p[0]]
        if mod.check_compatibility(StringTypes.TEXTSTRING):
            self._temp_mod_args = [p.NUMBER0[0], p.NUMBER1[0]]
            return mod
        else:
            message = 'Invalid modifier {} for text string'.format(p[0])
            raise ValueError(message)

    @_('BASE64 "(" TEXT_STRING ")"',
       'BASE64_WIDE "(" TEXT_STRING ")"')
    def string_modifier(self, p):
        mod = Modifiers[p[0]]
        if mod.check_compatibility(StringTypes.TEXTSTRING):
            self._temp_mod_args = p.TEXT_STRING
            return mod
        else:
            message = 'Invalid modifier {} for text string'.format(p[0])
            raise ValueError(message)

    @_('empty')
    def regexp_modifiers(self, p):
        return Modifiers.NONE

    @_('regexp_modifiers regexp_modifier')
    def regexp_modifiers(self, p):
        if p.regexp_modifiers & p.regexp_modifiers:
            raise ValueError('Duplicated regexp modifier, {}'.format(p.regexp_modifier))
        mods = p.regexp_modifiers | p.regexp_modifier
        if mods.check_compatibility(StringTypes.REGEXP):
            return mods
        else:
            raise ValueError('Invalid regexp modifier combination')

    @_('WIDE',
       'ASCII',
       'NOCASE',
       'FULLWORD',
       'PRIVATE')
    def regexp_modifier(self, p):
        return Modifiers[p[0]]

    @_('empty')
    def hex_modifiers(self, p):
        return Modifiers.NONE

    @_('hex_modifiers hex_modifier')
    def hex_modifiers(self, p):
        if p.hex_modifiers & p.hex_modifier:
            raise ValueError('Duplicated hex string modifier, {}'.format(p.hex_modifier))
        mods = p.hex_modifiers | p.hex_modifier
        if mods.check_compatibility(StringTypes.HEXSTRING):
            return mods
        else:
            raise ValueError('Invalid hex string modifier combination')

    @_('PRIVATE')
    def hex_modifier(self, p):
        return Modifiers[p.PRIVATE]

    @_('IDENTIFIER')
    def identifier(self, p):
        return Identifier(p.IDENTIFIER)

    @_('identifier "." IDENTIFIER')
    def identifier(self, p):
        return MemberAccess(p.identifier, p.IDENTIFIER)

    @_('identifier "[" primary_expression "]"')
    def identifier(self, p):
        return Subscripting(p.identifier, p.primary_expression)

    @_('identifier "(" arguments ")"')
    def identifier(self, p):
        return FunctionCall(p.identifier, p.arguments)

    @_('empty')
    def arguments(self, p):
        return []

    @_('arguments_list')
    def arguments(self, p):
        return p.arguments_list

    @_('expression')
    def arguments_list(self, p):
        return [Expression(p.expression)]

    @_('arguments_list "," expression')
    def arguments_list(self, p):
        p.arguments_list.append(p.expression)
        return p.arguments_list

    @_('REGEXP')
    def regexp(self, p):
        return p.REGEXP

    @_('expression')
    def boolean_expression(self, p):
        return p.expression

    @_('TRUE',
       'FALSE')
    def expression(self, p):
        return Keyword(Keywords[p[0]])

    @_('primary_expression MATCHES REGEXP',)
    def expression(self, p):
        return Operation(BinaryOperators(p[1]), p.primary_expression,
                         Literals(p.REGEXP[0], LiteralTypes.regexp, p.REGEXP[1]))

    @_('primary_expression CONTAINS primary_expression')
    def expression(self, p):
        return Operation(BinaryOperators(p[1]), p.primary_expression0, p.primary_expression1)

    @_('STRING_IDENTIFIER')
    def expression(self, p):
        # TODO - Check if in iterator with anonymous in iterators
        if p.STRING_IDENTIFIER == '$':
            print('potential misuse of anonymous string on line {}'.format(p.lineno))
            return StringIdentifier(Identifier(p.STRING_IDENTIFIER))
        str_sym = None
        for sym in self.symstack:
            if sym.type == 'strings':
                str_sym = sym.value
                break
        if str_sym is not None and p.STRING_IDENTIFIER not in str_sym.public_names:
            message = 'Undefined string identifier, {}, used in condition on line {}'.format(p.STRING_IDENTIFIER, p.lineno)
            raise ValueError(message)
        return StringIdentifier(Identifier(p.STRING_IDENTIFIER))

    @_('STRING_IDENTIFIER AT primary_expression')
    def expression(self, p):
        # TODO - Check if in iterator with anonymous in iterators
        if p.STRING_IDENTIFIER == '$':
            print('potential misuse of anonymous string on line {}'.format(p.lineno))
            return StringIdentifier(Identifier(p.STRING_IDENTIFIER))
        str_sym = None
        for sym in self.symstack:
            if sym.type == 'strings':
                str_sym = sym.value
                break
        if str_sym is not None and p.STRING_IDENTIFIER not in str_sym.public_names:
            message = 'Undefined string identifier, {}, used in condition on line {}'.format(p.STRING_IDENTIFIER, p.lineno)
            raise ValueError(message)
        return StringIdentifier(Identifier(p.STRING_IDENTIFIER), p.primary_expression)

    @_('STRING_IDENTIFIER IN range')
    def expression(self, p):
        # TODO - Check if in iterator with anonymous in iterators
        if p.STRING_IDENTIFIER == '$':
            print('potential misuse of anonymous string on line {}'.format(p.lineno))
            return StringIdentifier(Identifier(p.STRING_IDENTIFIER))
        str_sym = None
        for sym in self.symstack:
            if sym.type == 'strings':
                str_sym = sym.value
                break
        if str_sym is not None and p.STRING_IDENTIFIER not in str_sym.public_names:
            message = 'Undefined string identifier, {}, used in condition on line {}'.format(p.STRING_IDENTIFIER, p.lineno)
            raise ValueError(message)
        return StringIdentifier(Identifier(p.STRING_IDENTIFIER), p.range)

    @_('FOR for_expression error')
    def expression(self, p):
        raise ValueError('For Expresssion error on line {}'.format(p.lineno))

    @_('FOR for_expression for_variables IN iterator ":" "(" boolean_expression ")"')
    def expression(self, p):
        return ForIn(p.for_expression, p.for_variables, p.iterator, p.boolean_expression)

    @_('FOR for_expression OF string_set ":" "(" boolean_expression ")"')
    def expression(self, p):
        return ForOf(p.for_expression, p.string_set, p.boolean_expression)

    @_('for_expression OF string_set')
    def expression(self, p):
        return Of(p.for_expression, p.string_set)

    @_('NOT boolean_expression')
    def expression(self, p):
        return UnaryOperation(UnaryOperators.logical_not, p.boolean_expression)

    @_('boolean_expression AND boolean_expression',
       'boolean_expression OR boolean_expression')
    def expression(self, p):
        if isinstance(p.boolean_expression0, Operation):
            if p.boolean_expression0.operator is BinaryOperators(p[1]):
                p.boolean_expression0.append(p.boolean_expression1)
                return p.boolean_expression0
        return Operation(BinaryOperators(p[1]), p.boolean_expression0, p.boolean_expression1)

    @_('boolean_expression AND error',
       'boolean_expression OR error')
    def expression(self, p):
        raise ValueError('Unterminated logical operator error on line {}'.format(p.lineno))

    @_('primary_expression LE primary_expression',
       'primary_expression GE primary_expression',
       'primary_expression LT primary_expression',
       'primary_expression GT primary_expression',
       'primary_expression EQ primary_expression',
       'primary_expression NEQ primary_expression')
    def expression(self, p):
        return Operation(BinaryOperators(p[1]), p.primary_expression0, p.primary_expression1)

    @_('primary_expression')
    def expression(self, p):
        return p.primary_expression

    @_('"(" expression ")"')  # TODO - fix shift/reduce ambiguity
    def expression(self, p):
        return Group(p.expression)

    @_(' "(" integer_enumeration ")" ')
    def integer_set(self, p):
        return Enum(p.integer_enumeration)

    @_('range')
    def integer_set(self, p):
        return p.range

    @_('"(" primary_expression DOT_DOT primary_expression ")"')
    def range(self, p):
        return Range(p.primary_expression0, p.primary_expression1)

    @_('primary_expression')
    def integer_enumeration(self, p):
        return [Expression(p.primary_expression)]

    @_('integer_enumeration "," primary_expression')
    def integer_enumeration(self, p):
        p.integer_enumeration.append(p.primary_expression)
        return p.integer_enumeration

    @_('"(" string_enumeration ")"')
    def string_set(self, p):
        return Enum(p.string_enumeration)

    @_('THEM')
    def string_set(self, p):
        return Keyword(Keywords.them)

    @_('string_enumeration_item')
    def string_enumeration(self, p):
        return [Expression(p.string_enumeration_item)]

    @_('string_enumeration "," string_enumeration_item')
    def string_enumeration(self, p):
        p.string_enumeration.append(p.string_enumeration_item)
        return p.string_enumeration

    @_('STRING_IDENTIFIER')
    def string_enumeration_item(self, p):
        # TODO - Check if in iterator with anonymous in iterators
        if p.STRING_IDENTIFIER == '$':
            print('potential misuse of anonymous string on line {}'.format(p.lineno))
            return StringIdentifier(Identifier(p.STRING_IDENTIFIER))
        str_sym = None
        for sym in self.symstack:
            if sym.type == 'strings':
                str_sym = sym.value
                break
        if str_sym is not None and p.STRING_IDENTIFIER not in str_sym.public_names:
            message = 'Undefined string identifier, {}, used in condition on line {}'.format(p.STRING_IDENTIFIER, p.lineno)
            raise ValueError(message)
        return StringIdentifier(Identifier(p.STRING_IDENTIFIER))

    @_('STRING_IDENTIFIER_WITH_WILDCARD')
    def string_enumeration_item(self, p):
        str_sym = None
        for sym in self.symstack:
            if sym.type == 'strings':
                str_sym = sym.value
                break
        if str_sym is not None:
            if p.STRING_IDENTIFIER_WITH_WILDCARD == '$*':
                return StringIdentifier(Identifier(p.STRING_IDENTIFIER_WITH_WILDCARD))
            for name in str_sym.public_names:
                if name.startswith(p.STRING_IDENTIFIER_WITH_WILDCARD.rstrip('*')):
                    return StringIdentifier(Identifier(p.STRING_IDENTIFIER_WITH_WILDCARD))
        message = f'Undefined string identifier, {p.STRING_IDENTIFIER}, used in condition on line {p.lineno}'
        raise ValueError(message)

    @_('primary_expression')
    def for_expression(self, p):
        return Quantifier(p.primary_expression)

    @_('ALL')
    def for_expression(self, p):
        return Quantifier(Keyword(Keywords.all))

    @_('ANY')
    def for_expression(self, p):
        return Quantifier(Keyword(Keywords.any))

    @_('IDENTIFIER')
    def for_variables(self, p):
        return [Identifier(p.IDENTIFIER)]

    @_('for_variables "," IDENTIFIER')
    def for_variables(self, p):
        p.for_variables.append(p.IDENTIFIER)
        return p.for_variables

    @_('identifier')
    def iterator(self, p):
        return p.identifier

    @_('integer_set')
    def iterator(self, p):
        return p.integer_set

    @_('"(" primary_expression ")"')
    def primary_expression(self, p):
        return Group(p.primary_expression)

    @_('FILESIZE')
    def primary_expression(self, p):
        return Keyword(Keywords.filesize)

    @_('ENTRYPOINT')
    def primary_expression(self, p):
        return Keyword(Keywords.entrypoint)

    @_('INTEGER_FUNCTION "(" primary_expression ")"')
    def primary_expression(self, p):
        return FunctionCall(Identifier(IntegerFuctions[p.INTEGER_FUNCTION]), p.primary_expression)

    @_('NUMBER')
    def primary_expression(self, p):
        return Literals(p.NUMBER[0], LiteralTypes(p.NUMBER[1]))

    @_('DOUBLE')
    def primary_expression(self, p):
        return Literals(p.DOUBLE, LiteralTypes.float)

    @_('TEXT_STRING')
    def primary_expression(self, p):
        return Literals(p.TEXT_STRING, LiteralTypes.string)

    @_('STRING_COUNT')
    def primary_expression(self, p):
        # TODO - Check if in iterator with anonymous in iterators
        if p.STRING_COUNT == '#':
            print('potential misuse of anonymous string on line {}'.format(p.lineno))
        return StringCount(Identifier(p.STRING_COUNT))

    @_('STRING_OFFSET "[" primary_expression "]"')
    def primary_expression(self, p):
        # TODO - Check if in iterator with anonymous in iterators
        if p.STRING_OFFSET == '@':
            print('potential misuse of anonymous string on line {}'.format(p.lineno))
        return StringOffset(Identifier(p.STRING_OFFSET), p.primary_expression)

    @_('STRING_OFFSET')
    def primary_expression(self, p):
        # TODO - Check if in iterator with anonymous in iterators
        if p.STRING_OFFSET == '@':
            print('potential misuse of anonymous string on line {}'.format(p.lineno))
        return StringOffset(Identifier(p.STRING_OFFSET))

    @_('STRING_LENGTH "[" primary_expression "]"')
    def primary_expression(self, p):
        # TODO - Check if in iterator with anonymous in iterators
        if p.STRING_LENGTH == '!':
            print('potential misuse of anonymous string on line {}'.format(p.lineno))
        return StringLength(Identifier(p.STRING_LENGTH), p.primary_expression)

    @_('STRING_LENGTH')
    def primary_expression(self, p):
        # TODO - Check if in iterator with anonymous in iterators
        if p.STRING_LENGTH == '!':
            print('potential misuse of anonymous string on line {}'.format(p.lineno))
        return StringLength(Identifier(p.STRING_LENGTH))

    @_('identifier')
    def primary_expression(self, p):
        return p.identifier

    @_('MINUS primary_expression %prec UNARY_MINUS')
    def primary_expression(self, p):
        return UnaryOperation(UnaryOperators.unary_minus, p.primary_expression)

    @_('primary_expression PLUS primary_expression',
       'primary_expression MINUS primary_expression',
       'primary_expression MULTIPLY primary_expression',
       'primary_expression DIVIDE primary_expression',
       'primary_expression REMAINDER primary_expression',
       'primary_expression BITWISE_XOR primary_expression',
       'primary_expression BITWISE_AND primary_expression',
       'primary_expression BITWISE_OR primary_expression')
    def primary_expression(self, p):
        if isinstance(p.primary_expression0, Operation):
            if p.primary_expression0.operator is BinaryOperators(p[1]):
                p.primary_expression0.append(p.primary_expression1)
                return p.primary_expression0
        return Operation(BinaryOperators(p[1]), p.primary_expression0, p.primary_expression1)

    @_('BITWISE_NOT primary_expression')
    def primary_expression(self, p):
        return UnaryOperation(UnaryOperators.bitwise_not, p.primary_expression)

    @_('primary_expression SHIFT_LEFT primary_expression',
       'primary_expression SHIFT_RIGHT primary_expression')
    def primary_expression(self, p):
        if isinstance(p.primary_expression0, Operation):
            if p.primary_expression0.operator is BinaryOperators(p[1]):
                p.primary_expression0.append(p.primary_expression1)
                return p.primary_expression0
        return Operation(BinaryOperators(p[1]), p.primary_expression0, p.primary_expression1)

    @_('regexp')
    def primary_expression(self, p):
        return p.regexp

    @_('')
    def empty(self, p):
        pass

    def error(self, p):
        if p is None:
            pass
        elif p.type == 'RULE_END':
            message = 'Unexpected rule end on line {} after type {!r}, value "{}"'.format(
                p.lineno, self.symstack[-1].type,  self.symstack[-1].value
            )
            raise TypeError(message)
        else:
            message = 'Unknown text {!r} for token of type {} on line {}'.format(p.value, p.type, p.lineno)
            self.errok()
            raise TypeError(message)


class Slyara:
    def parse_rule(self, filepath: str = None, source: str = None) -> YaraRuleSet:
        lexer = YaraLexer()
        parser = YaraParser()

        if filepath is source is None:
            raise ValueError('filepath or source must be provided')
        if filepath is not None:
            with open(filepath, 'r', encoding='utf8', errors='ignore') as f:
                source = f.read()
        parser.parse(lexer.tokenize(source))
        return parser.yara_ruleset

    def parse_string(self, input_string: str) -> YaraRuleSet:
        return self.parse_rule(source=input_string)

if __name__ == '__main__':
    with open('../tests/data/import_ruleset_cuckoo.yar') as f:
        yl = YaraLexer()
        for tok in yl.tokenize(f.read()):
            pass
            print(tok)
