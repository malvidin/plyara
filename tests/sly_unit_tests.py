#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2014 Christian Buia
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
"""slyara unit tests.

This module contains various unit tests for slyara.
"""
import concurrent.futures
import contextlib
import hashlib
import io
from pathlib import Path
import sys
import unittest

from slyara import Slyara
from slyara.objects import *
# from plyara.exceptions import ParseTypeError, ParseValueError
# from plyara.utils import generate_logic_hash
# from plyara.utils import rebuild_yara_rule
# from plyara.utils import detect_imports, detect_dependencies
# from plyara.utils import is_valid_rule_name, is_valid_rule_tag
# from plyara.command_line import main

UNHANDLED_RULE_MSG = 'Unhandled Test Rule: {}'

tests = Path('tests')
if tests.is_dir():
    data_dir = tests.joinpath('data')
else:
    data_dir = Path('data')


@contextlib.contextmanager
def captured_output():
    """Capture stdout and stderr from execution."""
    new_out, new_err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestUtilities(unittest.TestCase):

    def test_logic_hash_generator(self):
        with data_dir.joinpath('logic_collision_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = Slyara().parse_rule(data_dir.joinpath('logic_collision_ruleset.yar'))

        rule_mapping = {}

        for rule in result:
            rulename = rule.name
            setname, _ = rulename.split('_')
            rulehash = rule.generate_hash()

            if setname not in rule_mapping:
                rule_mapping[setname] = [rulehash]
            else:
                rule_mapping[setname].append(rulehash)

        for setname, hashvalues in rule_mapping.items():
            self.assertEqual(len(set(hashvalues)), 1)
            if not len(set(hashvalues)) == 1:
                raise AssertionError('Collision detection failure for {}'.format(setname))

    def test_logic_hash_generator_output(self):
        with data_dir.joinpath('rulehashes.txt').open('r') as fh:
            rule_hashes = fh.read().splitlines()

        results = Slyara().parse_rule(data_dir.joinpath('test_rules_from_yara_project.yar'))

        for index, result in enumerate(results):
            rulehash = result.generate_hash()
            self.assertEqual(rulehash, rule_hashes[index])

    def test_is_valid_rule_name(self):
        valid_names = ('test', 'test123', 'test_test', '_test_', 'include_test', 'x' * 128, )
        for name in valid_names:
            self.assertIsInstance(YaraRule(name), YaraRule, msg=f'Valid rule name {name} was not accepted')

    def test_is_invalid_rule_name(self):
        invalid_names = ('123test', '123 test', 'test 123', 'test test',
                         'test-test', 'include', 'test!*@&*!&', '', 'x' * 129,)
        for name in invalid_names:
            with self.assertRaises(ValueError, msg=f'Invalid rule name {name} was accepted'):
                YaraRule(name)

    def test_is_valid_rule_tag(self):
        valid_names = ('test', 'test123', 'test_test', '_test_', 'include_test', 'x' * 128, )
        for name in valid_names:
            self.assertIn(name, IdentifierSet([name]), msg=f'Valid rule name {name} was not accepted')

    def test_is_invalid_rule_tag(self):
        invalid_names = ('123test', '123 test', 'test 123', 'test test',
                         'test-test', 'include', 'test!*@&*!&', '', 'x' * 129,)
        for name in invalid_names:
            with self.assertRaises(ValueError, msg=f'Invalid tag name {name} was accepted'):
                IdentifierSet([name])
                IdentifierSet().add(name)

    def test_rebuild_yara_rule(self):
        with data_dir.joinpath('rebuild_ruleset.yar').open('r', encoding='utf-8') as fh:
            inputString = fh.read()

        result = Slyara().parse_rule(source=inputString)

        rebuilt_rules = str(result)
        self.assertEqual(inputString, rebuilt_rules)

    def test_rebuild_yara_rule_metadata(self):
        test_rule = """
        rule check_meta {
            meta:
                string_value = "TEST STRING"
                string_value = "DIFFERENT TEST STRING"
                bool_value = true
                bool_value = false
                digit_value = 5
                digit_value = 10
            condition:
                true
        }
        """
        result = Slyara().parse_rule(source=test_rule)
        for rule in result:
            unparsed = str(rule)
            self.assertIn('string_value = "TEST STRING"', unparsed)
            self.assertIn('string_value = "DIFFERENT TEST STRING"', unparsed)
            self.assertIn('bool_value = true', unparsed)
            self.assertIn('bool_value = false', unparsed)
            self.assertIn('digit_value = 5', unparsed)
            self.assertIn('digit_value = 10', unparsed)

    def test_detect_dependencies(self):
        with data_dir.joinpath('detect_dependencies_ruleset.yar').open('r') as fh:
            inputString = fh.read()

        result = Slyara().parse_string(inputString)

        expected_externals = (
            None, None, None,
            ['is__osx', 'priv01', 'priv02', 'priv03', 'priv04'],
            ['is__elf', 'priv01', 'priv02', 'priv03', 'priv04'],
            ['is__elf', 'is__osx', 'priv01', 'priv02'],
            ['is__elf', 'is__osx', 'priv01'],
            ['is__elf'],
            ['is__osx', 'is__elf'],
            ['is__osx'],
            ['is__elf', 'is__osx'],
            ['is__osx'],
            None, None,
            ['is__osx'],
            ['is__osx'],
        )
        for i, rule in enumerate(result):
            self.assertEqual(rule.condition.externals, IdentifierSet(expected_externals[i]),
                             msg=f'External identifiers in {rule.name} '
                                 f'did not match expected identifiers, {expected_externals[i]}')

    def test_detect_imports(self):
        for imp in ('pe', 'elf', 'cuckoo', 'magic', 'hash', 'math', 'dotnet', 'androguard'):
            results = Slyara().parse_rule(data_dir.joinpath(f'import_ruleset_{imp}.yar'))
            for rule in results:
                # TODO - Implement a node visitor that gathers likely imports and externals
                self.assertIn(imp, rule.condition.imports,
                              msg=f'while inspecting rule import_ruleset_{imp}.yar')


class TestRuleParser(unittest.TestCase):

    def setUp(self):
        self.parser = Slyara()

    def test_imports(self):
        for imp in ('pe', 'elf', 'cuckoo', 'magic', 'hash', 'math', 'dotnet', 'androguard'):
            result = self.parser.parse_rule(data_dir.joinpath(f'import_ruleset_{imp}.yar'))
            self.assertIn(imp, result.imports)

    def test_flags(self):
        result = self.parser.parse_rule(data_dir.joinpath('flags_ruleset.yar'))

        for rule in result:
            flags = rule.flags.get_str()
            for flag in flags.split(' '):
                self.assertIn(str(flag), rule.name.lower(), msg=f'{flag} not found in {rule.name}')

    def test_tags(self):
        result = self.parser.parse_rule(data_dir.joinpath('tag_ruleset.yar'))

        for rule in result:
            rulename = rule.name

            if rule.name == 'OneTag':
                self.assertEqual(rule.tags, IdentifierSet(['tag1']))

            elif rule.name == 'TwoTags':
                self.assertEqual(rule.tags, IdentifierSet(['tag1', 'tag2']))

            elif rule.name == 'ThreeTags':
                self.assertEqual(rule.tags, IdentifierSet(['tag1', 'tag2', 'tag3']))

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rule.name))

    def test_metadata(self):
        result = self.parser.parse_rule(data_dir.joinpath('metadata_ruleset.yar'))

        for rule in result:
            kv = rule.meta.get_meta_as_kv()
            kv_list = rule.meta.get_meta()

            if rule.name == 'StringTypeMetadata':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0][0], 'string_value')
                self.assertEqual(kv_list[0][1], 'String Metadata')

            elif rule.name == 'IntegerTypeMetadata':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0][0], 'integer_value')
                self.assertIs(kv_list[0][1], 100)

            elif rule.name == 'BooleanTypeMetadata':
                self.assertEqual(len(kv), 1)
                self.assertEqual(kv_list[0][0], 'boolean_value')
                self.assertIs(kv_list[0][1], True)

            elif rule.name == 'AllTypesMetadata':
                self.assertEqual(len(kv), 3)
                self.assertEqual(kv_list[0][0], 'string_value')
                self.assertEqual(kv_list[1][0], 'integer_value')
                self.assertEqual(kv_list[2][0], 'boolean_value')
                self.assertEqual(kv_list[0][1], 'Different String Metadata')
                self.assertIs(kv_list[1][1], 33)
                self.assertIs(kv_list[2][1], False)

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rule.name))

    def test_strings(self):
        result = self.parser.parse_rule(data_dir.joinpath('string_ruleset.yar'))

        for rule in result:
            if not hasattr(rule.strings, 'to_json'):
                raise NotImplementedError('JSON dump of strings not yet implemented')
            strings_json = rule.strings.to_json()

            if rule.name == 'Text':
                self.assertEqual(strings_json, [{'name': '$text_string', 'value': 'foobar', 'type': 'textstring'}])

            elif rule.name == 'FullwordText':
                self.assertEqual(strings_json, [{
                    'name': '$text_string',
                    'value': 'foobar',
                    'type': 'textstring',
                    'modifiers': ['fullword']}])

            elif rule.name == 'CaseInsensitiveText':
                self.assertEqual(strings_json, [{'name': '$text_string',
                                                 'value': 'foobar',
                                                 'type': 'textstring',
                                                 'modifiers': ['nocase']}])

            elif rule.name == 'WideCharText':
                self.assertEqual(strings_json, [{'name': '$wide_string',
                                                 'value': 'Borland',
                                                 'type': 'textstring',
                                                 'modifiers': ['wide']}])

            elif rule.name == 'WideCharAsciiText':
                self.assertEqual(strings_json, [{'name': '$wide_and_ascii_string',
                                                 'value': 'Borland',
                                                 'type': 'textstring',
                                                 'modifiers': ['wide', 'ascii']}])

            elif rule.name == 'HexWildcard':
                self.assertEqual(strings_json, [{'name': '$hex_string', 'value': '{ E2 34 ?? C8 A? FB }',
                                                 'type': 'hexstring'}])

            elif rule.name == 'HexJump':
                self.assertEqual(strings_json, [{'name': '$hex_string', 'value': '{ F4 23 [4-6] 62 B4 }',
                                                 'type': 'hexstring'}])

            elif rule.name == 'HexAlternatives':
                self.assertEqual(strings_json, [{'name': '$hex_string', 'value': '{ F4 23 ( 62 B4 | 56 ) 45 }',
                                                 'type': 'hexstring'}])

            elif rule.name == 'HexMultipleAlternatives':
                self.assertEqual(strings_json, [{'name': '$hex_string',
                                                 'value': '{ F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }',
                                                 'type': 'hexstring'}])

            elif rule.name == 'RegExp':
                self.assertEqual(strings_json, [
                    {
                        'name': '$re1',
                        'value': '/md5: [0-9a-fA-F]{32}/',
                        'type': 'regexp',
                        'modifiers': ['nocase'],
                    },
                    {
                        'name': '$re2',
                        'value': '/state: (on|off)/i',
                        'type': 'regexp',
                    },
                    {
                        'name': '$re3',
                        'value': r'/\x00https?:\/\/[^\x00]{4,500}\x00\x00\x00/',
                        'type': 'regexp',
                    }])

            elif rule.name == 'Xor':
                self.assertEqual(strings_json, [{'name': '$xor_string',
                                                 'value': 'This program cannot',
                                                 'type': 'textstring',
                                                 'modifiers': ['xor']}])

            elif rule.name == 'WideXorAscii':
                self.assertEqual(strings_json, [{'name': '$xor_string',
                                                 'value': 'This program cannot',
                                                 'type': 'textstring',
                                                 'modifiers': ['xor', 'wide', 'ascii']}])

            elif rule.name == 'WideXor':
                self.assertEqual(strings_json, [{'name': '$xor_string',
                                                 'value': 'This program cannot',
                                                 'type': 'textstring',
                                                 'modifiers': ['xor', 'wide']}])

            elif rule.name == 'DoubleBackslash':
                self.assertEqual(strings_json, [{'name': '$bs', 'value': r'\"\\\\\\\"', 'type': 'textstring'}])

            else:
                raise AssertionError(UNHANDLED_RULE_MSG.format(rule.name))

    def test_conditions(self):
        result = self.parser.parse_rule(data_dir.joinpath('condition_ruleset.yar'))

        for rule in result:
            self.assertIn('filename', rule.condition.externals)

    def test_include(self):
        result = self.parser.parse_rule(data_dir.joinpath('include_ruleset.yar'))
        self.assertIn('string_ruleset.yar', result.includes)

    def test_include_statements(self):
        result = self.parser.parse_string('include "file1.yara"\ninclude "file2.yara"\ninclude "file3.yara"')
        self.assertEqual(result.includes, OrderedSet(['file1.yara', 'file2.yara', 'file3.yara']))

    def test_rules_from_yara_project(self):
        result = self.parser.parse_rule(data_dir.joinpath('test_rules_from_yara_project.yar'))
        self.assertEqual(len(result), 293)

    def test_multiple_threads(self):
        with data_dir.joinpath('test_rules_from_yara_project.yar').open('r') as fh:
            inputRules = fh.read()

        def parse_rules(rules):
            slyara = Slyara()
            return slyara.parse_string(inputRules)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
            futs = [e.submit(parse_rules, inputRules) for _ in range(4)]
            for fut in concurrent.futures.as_completed(futs):
                self.assertEqual(len(fut.result()), 293)

    def test_clear(self):
        # instantiate parser
        parser = Slyara()

        # open a ruleset with one or more rules
        with data_dir.joinpath('test_ruleset_2_rules.yar').open('r') as fh:
            inputRules = fh.read()

        # parse the rules
        parser.parse_string(inputRules)

        # clear the parser's state
        # parser.clear()

        # open a ruleset with one rule
        with data_dir.joinpath('test_ruleset_1_rule.yar').open('r') as fh:
            inputRules = fh.read()

        # parse the rules
        result = parser.parse_string(inputRules)

        # does the result contain just the rule from the second parse
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, 'rule_one')


class TestRuleParserKVMeta(unittest.TestCase):

    def setUp(self):
        self.parser = Slyara()

    def test_meta_kv(self):
        with data_dir.joinpath('metakv_test.yar').open('r') as fh:
            inputString = fh.read()
        reference0 = {'author': 'Malware Utkonos',
                      'date': '2020-01-04',
                      'tlp': 'Green'}
        reference1 = {'author': 'Someone else',
                      'date': '2020-01-04',
                      'tlp': 'Green'}

        result = self.parser.parse_string(inputString)

        self.assertEqual(result[0].meta.get_meta_as_kv(), reference0)
        self.assertEqual(result[1].meta.get_meta_as_kv(), reference1)


class TestYaraRules(unittest.TestCase):

    def test_multiple_rules(self):
        inputString = '''
        rule FirstRule {
            meta:
                author = "Andrés Iniesta"
                date = "2015-01-01"
            strings:
                $a = "hark, a \\"string\\" here" fullword ascii
                $b = { 00 22 44 66 88 aa cc ee }
            condition:
                all of them
            }

        import "bingo"
        import "bango"
        rule SecondRule : aTag {
            meta:
                author = "Ivan Rakitić"
                date = "2015-02-01"
            strings:
                $x = "hi"
                $y = /state: (on|off)/ wide
                $z = "bye"
            condition:
                for all of them : ( # > 2 )
        }

        rule ThirdRule {condition: uint32(0) == 0xE011CFD0}
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputString)

        self.assertEqual(len(result), 3)
        kv_list = result.rules[0].meta.get_meta()
        self.assertEqual(kv_list[0][0], 'author')
        self.assertEqual(kv_list[0][1], 'Andrés Iniesta')
        self.assertEqual(kv_list[1][0], 'date')
        self.assertEqual(kv_list[1][1], '2015-01-01')
        self.assertEqual([x.name for x in result[0].strings], ['$a', '$b'])

    def test_rule_name_imports_and_flags(self):
        inputStringNIS = r'''
        rule four {meta: i = "j" strings: $a = "b" condition: true }

        global rule five {meta: i = "j" strings: $a = "b" condition: $a }

        private rule six {meta: i = "j" strings: $a = "b" condition: $a }

        global private rule seven {meta: i = "j" strings: $a = "b" condition: $a }

        import "lib1"
        rule eight {meta: i = "j" strings: $a = "b" condition: $a and lib1.dummy() }

        import "lib1"
        import "lib2"
        rule nine {meta: i = "j" strings: $a = "b" condition: $a and lib1.dummy() and lib2.dummy() }

        import "lib2"
        private global rule ten {meta: i = "j" strings: $a = "b" condition: $a and lib2.dummy() }
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputStringNIS)

        self.assertEqual(len(result), 7)

        for rule in result:
            rule_name = rule.name
            if rule_name == 'four':
                self.assertEqual(result.imports & rule.condition.imports, IdentifierSet())
                self.assertEqual(rule.flags, RuleModifiers.NONE)
            if rule_name == 'five':
                self.assertEqual(result.imports & rule.condition.imports, IdentifierSet())
                self.assertEqual(rule.flags, RuleModifiers.global_flag)
            if rule_name == 'six':
                self.assertEqual(result.imports & rule.condition.imports, IdentifierSet())
                self.assertEqual(rule.flags, RuleModifiers.private_flag)
            if rule_name == 'seven':
                self.assertEqual(result.imports & rule.condition.imports, IdentifierSet())
                self.assertEqual(rule.flags, RuleModifiers.private_flag | RuleModifiers.global_flag)
            if rule_name == 'eight':
                self.assertEqual(result.imports & rule.condition.imports, IdentifierSet(['lib1']))
                self.assertEqual(rule.flags, RuleModifiers.NONE)
            if rule_name == 'nine':
                self.assertEqual(result.imports & rule.condition.imports, IdentifierSet(['lib1', 'lib2']))
                self.assertEqual(rule.flags, RuleModifiers.NONE)
            if rule_name == 'ten':
                self.assertEqual(result.imports & rule.condition.imports, IdentifierSet(['lib2']))
                self.assertEqual(rule.flags, RuleModifiers.ALL)

    def test_rule_name_imports_by_instance(self):
        input1 = r'''
        rule one {meta: i = "j" strings: $a = "b" condition: true }

        '''
        input2 = r'''
        import "lib1"
        rule two {meta: i = "j" strings: $a = "b" condition: $a }

        import "lib2"
        private global rule three {meta: i = "j" strings: $a = "b" condition: $a }
        '''

        slyara = Slyara()
        result1 = slyara.parse_string(input1)
        result2 = slyara.parse_string(input2)

        self.assertEqual(len(result1), 1)
        self.assertEqual(len(result2), 2)

        for rule in result1:
            rule_name = rule.name

            if rule_name == 'one':
                self.assertEqual(rule.flags, RuleModifiers.NONE)
                self.assertEqual(result1.imports & rule.condition.imports, IdentifierSet())

        for rule in result2:
            rule_name = rule.name

            if rule_name == 'two':
                self.assertEqual(rule.flags, RuleModifiers.NONE)
                self.assertEqual(result2.imports & rule.condition.imports, IdentifierSet(['lib1', 'lib2']))

            if rule_name == 'three':
                self.assertEqual(rule.flags, RuleModifiers.ALL)
                self.assertEqual(result2.imports & rule.condition.imports, IdentifierSet(['lib1', 'lib2']))

    def test_rule_name(self):
        inputRule = r'''
        rule testName
        {
        meta:
        my_identifier_1 = ""
        my_identifier_2 = 24
        my_identifier_3 = true

        strings:
                $my_text_string = "text here"
                $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
                $my_text_string or $my_hex_string
        }
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRule)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, 'testName')

    def test_store_raw(self):
        inputRule = r'''
        rule testName
        {
        meta:
            my_identifier_1 = ""
            my_identifier_2 = 24
            my_identifier_3 = true

        strings:
            $my_text_string = "text here"
            $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
            $my_text_string or $my_hex_string
        }

        rule testName2 {
        strings:
            $test1 = "some string"

        condition:
            $test1 or true
        }

        rule testName3 {

        condition:
            true
        }

        rule testName4 : tag1 tag2 {meta: i = "j" strings: $a = "b" condition: true }
        '''

        slyara = Slyara(store_raw_sections=True)
        result = slyara.parse_string(inputRule)

        self.assertEqual(len(result), 4)
        self.assertTrue(result[0].get('raw_meta', False))
        self.assertTrue(result[0].get('raw_strings', False))
        self.assertTrue(result[0].get('raw_condition', False))

        self.assertFalse(result[1].get('raw_meta', False))
        self.assertTrue(result[1].get('raw_strings', False))
        self.assertTrue(result[1].get('raw_condition', False))

        self.assertFalse(result[2].get('raw_meta', False))
        self.assertFalse(result[2].get('raw_strings', False))
        self.assertTrue(result[2].get('raw_condition', False))

        self.assertTrue(result[3].get('raw_meta', False))
        self.assertTrue(result[3].get('raw_strings', False))
        self.assertTrue(result[3].get('raw_condition', False))

    def test_tags(self):
        inputTags = r'''
        rule eleven: tag1 {meta: i = "j" strings: $a = "b" condition: true }

        rule twelve : tag1 tag2 {meta: i = "j" strings: $a = "b" condition: true }
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputTags)

        for rule in result:
            rule_name = rule.name
            if rule_name == 'eleven':
                self.assertEqual(len(rule.tags), 1)
                self.assertIn('tag1', rule.tags)
            if rule_name == 'twelve':
                self.assertEqual(len(rule.tags), 2)
                self.assertIn('tag1', rule.tags)
                self.assertIn('tag2', rule.tags)

    def test_empty_string(self):
        inputRules = r'''
        rule thirteen
        {
        meta:
            my_identifier_1 = ""
            my_identifier_2 = 24
            my_identifier_3 = true

        strings:
            $my_text_string = "text here"
            $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
            $my_text_string or $my_hex_string
        }
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRules)

        for rule in result:
            rule_name = rule.name
            if rule_name == 'thirteen':
                self.assertEqual(len(rule.meta), 3)

    def test_bytestring(self):
        inputRules = r'''
        rule testName
        {
        strings:
            $a1 = { E2 34 A1 C8 23 FB }
            $a2 = { E2 34 A1 C8 2? FB }
            $a3 = { E2 34 A1 C8 ?? FB }
            $a4 = { E2 34 A1 [6] FB }
            $a5 = { E2 34 A1 [4-6] FB }
            $a6 = { E2 34 A1 [4 - 6] FB }
            $a7 = { E2 34 A1 [-] FB }
            $a8 = { E2 34 A1 [10-] FB }
            $a9 = { E2 23 ( 62 B4 | 56 ) 45 FB }
            $a10 = { E2 23 62 B4 56 // comment
                     45 FB }
            $a11 = { E2 23 62 B4 56 /* comment */ 45 FB }
            $a12 = {
                E2 23 62 B4 56 45 FB // comment
            }

        condition:
            any of them
        }
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRules)

        self.assertEqual(len(result), 1)
        for rule in result:
            rule_name = rule.name
            if rule_name == 'testName':
                self.assertEqual(len(rule.strings), 12)
                for hex_string in rule.strings:
                    # Basic sanity check.
                    self.assertIn('E2', hex_string.value)
                    self.assertIn('FB', hex_string.value)
                self.assertEqual(rule.strings[0].value, '{ E2 34 A1 C8 23 FB }')
                self.assertEqual(rule.strings[4].value, '{ E2 34 A1 [4-6] FB }')
                self.assertEqual(rule.strings[8].value, '{ E2 23 ( 62 B4 | 56 ) 45 FB }')
                long_string = '{ E2 23 62 B4 56 // comment\n                     45 FB }'
                self.assertEqual(rule.strings[9].value, long_string)
                self.assertEqual(rule.strings[10].value, '{ E2 23 62 B4 56 /* comment */ 45 FB }')
                long_string = '{\n                E2 23 62 B4 56 45 FB // comment\n            }'
                self.assertEqual(rule.strings[11].value, long_string)

    def test_nested_bytestring(self):
        inputRules = r'''
        rule sample {
            strings:
                $ = { 4D 5A ( 90 ( 00 | 01 ) | 89 ) }
            condition:
                all of them
        }
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRules)
        self.assertEqual(result.rules[0].strings[0].value, '{ 4D 5A ( 90 ( 00 | 01 ) | 89 ) }')

    def test_bytestring_bad_jump(self):
        inputRules = r'''
        rule testName
        {
        strings:
            $a6 = { E2 34 A1 [6 - 4] FB }

        condition:
            any of them
        }
        '''

        slyara = Slyara()
        with self.assertRaises(ValueError):
            slyara.parse_string(inputRules)

    def test_bytestring_bad_group(self):
        inputRules = r'''
        rule sample {
            strings:
                $ = { 4D 5A ( 90 ( 00 | 01 ) | 89 ) ) }
            condition:
                all of them
        }
        '''

        slyara = Slyara()
        with self.assertRaises(ValueError):
            slyara.parse_string(inputRules)

    def test_rexstring(self):
        inputRules = r'''
        rule testName
        {
        strings:
            $a1 = /abc123 \d/i
            $a2 = /abc123 \d+/i // comment
            $a3 = /abc123 \d\/ afterspace/is // comment
            $a4 = /abc123 \d\/ afterspace/is nocase // comment
            $a5 = /abc123 \d\/ afterspace/nocase // comment
            $a6 = /abc123 \d\/ afterspace/nocase// comment

            /* It should only consume the regex pattern and not text modifiers
               or comment, as those will be parsed separately. */

        condition:
            any of them
        }
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRules)

        self.assertEqual(len(result), 1)
        for rule in result:
            rule_name = rule.name
            if rule_name == 'testName':
                self.assertEqual(len(rule.strings), 6)
                for rex_string in rule.strings:
                    if rex_string.name == '$a1':
                        self.assertEqual(str(rex_string.value), 'abc123 \\d')
                        self.assertEqual(rex_string.modifiers, Modifiers.i)
                    elif rex_string.name == '$a2':
                        self.assertEqual(str(rex_string.value), 'abc123 \\d+')
                        self.assertEqual(rex_string.modifiers, Modifiers.i)
                    elif rex_string.name == '$a3':
                        self.assertEqual(str(rex_string.value), 'abc123 \\d\\/ afterspace')
                        self.assertEqual(rex_string.modifiers, Modifiers.i | Modifiers.s)
                    elif rex_string.name == '$a4':
                        self.assertEqual(str(rex_string.value), 'abc123 \\d\\/ afterspace')
                        self.assertEqual(rex_string.modifiers, Modifiers.i | Modifiers.s | Modifiers.nocase)
                    elif rex_string.name in ['$a5', '$a6']:
                        self.assertEqual(str(rex_string.value), 'abc123 \\d\\/ afterspace')
                        self.assertEqual(rex_string.modifiers, Modifiers.nocase)
                    else:
                        self.assertFalse('Unknown string name...')

    def test_string(self):
        inputRules = r'''
        rule testName
        {
        strings:
            $a1 = "test string"
            $a2 = "test string" // comment
            $a3 = "test string" /* comment */
            $a4 = "teststring" //comment
            $a5 = "test // string" // comm ent
            $a6 = "test /* string */ string"
            $a7 = "teststring" //comment
            $a8 = "'test"
            $a9 = "'test' string"
            $a10 = "\"test string\""
            $a11 = "test \"string\""
            $a12 = "test \"string\" test \\"
            $a13 = "test string" // "comment"
            $a14 = "test string" nocase wide // comment

        condition:
            any of them
        }
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRules)

        self.assertEqual(len(result), 1)
        for rule in result:
            self.assertEqual(len(rule.strings), 14)
            self.assertEqual(rule.strings[0].value, 'test string')
            self.assertEqual(rule.strings[1].value, 'test string')
            self.assertEqual(rule.strings[2].value, 'test string')
            self.assertEqual(rule.strings[3].value, 'teststring')
            self.assertEqual(rule.strings[4].value, 'test // string')
            self.assertEqual(rule.strings[5].value, 'test /* string */ string')
            self.assertEqual(rule.strings[6].value, 'teststring')
            self.assertEqual(rule.strings[7].value, "'test")
            self.assertEqual(rule.strings[8].value, "'test' string")
            self.assertEqual(rule.strings[9].value, '\\"test string\\"')
            self.assertEqual(rule.strings[10].value, 'test \\"string\\"')
            self.assertEqual(rule.strings[11].value, 'test \\"string\\" test \\\\')
            self.assertEqual(rule.strings[12].value, 'test string')
            self.assertEqual(rule.strings[13].value, 'test string')

    def test_slyara_script(self):
        test_file_path = data_dir.joinpath('test_file.txt')

        with captured_output() as (out, err):
            main([str(test_file_path)])
            output = out.getvalue()
            error = err.getvalue()
        output_hash = hashlib.sha256(output.encode()).hexdigest()

        self.assertTrue(output_hash in ['9d1991858f1b48b2485a9cb45692bc33c5228fb5acfa877a0d097b1db60052e3',
                                        '18569226a33c2f8f0c43dd0e034a6c05ea38f569adc3ca37d3c975be0d654f06'])
        self.assertEqual(error, str())

    def test_raw_condition_contains_all_condition_text(self):
        inputRules = r'''
        rule testName {condition: any of them}
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRules)

        self.assertEqual(result[0]['raw_condition'], 'condition: any of them')

    def test_raw_strings_contains_all_string_text(self):
        inputRules = r'''
        rule testName {strings: $a = "1" condition: true}
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRules)

        self.assertEqual(result[0]['raw_strings'], 'strings: $a = "1" ')

    def test_raw_meta_contains_all_meta_text(self):
        inputRules = r'''
        rule testName {meta: author = "Test" condition: true}
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRules)

        self.assertEqual(result[0]['raw_meta'], 'meta: author = "Test" ')

        # strings after meta
        inputRules = r'''
        rule testName {meta: author = "Test" strings: $a = "1"}
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRules)

        self.assertEqual(result[0]['raw_meta'], 'meta: author = "Test" ')

    def test_parse_file_without_rules_returns_empty_list(self):
        inputRules = str()

        slyara = Slyara()
        result = slyara.parse_string(inputRules)

        self.assertIsInstance(result, YaraRuleSet)
        self.assertEqual(len(result), 0)

    def test_lineno_incremented_by_newlines_in_bytestring(self):
        inputRules = r'''
        rule sample
        {
            strings:
                $ = { 00 00 00 00 00 00
                      00 00 00 00 00 00 } //line 6
            conditio: //fault
                all of them
        }
        '''

        slyara = Slyara()

        with self.assertRaises(TypeError):
            try:
                slyara.parse_string(inputRules)
            except TypeError as e:
                # self.assertEqual(7, e.lineno)
                raise e

    def test_lineno_incremented_by_windows_newlines_in_bytestring(self):
        with data_dir.joinpath('windows_newline_ruleset.yar').open('r') as fh:
            inputRules = fh.read()

        slyara = Slyara()

        with self.assertRaises(TypeError):
            try:
                slyara.parse_string(inputRules)
            except TypeError as e:
                # self.assertEqual(6, e.lineno)
                raise e

    def test_anonymous_array_condition(self):
        inputRules = r'''
        rule sample
        {
            strings:
                $ = { 01 02 03 04 }
            condition:
                for all of ($) : ( @ < 0xFF )
        }
        '''

        slyara = Slyara()
        result = slyara.parse_string(inputRules)

        self.assertEqual(result[0].get('condition_terms')[8], '@')

    def test_xor_modified_condition(self):
        slyara = Slyara()
        results = slyara.parse_rule(data_dir.joinpath('xor_modifier_ruleset.yar'))

        for rule in results:
            yr_mods = rule.strings[0].modifiers
            xor_string_mod = Modifiers.xor & yr_mods
            self.assertEqual(Modifiers.xor, xor_string_mod)

            yr_mod_args = rule.strings[0].mod_args
            if yr_mod_args:
                self.assertIn(0x10, yr_mod_args)

    def test_base64_modified_condition(self):
        slyara = Slyara()
        results = slyara.parse_rule(data_dir.joinpath('base64_modifier_ruleset.yar'))

        for rule in results:
            yr_mods = rule.strings[0].modifiers
            self.assertTrue(yr_mods & (Modifiers.base64 | Modifiers.base64wide))

            yr_mod_args = rule.strings[0].mod_args
            if yr_mod_args:
                self.assertEqual(r"!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu", yr_mod_args)


class TestGithubIssues(unittest.TestCase):

    # Reference: https://github.com/plyara/plyara/issues/63
    def test_issue_63(self):
        with data_dir.joinpath('comment_only.yar').open('r') as fh:
            inputString = fh.read()

        slyara = Slyara()
        result = slyara.parse_string(inputString)

        self.assertIsInstance(result, YaraRuleSet)
        self.assertEqual(0, len(result))


if __name__ == '__main__':
    unittest.main()
